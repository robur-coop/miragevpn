
type key_source = {
  pre_master : Cstruct.t ; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t ; (* 32 bytes *)
  random2 : Cstruct.t ; (* 32 bytes *)
}

type transport = {
  my_message_id : int32 ; (* this starts from 0l, indicates the next to-be-send *)
  their_message_id : int32 ; (* the first should be 0l, indicates the next to-be-received *)
  their_last_acked_message_id : int32 ;
}

let pp_transport ppf t =
  Fmt.pf ppf "my message %lu@.their message %lu (acked %lu)"
    t.my_message_id t.their_message_id t.their_last_acked_message_id

let init_transport = {
  my_message_id = 0l ;
  their_message_id = 0l ;
  their_last_acked_message_id = 0l ;
}

type keys = {
  my_key : Nocrypto.Cipher_block.AES.CBC.key ;
  my_hmac : Cstruct.t ;
  my_packet_id : int32 ;
  their_key : Nocrypto.Cipher_block.AES.CBC.key ;
  their_hmac : Cstruct.t ;
  their_packet_id : int32 ;
}

let pp_keys ppf t =
  Fmt.pf ppf "keys: my id %lu, their id %lu"
    t.my_packet_id t.their_packet_id

type channel_state =
  | Expect_server_reset
  | TLS_handshake of Tls.Engine.state
  | TLS_established of Tls.Engine.state * key_source
  | Push_request_sent of Tls.Engine.state * keys
  | Established of Tls.Engine.state * keys

let pp_channel_state ppf = function
  | Expect_server_reset -> Fmt.string ppf "expecting server reset"
  | TLS_handshake _ -> Fmt.string ppf "TLS handshake in process"
  | TLS_established _ -> Fmt.string ppf "TLS handshake established"
  | Push_request_sent _ -> Fmt.string ppf "push request sent"
  | Established _ -> Fmt.string ppf "established"

type channel = {
  keyid : int ;
  channel_st : channel_state ;
  transport : transport ;
}

let keys_opt ch = match ch.channel_st with
  | Push_request_sent (_, keys) | Established (_, keys) -> Some keys
  | _ -> None

let set_keys ch keys =
  let channel_st = match ch.channel_st with
    | Established (tls, _) -> Established (tls, keys)
    | x -> x
  in
  { ch with channel_st }

let pp_channel ppf c =
  Fmt.pf ppf "channel %d: %a, transport %a"
    c.keyid pp_channel_state c.channel_st
    pp_transport c.transport

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

let pp_ip ppf { ip ; prefix ; gateway } =
  Fmt.pf ppf "ip %a prefix %a gateway %a"
    Ipaddr.V4.pp ip Ipaddr.V4.Prefix.pp prefix Ipaddr.V4.pp gateway

let ip_from_config config =
  match Config.(get Ifconfig config, get Route_gateway config) with
  | (V4 ip, V4 mask), `IP (V4 gateway) ->
    { ip ; prefix = Ipaddr.V4.Prefix.of_netmask mask ip ; gateway }
  | _ -> assert false

type session_state =
  | Connecting
  | Ready of ip_config
  | Rekeying of ip_config * channel

let pp_session_state ppf = function
  | Connecting -> Fmt.string ppf "connecting"
  | Ready ip -> Fmt.pf ppf "ready %a" pp_ip ip
  | Rekeying (ip, c) -> Fmt.pf ppf "rekeying %a %a" pp_ip ip pp_channel c

type session = {
  state : session_state ;
  my_session_id : int64 ;
  my_packet_id : int32 ; (* this starts from 1l, indicates the next to-be-send *)
  my_hmac : Cstruct.t ;
  their_session_id : int64 ;
  their_packet_id : int32 ; (* the first should be 1l, indicates the next to-be-received *)
  their_hmac : Cstruct.t ;
}

let pp_session ppf t =
  Fmt.pf ppf "state %a@.my session %Lu packet %lu@.their session %Lu packet %lu"
    pp_session_state t.state t.my_session_id t.my_packet_id t.their_session_id
    t.their_packet_id

type t = {
  config : Config.t ;
  linger : Cstruct.t ;
  compress : bool ;
  rng : int -> Cstruct.t ;
  session : session ;
  channel : channel ;
  lame_duck : channel option ;
  last_received : int64 ;
  last_sent : int64 ;
}

let pp ppf t =
  Fmt.pf ppf "linger %d compress %B session %a@.active %a@.lame duck %a@.last-rcvd %Lu last-sent %Lu"
    (Cstruct.len t.linger) t.compress
    pp_session t.session pp_channel t.channel
    Fmt.(option ~none:(unit "no") pp_channel) t.lame_duck t.last_received t.last_sent

let channel_of_keyid keyid s =
  if s.channel.keyid = keyid then
    Some (s.channel, fun s channel -> { s with channel })
  else match s.lame_duck with
    | Some ch when ch.keyid = keyid ->
      Some (ch, fun s ch -> { s with lame_duck = Some ch })
    | _ -> match s.session.state with
      | Rekeying (ip, channel) when channel.keyid = keyid ->
        let set s ch =
          let session = { s.session with state = Rekeying (ip, ch) } in
          { s with session }
        in
        Some (channel, set)
      | _ -> None
