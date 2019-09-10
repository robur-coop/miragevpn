
type key_source = {
  pre_master : Cstruct.t ; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t ; (* 32 bytes *)
  random2 : Cstruct.t ; (* 32 bytes *)
}

type transport = {
  my_message_id : int32 ; (* this starts from 0l, indicates the next to-be-send *)
  their_message_id : int32 ; (* the first should be 0l, indicates the next to-be-received *)
  last_acked_message_id : int32 ;
}

let pp_transport ppf t =
  Fmt.pf ppf "my message %lu@.their message %lu (acked %lu)"
    t.my_message_id t.their_message_id t.last_acked_message_id

let init_transport = {
  my_message_id = 0l ;
  their_message_id = 0l ;
  last_acked_message_id = 0l ;
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
  started : int64 ;
  bytes : int ;
  packets : int ;
}

let pp_channel ppf c =
  Fmt.pf ppf "channel %d %a@ started %Lu bytes %d packets %d@ transport %a"
    c.keyid pp_channel_state c.channel_st
    c.started c.bytes c.packets pp_transport c.transport

let new_channel ?(state = Expect_server_reset) keyid started = {
  keyid ; channel_st = state ; transport = init_transport ; started ;
  bytes = 0 ; packets = 0
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

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

let pp_ip_config ppf { ip ; prefix ; gateway } =
  Fmt.pf ppf "ip %a prefix %a gateway %a"
    Ipaddr.V4.pp ip Ipaddr.V4.Prefix.pp prefix Ipaddr.V4.pp gateway

type event = [
  | `Resolved of Ipaddr.t
  | `Resolve_failed
  | `Connected
  | `Connection_failed
  | `Tick
  | `Data of Cstruct.t
]

let pp_event ppf = function
  | `Resolved r -> Fmt.pf ppf "resolved %a" Ipaddr.pp r
  | `Resolve_failed -> Fmt.string ppf "resolve failed"
  | `Connected -> Fmt.string ppf "connected"
  | `Connection_failed -> Fmt.string ppf "connection failed"
  | `Tick -> Fmt.string ppf "tick"
  | `Data cs -> Fmt.pf ppf "data %d bytes" (Cstruct.len cs)

type action = [
  | `Resolve of [ `host ] Domain_name.t * [`Ipv4 | `Ipv6 | `Any]
  | `Connect of Ipaddr.t * int * [`Tcp | `Udp]
  | `Disconnect
  | `Exit
  | `Established of ip_config * int
  | `Payload of Cstruct.t list
]

let pp_ip_version ppf = function
  | `Ipv4 -> Fmt.string ppf "ipv4"
  | `Ipv6 -> Fmt.string ppf "ipv6"
  | `Any -> Fmt.string ppf "any"

let pp_proto ppf = function
  | `Tcp -> Fmt.string ppf "tcp"
  | `Udp -> Fmt.string ppf "udp"

let pp_action ppf = function
  | `Resolve (host, ip_version) ->
    Fmt.pf ppf "resolve %a (%a)" Domain_name.pp host pp_ip_version ip_version
  | `Connect (ip, port, proto) ->
    Fmt.pf ppf "connect %a %a:%d" pp_proto proto Ipaddr.pp ip port
  | `Disconnect -> Fmt.string ppf "disconect"
  | `Exit -> Fmt.string ppf "exit"
  | `Established (ip, mtu) ->
    Fmt.pf ppf "established %a, mtu %d" pp_ip_config ip mtu
  | `Payload xs ->
    Fmt.pf ppf "payload %d (%d bytes)" (List.length xs) (Cstruct.lenv xs)

let ip_from_config config =
  match Config.(get Ifconfig config, get Route_gateway config) with
  | (V4 ip, V4 mask), `Ip (V4 gateway) ->
    let prefix = Ipaddr.V4.Prefix.of_netmask mask ip in
    { ip ; prefix ; gateway }
  | _ -> assert false

type session = {
  my_session_id : int64 ;
  my_packet_id : int32 ; (* this starts from 1l, indicates the next to-be-send *)
  my_hmac : Cstruct.t ;
  their_session_id : int64 ;
  their_packet_id : int32 ; (* the first should be 1l, indicates the next to-be-received *)
  their_hmac : Cstruct.t ;
  compress : bool ;
}

let init_session ~my_session_id ?(their_session_id = 0L) ~my_hmac ~their_hmac () =
  { my_session_id ; my_packet_id = 1l ; my_hmac ;
    their_session_id ; their_packet_id = 1l ; their_hmac ;
    compress = false }

let pp_session ppf t =
  Fmt.pf ppf "compression %B my session %Lu packet %lu@.their session %Lu packet %lu"
    t.compress
    t.my_session_id t.my_packet_id t.their_session_id
    t.their_packet_id

type state =
  | Resolving of int * int64 * int (* index [into remote], timestamp, retry count *)
  | Connecting of int * int64 * int (* index [into remote], ts, retry count *)
  | Handshaking of int * int64 (* index into [remote], ts *)
  | Ready
  | Rekeying of channel

let pp_state ppf = function
  | Resolving (_idx, _ts, _) -> Fmt.string ppf "resolving"
  | Connecting (_idx, _ts, retry) -> Fmt.pf ppf "connecting (retry %d)" retry
  | Handshaking (_idx, _ts) -> Fmt.string ppf "handshaking"
  | Ready -> Fmt.string ppf "ready"
  | Rekeying c ->
    Fmt.pf ppf "rekeying %a" pp_channel c

type t = {
  config : Config.t ;
  linger : Cstruct.t ;
  rng : int -> Cstruct.t ;
  state : state ;
  session : session ;
  channel : channel ;
  lame_duck : (channel * int64) option ;
  last_received : int64 ;
  last_sent : int64 ;
}

let pp ppf t =
  let lame_duck = match t.lame_duck with None -> None | Some (ch, _) -> Some ch in
  Fmt.pf ppf "@[linger %d state %a session %a@.active %a@.lame duck %a@.\
              last-rcvd %Lu last-sent %Lu@]"
    (Cstruct.len t.linger)
    pp_state t.state
    pp_session t.session
    pp_channel t.channel
    Fmt.(option ~none:(unit "no") pp_channel) lame_duck
    t.last_received t.last_sent

let compress s = s.session.compress

let mtu config compress =
  (* we assume to have a tun interface and the server send us a tun-mtu *)
  let tun_mtu = match Config.find Tun_mtu config with
    | None -> 1500 (* TODO "client_merge_server_config" should do this! *)
    | Some x -> x
  in
  let bs = match Config.find Cipher config with
    | Some "AES-256-CBC" -> 16
    | _ -> assert false
  in
  (* padding, done on packet_id + compress + data *)
  let not_yet_padded_payload =
    4 (* packet id *) + if compress then 1 else 0
  in
  let hdrs =
    3 (* hdr: 2 byte length, 1 byte op + key *) + bs (* IV *) + Packet.hmac_len
  in
  (* now we know: tun_mtu - hdrs is space we have for data *)
  let data = tun_mtu - hdrs in
  (* data is pad ( not_yet_padded_payload + x ) - i.e. we're looking for the
     closest bs-1 number, and subtract not_yet_padded_payload *)
  let left = data mod bs in
  let r =
    if left = pred bs then
      data - not_yet_padded_payload
    else
      data - succ left - not_yet_padded_payload
  in
  assert (r > 0) ;
  r

let channel_of_keyid keyid s =
  if s.channel.keyid = keyid then
    Some (s.channel, fun s channel -> { s with channel })
  else match s.lame_duck with
    | Some (ch, ts) when ch.keyid = keyid ->
      Some (ch, fun s ch -> { s with lame_duck = Some (ch, ts) })
    | _ -> match s.state with
      | Rekeying channel when channel.keyid = keyid ->
        let set s ch =
          let state = Rekeying ch in
          { s with state }
        in
        Some (channel, set)
      | _ -> None
