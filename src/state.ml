
type key_source = {
  pre_master : Cstruct.t ; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t ; (* 32 bytes *)
  random2 : Cstruct.t ; (* 32 bytes *)
}

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

let pp_ip_config ppf { ip ; prefix ; gateway } =
  Fmt.pf ppf "ip %a prefix %a gateway %a"
    Ipaddr.V4.pp ip Ipaddr.V4.Prefix.pp prefix Ipaddr.V4.pp gateway

type client_state =
  | Expect_server_reset
  | TLS_handshake of Tls.Engine.state
  | TLS_established of Tls.Engine.state * key_source
  | Push_request_sent of Tls.Engine.state
  | Established of Tls.Engine.state * ip_config

let pp_client_state ppf = function
  | Expect_server_reset -> Fmt.string ppf "expecting server reset"
  | TLS_handshake _ -> Fmt.string ppf "TLS handshake in process"
  | TLS_established _ -> Fmt.string ppf "TLS handshake established"
  | Push_request_sent _ -> Fmt.string ppf "push request sent"
  | Established (_, ip) -> Fmt.pf ppf "established %a" pp_ip_config ip

type transport = {
  key : int ;
  my_hmac : Cstruct.t ;
  my_session_id : int64 ;
  my_packet_id : int32 ; (* this starts from 1l, indicates the next to-be-send *)
  my_message_id : int32 ; (* this starts from 0l, indicates the next to-be-send *)
  their_hmac : Cstruct.t ;
  their_session_id : int64 ;
  their_packet_id : int32 ; (* the first should be 1l, indicates the next to-be-received *)
  their_message_id : int32 ; (* the first should be 0l, indicates the next to-be-received *)
  their_last_acked_message_id : int32 ;
}

let pp_transport ppf t =
  Fmt.pf ppf "key %d, session %Lu packet %lu message %lu@.session %Lu packet %lu message %lu (acked %lu)"
    t.key
    t.my_session_id t.my_packet_id t.my_message_id
    t.their_session_id t.their_packet_id t.their_message_id t.their_last_acked_message_id

type keys_ctx = {
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

type t = {
  config : Config.t ;
  linger : Cstruct.t ;
  transport : transport ;
  keys_ctx : keys_ctx option ;
  rng : int -> Cstruct.t ;
  client_state : client_state ;
  last_received : int64 ;
  last_sent : int64
}

let pp ppf t =
  Fmt.pf ppf "%a, transport %a"
    pp_client_state t.client_state pp_transport t.transport
