
type key_source = {
  pre_master : Cstruct.t ; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t ; (* 32 bytes *)
  random2 : Cstruct.t ; (* 32 bytes *)
}

type client_state =
  | Expect_server_reset
  | TLS_handshake of Tls.Engine.state
  | TLS_established of Tls.Engine.state * key_source
  | Push_request_sent of Tls.Engine.state * Cstruct.t

let pp_client_state ppf = function
  | Expect_server_reset -> Fmt.string ppf "expecting server reset"
  | TLS_handshake _ -> Fmt.string ppf "TLS handshake in process"
  | TLS_established _ -> Fmt.string ppf "TLS handshake established"
  | Push_request_sent _ -> Fmt.string ppf "push request sent"

type t = {
  linger : Cstruct.t ;
  authenticator : X509.Authenticator.a ;
  rng : int -> Cstruct.t ;
  key : int ;
  client_state : client_state ;
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

let pp ppf t =
  Fmt.pf ppf "key %d state %a, my hmac %a session %Lu packet %lu message %lu@.their hmac %a session %Lu packet %lu message %lu (acked %lu)"
    t.key pp_client_state t.client_state
    Cstruct.hexdump_pp t.my_hmac t.my_session_id t.my_packet_id t.my_message_id
    Cstruct.hexdump_pp t.their_hmac t.their_session_id t.their_packet_id t.their_message_id t.their_last_acked_message_id
