
type key_source = {
  pre_master : Cstruct.t ; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t ; (* 32 bytes *)
  random2 : Cstruct.t ; (* 32 bytes *)
}

type client_state =
  | Expect_server_reset
  | TLS_handshake of Tls.Engine.state
  | TLS_established of Tls.Engine.state * key_source
  | Push_request_sent of Tls.Engine.state

let pp_client_state ppf = function
  | Expect_server_reset -> Fmt.string ppf "expecting server reset"
  | TLS_handshake _ -> Fmt.string ppf "TLS handshake in process"
  | TLS_established _ -> Fmt.string ppf "TLS handshake established"
  | Push_request_sent _ -> Fmt.string ppf "push request sent"

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
  their_key : Nocrypto.Cipher_block.AES.CBC.key ;
  their_hmac : Cstruct.t ;
}

let pp_keys ppf t =
  Fmt.pf ppf "keys: my hmac %a, their hmac %a"
    Cstruct.hexdump_pp t.my_hmac Cstruct.hexdump_pp t.their_hmac

type t = {
  linger : Cstruct.t ;
  transport : transport ;
  keys_ctx : keys_ctx option ;
  authenticator : X509.Authenticator.a ;
  user_pass : (string * string) option ;
  rng : int -> Cstruct.t ;
  client_state : client_state ;
}

let pp ppf t =
  Fmt.pf ppf "%a, transport %a"
    pp_client_state t.client_state pp_transport t.transport
