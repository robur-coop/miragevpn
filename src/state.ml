
type client_state =
  | Client_reset
  | Server_reset

let pp_client_state ppf = function
  | Client_reset -> Fmt.string ppf "client reset"
  | Server_reset -> Fmt.string ppf "server reset"

type t = {
  key : int ;
  state : client_state ;
  my_session_id : int64 ;
  my_packet_id : int32 ;
  my_message_id : int32 ;
  their_session_id : int64 ;
  their_packet_id : int32 ;
  their_acked_packet_id : int32 ;
  their_message_id : int32 ;
}
 (* likely some keys and states *)

let pp ppf t =
  Fmt.pf ppf "key %d state %a, session %Lu packet %lu message %lu@.their session %Lu packet %lu (acked %lu) message %lu"
    t.key pp_client_state t.state
    t.my_session_id t.my_packet_id t.my_message_id
    t.their_session_id t.their_packet_id t.their_acked_packet_id t.their_message_id
