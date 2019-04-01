
(* packet format, as defined in the openvpn-protocol document

   no support for key method v1! *)

type operation =
  | Soft_reset
  | Control
  | Ack
  | Data_v1
  | Hard_reset_client
  | Hard_reset_server
  | Data_v2

let operation_to_int, int_to_operation =
  let ops = [ (Soft_reset, 3) ; (Control, 4) ; (Ack, 5) ; (Data_v1, 6) ;
              (Hard_reset_client, 7) ; (Hard_reset_server, 8) ; (Data_v2, 9) ]
  in
  let rev_ops = List.map (fun (a, b) -> (b, a)) ops in
  (fun k -> List.assoc k ops),
  (fun i -> match List.assoc_opt i rev_ops with Some x -> Ok x | None -> Error (`Unknown_operation i))

let pp_operation ppf op =
  Fmt.string ppf (match op with
      | Soft_reset -> "soft reset"
      | Control -> "control"
      | Ack -> "ack"
      | Data_v1 -> "data v1"
      | Hard_reset_client -> "hard reset client"
      | Hard_reset_server -> "hard reset server"
      | Data_v2 -> "data v2")

type packet_id = int32 (* 4 or 8 bytes -- latter in pre-shared key mode *)

let hmac_len = 20 (* SHA1 is what you say *)

type packet = {
  (* 16 bit length *)
  operation : operation ; (* uint8 *)
  payload : Cstruct.t ;
}

let guard f e = if f then Ok () else Error e

type error = [
  | `Partial
  | `Leftover
  | `Unknown_operation of int
]

let decode_packet buf =
  let open Rresult.R.Infix in
  guard (Cstruct.len buf >= 3) `Partial >>= fun () ->
  let plen = Cstruct.BE.get_uint16 buf 0 in
  let op = Cstruct.get_uint8 buf 2 in
  guard (Cstruct.len buf >= plen + 3) `Partial >>= fun () ->
  guard (Cstruct.len buf = plen + 3) `Leftover >>= fun () ->
  let payload = Cstruct.sub buf 0 plen in
  int_to_operation op >>| fun operation ->
  { operation ; payload }

type control = {
  local_session : int64 ;
  hmac : Cstruct.t ; (* usually 16 or 20 bytes *)
  packet_id : packet_id ;
  timestamp : int32 ;
  (* uint8 array length *)
  ack_packet_id : packet_id array ;
  remote_session : int64 option ; (* if above is non-empty *)
  message_packet_id : packet_id ; (* if op != ACK *)
  payload : Cstruct.t ; (* if op != ACK *)
}

type tls_control = { (* v2 only! *)
  (* 4 zero bytes *)
  key_method_type : int ; (* uint8 *)
  key_source : Cstruct.t ; (* pre_master only defined for client -> server *)
  (* 16 bit len *)
  options : string ; (* n bytes, null terminated -- record may end after options! *)
  (* 16 bit len *)
  user : string option ;
  (* 16 bit len *)
  password : string option ;
}

type data = {
  hmac : Cstruct.t ; (* of cipertext IV + ciphertext if not disabled by --auth none *)
  ciphertext_iv : Cstruct.t ; (* size is cipher-dependent, if not disabled by --no-iv *)
  payload : Cstruct.t ;
}

type tls_data = {
  packet_id : packet_id ; (* disabled by --no-replay *)
  payload : Cstruct.t
}
