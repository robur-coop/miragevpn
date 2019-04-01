
(* packet format, as defined in the openvpn-protocol document

   no support for key method v1! *)

open Rresult.R.Infix

type error = [
  | `Partial
  | `Leftover of int
  | `Unknown_operation of int
]

let pp_error ppf = function
  | `Partial -> Fmt.string ppf "partial"
  | `Leftover off -> Fmt.pf ppf "leftover at %d" off
  | `Unknown_operation op -> Fmt.pf ppf "unknown operation %d" op

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

let packet_id_len = 4

let hmac_len = 20 (* SHA1 is what you say *)

let hdr_len = 8 + hmac_len + packet_id_len + 4 + 1

let guard f e = if f then Ok () else Error e

type header = {
  local_session : int64 ;
  hmac : Cstruct.t ; (* usually 16 or 20 bytes *)
  packet_id : packet_id ;
  timestamp : int32 ;
  (* uint8 array length *)
  ack_packet_ids : packet_id list ;
  remote_session : int64 option ; (* if above is non-empty *)
}

let pp_header ppf hdr =
  Fmt.pf ppf "local %Lu packet_id %ld timestamp %ld hmac %a ack %a remote %a"
    hdr.local_session hdr.packet_id hdr.timestamp Cstruct.hexdump_pp hdr.hmac
    Fmt.(list ~sep:(unit ", ") int32) hdr.ack_packet_ids
    Fmt.(option ~none:(unit " ") int64) hdr.remote_session

let decode_header buf =
  guard (Cstruct.len buf >= hdr_len) `Partial >>= fun () ->
  let local_session = Cstruct.BE.get_uint64 buf 0
  and hmac = Cstruct.sub buf 8 hmac_len
  and packet_id = Cstruct.BE.get_uint32 buf (hmac_len + 8)
  and timestamp = Cstruct.BE.get_uint32 buf (hmac_len + 12)
  and arr_len = Cstruct.get_uint8 buf (hmac_len + 16)
  in
  guard (Cstruct.len buf >= hdr_len + packet_id_len * arr_len + 8) `Partial >>| fun () ->
  let rec ack_packet_id = function
    | 0 -> []
    | n ->
      let id = Cstruct.BE.get_uint32 buf (hdr_len + packet_id_len * n) in
      id :: (ack_packet_id (pred n))
  in
  let ack_packet_ids = ack_packet_id arr_len in
  let remote_session =
    if arr_len > 0 then
      Some (Cstruct.BE.get_uint64 buf (hdr_len + packet_id_len * arr_len))
    else
      None
  in
  { local_session ; hmac ; packet_id ; timestamp ; ack_packet_ids ; remote_session },
  (hdr_len + packet_id_len * arr_len + 8)

let encode_header hdr =
  let id_arr_len = packet_id_len * List.length hdr.ack_packet_ids in
  let rsid = if id_arr_len = 0 then 0 else 8 in
  let buf = Cstruct.create (hdr_len + rsid + id_arr_len) in
  Cstruct.BE.set_uint64 buf 0 hdr.local_session ;
  Cstruct.blit hdr.hmac 0 buf 8 hmac_len ;
  Cstruct.BE.set_uint32 buf (hmac_len + 8) hdr.packet_id ;
  Cstruct.BE.set_uint32 buf (hmac_len + 12) hdr.timestamp ;
  Cstruct.set_uint8 buf (hmac_len + 16) (List.length hdr.ack_packet_ids);
  List.iteri
    (fun i v -> Cstruct.BE.set_uint32 buf (hmac_len + 17 + i * packet_id_len) v)
    hdr.ack_packet_ids ;
  (match hdr.remote_session with
   | None -> ()
   | Some v ->
     assert (rsid <> 0) ;
     Cstruct.BE.set_uint64 buf (hdr_len + id_arr_len) v) ;
  buf, hdr_len + rsid + id_arr_len

type control = header * packet_id * Cstruct.t

let pp_control ppf (hdr, id, payload) =
  Fmt.pf ppf "%a id %lu %a" pp_header hdr id Cstruct.hexdump_pp payload

let decode_control buf =
  decode_header buf >>= fun (header, off) ->
  guard (Cstruct.len buf >= off + 4) `Partial >>| fun () ->
  let packet_id = Cstruct.BE.get_uint32 buf off
  and payload = Cstruct.shift buf 4
  in
  (header, packet_id, payload)

let encode_control (header, packet_id, payload) =
  let hdr_buf, len = encode_header header in
  let packet_id_buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 packet_id_buf 0 packet_id ;
  Cstruct.concat [ hdr_buf ; packet_id_buf ; payload ],
  len + Cstruct.len payload + 4

let decode_data buf = Ok buf

let encode_data data = data, Cstruct.len data

let decode buf =
  guard (Cstruct.len buf >= 3) `Partial >>= fun () ->
  let plen = Cstruct.BE.get_uint16 buf 0 in
  let op = Cstruct.get_uint8 buf 2 in
  guard (Cstruct.len buf >= plen + 3) `Partial >>= fun () ->
  guard (Cstruct.len buf = plen + 3) (`Leftover (plen + 3)) >>= fun () ->
  let payload = Cstruct.sub buf 0 plen in
  int_to_operation op >>| fun operation ->
  match operation with
  | Ack -> decode_header payload >>| fun (ack, _) -> `Ack ack
  | Data_v1 | Data_v2 -> decode_data payload >>| fun data -> `Data (operation, data)
  | _ -> decode_control payload >>| fun control -> `Control (operation, control)

let encode p =
  let (payload, len), operation = match p with
    | `Ack ack -> encode_header ack, Ack
    | `Control (operation, control) -> encode_control control, operation
    | `Data (operation, d) -> encode_data d, operation
  in
  let buf = Cstruct.create 3 in
  Cstruct.BE.set_uint16 buf 0 len ;
  Cstruct.set_uint8 buf (operation_to_int operation) 2 ;
  Cstruct.append buf payload

type t = [
  | `Ack of header
  | `Control of operation * control
  | `Data of operation * Cstruct.t
]

let pp ppf = function
  | `Ack a -> Fmt.pf ppf "ack %a" pp_header a
  | `Control (op, c) -> Fmt.pf ppf "control %a: %a" pp_operation op pp_control c
  | `Data (op, d) -> Fmt.pf ppf "data %a: %a" pp_operation op Cstruct.hexdump_pp d

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
