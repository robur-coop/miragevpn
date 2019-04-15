
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
  let ops =
    [ (Soft_reset, 3) ; (Control, 4) ; (Ack, 5) ; (Data_v1, 6) ;
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
  ack_message_ids : packet_id list ;
  remote_session : int64 option ; (* if above is non-empty *)
}

let pp_header ppf hdr =
  Fmt.pf ppf "local %Lu packet_id %ld timestamp %ld hmac %a ack %a remote %a"
    hdr.local_session hdr.packet_id hdr.timestamp Cstruct.hexdump_pp hdr.hmac
    Fmt.(list ~sep:(unit ", ") int32) hdr.ack_message_ids
    Fmt.(option ~none:(unit " ") int64) hdr.remote_session

let decode_header buf =
  guard (Cstruct.len buf >= hdr_len) `Partial >>= fun () ->
  let local_session = Cstruct.BE.get_uint64 buf 0
  and hmac = Cstruct.sub buf 8 hmac_len
  and packet_id = Cstruct.BE.get_uint32 buf (hmac_len + 8)
  and timestamp = Cstruct.BE.get_uint32 buf (hmac_len + 12)
  and arr_len = Cstruct.get_uint8 buf (hmac_len + 16)
  in
  let rs = if arr_len = 0 then 0 else 8 in
  guard (Cstruct.len buf >= hdr_len + packet_id_len * arr_len + rs) `Partial >>| fun () ->
  let rec ack_message_id = function
    | 0 -> []
    | n ->
      let idx = pred n in
      let id = Cstruct.BE.get_uint32 buf (hdr_len + packet_id_len * idx) in
      id :: ack_message_id idx
  in
  let ack_message_ids = ack_message_id arr_len in
  let remote_session =
    if arr_len > 0 then
      Some (Cstruct.BE.get_uint64 buf (hdr_len + packet_id_len * arr_len))
    else
      None
  in
  { local_session ; hmac ; packet_id ; timestamp ; ack_message_ids ; remote_session },
  (hdr_len + packet_id_len * arr_len + rs)

let encode_header hdr =
  let id_arr_len = packet_id_len * List.length hdr.ack_message_ids in
  let rsid = if id_arr_len = 0 then 0 else 8 in
  let buf = Cstruct.create (hdr_len + rsid + id_arr_len) in
  Cstruct.BE.set_uint64 buf 0 hdr.local_session ;
  Cstruct.blit hdr.hmac 0 buf 8 hmac_len ;
  Cstruct.BE.set_uint32 buf (hmac_len + 8) hdr.packet_id ;
  Cstruct.BE.set_uint32 buf (hmac_len + 12) hdr.timestamp ;
  Cstruct.set_uint8 buf (hmac_len + 16) (List.length hdr.ack_message_ids);
  List.iteri
    (fun i v -> Cstruct.BE.set_uint32 buf (hmac_len + 17 + i * packet_id_len) v)
    hdr.ack_message_ids ;
  (match hdr.remote_session with
   | None -> ()
   | Some v ->
     assert (rsid <> 0) ;
     Cstruct.BE.set_uint64 buf (hdr_len + id_arr_len) v) ;
  buf, hdr_len + rsid + id_arr_len

let to_be_signed_header ?(more = 0) op header =
  (* TODO verify that this is indeed the thing to sign! *)
  (* packet_id ++ timestamp ++ operation ++ session_id ++ ack_len ++ acks ++ remote_session ++ msg_id *)
  let acks = match header.ack_message_ids with
    | [] -> 0
    | x -> List.length x * packet_id_len
  and rses = match header.remote_session with
    | None -> 0
    | Some _ -> 8
  in
  let buflen = packet_id_len + 4 + 1 + 8 + 1 + acks + rses + more in
  let buf = Cstruct.create buflen in
  Cstruct.BE.set_uint32 buf 0 header.packet_id ;
  Cstruct.BE.set_uint32 buf 4 header.timestamp ;
  Cstruct.set_uint8 buf 8 op ;
  Cstruct.BE.set_uint64 buf 9 header.local_session ;
  Cstruct.set_uint8 buf 17 (List.length header.ack_message_ids) ;
  let rec enc_ack off = function
    | [] -> ()
    | hd::tl -> Cstruct.BE.set_uint32 buf off hd ; enc_ack (off + 4) tl
  in
  enc_ack 18 header.ack_message_ids ;
  (match header.remote_session with
   | None -> ()
   | Some x -> Cstruct.BE.set_uint64 buf (18 + acks) x) ;
  buf, 18 + acks + rses

type control = header * packet_id * Cstruct.t

let pp_control ppf (hdr, id, payload) =
  Fmt.pf ppf "%a message-id %lu payload %a" pp_header hdr id Cstruct.hexdump_pp payload

let decode_control buf =
  decode_header buf >>= fun (header, off) ->
  guard (Cstruct.len buf >= off + 4) `Partial >>| fun () ->
  let message_id = Cstruct.BE.get_uint32 buf off
  and payload = Cstruct.shift buf (off + 4)
  in
  (header, message_id, payload)

let encode_control (header, packet_id, payload) =
  let hdr_buf, len = encode_header header in
  let packet_id_buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 packet_id_buf 0 packet_id ;
  Cstruct.concat [ hdr_buf ; packet_id_buf ; payload ],
  len + Cstruct.len payload + 4

let to_be_signed_control op (header, packet_id, payload) =
  (* rly? not length!? *)
  let buf, off = to_be_signed_header ~more:packet_id_len op header in
  Cstruct.BE.set_uint32 buf off packet_id ;
  Cstruct.append buf payload

let decode_data buf = Ok buf

let encode_data data = data, Cstruct.len data

let decode buf =
  guard (Cstruct.len buf >= 3) `Partial >>= fun () ->
  let plen = Cstruct.BE.get_uint16 buf 0 in
  let opkey = Cstruct.get_uint8 buf 2 in
  guard (Cstruct.len buf - 2 >= plen) `Partial >>= fun () ->
  guard (Cstruct.len buf - 2 = plen) (`Leftover (plen + 2)) >>= fun () ->
  let payload = Cstruct.sub buf 3 (pred plen) in
  let op, key = opkey lsr 3, opkey land 0x07 in
  int_to_operation op >>= fun operation ->
  (match operation with
   | Ack -> decode_header payload >>| fun (ack, _) -> `Ack ack
   | Data_v1 | Data_v2 -> decode_data payload >>| fun data -> `Data (operation, data)
   | _ -> decode_control payload >>| fun control -> `Control (operation, control)) >>| fun res ->
  (key, res)

let operation = function
  | `Ack _ -> Ack
  | `Control (op, _) -> op
  | `Data (op, _) -> op

let op_key op key =
  let op = operation_to_int op in
  op lsl 3 lor key

let encode (key, p) =
  let (payload, len)= match p with
    | `Ack ack -> encode_header ack
    | `Control (_, control) -> encode_control control
    | `Data (_, d) -> encode_data d
  in
  let buf = Cstruct.create 3 in
  Cstruct.BE.set_uint16 buf 0 (succ len) ;
  let op = op_key (operation p) key in
  Cstruct.set_uint8 buf 2 op ;
  Cstruct.append buf payload

let to_be_signed key p =
  let op = op_key (operation p) key in
  match p with
  | `Ack hdr -> fst (to_be_signed_header op hdr)
  | `Data _ -> assert false
  | `Control (_, c) -> to_be_signed_control op c

type t = int * [
  | `Ack of header
  | `Control of operation * control
  | `Data of operation * Cstruct.t
]

let header = function
  | `Ack hdr -> hdr
  | `Control (_, (hdr, _, _)) -> hdr
  | `Data (_, _) -> assert false

let with_header hdr = function
  | `Ack _ -> `Ack hdr
  | `Control (op, (_, id, data)) -> `Control (op, (hdr, id, data))
  | `Data (op, data) -> `Data (op, data)

let message_id = function
  | `Ack _ -> None
  | `Control (_, (_, msg_id, _)) -> Some msg_id
  | `Data (_, _) -> assert false

let pp ppf (key, p) = match p with
  | `Ack a -> Fmt.pf ppf "key %x ack %a" key pp_header a
  | `Control (op, c) -> Fmt.pf ppf "key %x control %a: %a" key pp_operation op pp_control c
  | `Data (op, d) -> Fmt.pf ppf "key %x data %a: %a" key pp_operation op Cstruct.hexdump_pp d

(*
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
  *)
