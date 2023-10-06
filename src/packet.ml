(* packet format, as defined in the openvpn-protocol document

   no support for key method v1! *)

module Log =
  (val Logs.(
         src_log
         @@ Src.create ~doc:"Miragevpn library's packet module" "ovpn.packet")
      : Logs.LOG)

type error = [ `Partial | `Unknown_operation of int | `Malformed of string ]

let pp_error ppf = function
  | `Partial -> Fmt.string ppf "partial"
  | `Unknown_operation op -> Fmt.pf ppf "unknown operation %d" op
  | `Malformed msg -> Fmt.pf ppf "malformed %s" msg

type operation =
  | Soft_reset
  | Control
  | Ack
  | Data_v1
  | Hard_reset_client
  | Hard_reset_server

let operation_to_int, int_to_operation =
  let ops =
    [
      (Soft_reset, 3);
      (Control, 4);
      (Ack, 5);
      (Data_v1, 6);
      (Hard_reset_client, 7);
      (Hard_reset_server, 8);
    ]
  in
  let rev_ops = List.map (fun (a, b) -> (b, a)) ops in
  ( (fun k -> List.assoc k ops),
    fun i ->
      match List.assoc_opt i rev_ops with
      | Some x -> Ok x
      | None -> Error (`Unknown_operation i) )

let pp_operation ppf op =
  Fmt.string ppf
    (match op with
    | Soft_reset -> "soft reset"
    | Control -> "control"
    | Ack -> "ack"
    | Data_v1 -> "data v1"
    | Hard_reset_client -> "hard reset client"
    | Hard_reset_server -> "hard reset server")

type packet_id = int32 (* 4 or 8 bytes -- latter in pre-shared key mode *)

let packet_id_len = 4
let hmac_len = 20 (* SHA1 is what you say *)
let cipher_block_size = 16
let hdr_len = 8 + hmac_len + packet_id_len + 4 + 1
let guard f e = if f then Ok () else Error e

type header = {
  local_session : int64;
  hmac : Cstruct.t; (* usually 16 or 20 bytes *)
  packet_id : packet_id;
  timestamp : int32;
  (* uint8 array length *)
  ack_message_ids : packet_id list;
  remote_session : int64 option; (* if above is non-empty *)
}

let pp_header ppf hdr =
  Fmt.pf ppf "local %Lu packet_id %ld timestamp %ld hmac %a ack %a remote %a"
    hdr.local_session hdr.packet_id hdr.timestamp Cstruct.hexdump_pp hdr.hmac
    Fmt.(list ~sep:(any ", ") uint32)
    hdr.ack_message_ids
    Fmt.(option ~none:(any " ") uint64)
    hdr.remote_session

let decode_header buf =
  let open Result.Infix in
  guard (Cstruct.length buf >= hdr_len) `Partial >>= fun () ->
  let local_session = Cstruct.BE.get_uint64 buf 0
  and hmac = Cstruct.sub buf 8 hmac_len
  and packet_id = Cstruct.BE.get_uint32 buf (hmac_len + 8)
  and timestamp = Cstruct.BE.get_uint32 buf (hmac_len + 12)
  and arr_len = Cstruct.get_uint8 buf (hmac_len + 16) in
  let rs = if arr_len = 0 then 0 else 8 in
  guard
    (Cstruct.length buf >= hdr_len + (packet_id_len * arr_len) + rs)
    `Partial
  >>| fun () ->
  let ack_message_id idx =
    Cstruct.BE.get_uint32 buf (hdr_len + (packet_id_len * idx))
  in
  let ack_message_ids = List.init arr_len ack_message_id in
  let remote_session =
    if arr_len > 0 then
      Some (Cstruct.BE.get_uint64 buf (hdr_len + (packet_id_len * arr_len)))
    else None
  in
  ( {
      local_session;
      hmac;
      packet_id;
      timestamp;
      ack_message_ids;
      remote_session;
    },
    hdr_len + (packet_id_len * arr_len) + rs )

let encode_header hdr =
  let id_arr_len = packet_id_len * List.length hdr.ack_message_ids in
  let rsid = if id_arr_len = 0 then 0 else 8 in
  let buf = Cstruct.create (hdr_len + rsid + id_arr_len) in
  Cstruct.BE.set_uint64 buf 0 hdr.local_session;
  Cstruct.blit hdr.hmac 0 buf 8 hmac_len;
  Cstruct.BE.set_uint32 buf (hmac_len + 8) hdr.packet_id;
  Cstruct.BE.set_uint32 buf (hmac_len + 12) hdr.timestamp;
  Cstruct.set_uint8 buf (hmac_len + 16) (List.length hdr.ack_message_ids);
  List.iteri
    (fun i v ->
      Cstruct.BE.set_uint32 buf (hmac_len + 17 + (i * packet_id_len)) v)
    hdr.ack_message_ids;
  (match hdr.remote_session with
  | None -> ()
  | Some v ->
      assert (rsid <> 0);
      Cstruct.BE.set_uint64 buf (hdr_len + id_arr_len) v);
  (buf, hdr_len + rsid + id_arr_len)

let to_be_signed_header ?(more = 0) op header =
  (* packet_id ++ timestamp ++ operation ++ session_id ++ ack_len ++ acks ++ remote_session ++ msg_id *)
  let acks =
    match header.ack_message_ids with
    | [] -> 0
    | x -> List.length x * packet_id_len
  and rses = match header.remote_session with None -> 0 | Some _ -> 8 in
  let buflen = packet_id_len + 4 + 1 + 8 + 1 + acks + rses + more in
  let buf = Cstruct.create buflen in
  Cstruct.BE.set_uint32 buf 0 header.packet_id;
  Cstruct.BE.set_uint32 buf 4 header.timestamp;
  Cstruct.set_uint8 buf 8 op;
  Cstruct.BE.set_uint64 buf 9 header.local_session;
  Cstruct.set_uint8 buf 17 (List.length header.ack_message_ids);
  let rec enc_ack off = function
    | [] -> ()
    | hd :: tl ->
        Cstruct.BE.set_uint32 buf off hd;
        enc_ack (off + 4) tl
  in
  enc_ack 18 header.ack_message_ids;
  (match header.remote_session with
  | None -> ()
  | Some x -> Cstruct.BE.set_uint64 buf (18 + acks) x);
  (buf, 18 + acks + rses)

type control = header * packet_id * Cstruct.t

let pp_control ppf (hdr, id, payload) =
  Fmt.pf ppf "%a message-id %lu@.payload %d bytes" pp_header hdr id
    (Cstruct.length payload)

let decode_control buf =
  let open Result.Infix in
  decode_header buf >>= fun (header, off) ->
  guard (Cstruct.length buf >= off + 4) `Partial >>| fun () ->
  let message_id = Cstruct.BE.get_uint32 buf off
  and payload = Cstruct.shift buf (off + 4) in
  (header, message_id, payload)

let encode_control (header, packet_id, payload) =
  let hdr_buf, len = encode_header header in
  let packet_id_buf = Cstruct.create 4 in
  Cstruct.BE.set_uint32 packet_id_buf 0 packet_id;
  ( Cstruct.concat [ hdr_buf; packet_id_buf; payload ],
    len + Cstruct.length payload + 4 )

let to_be_signed_control op (header, packet_id, payload) =
  (* rly? not length!? *)
  let buf, off = to_be_signed_header ~more:packet_id_len op header in
  Cstruct.BE.set_uint32 buf off packet_id;
  Cstruct.append buf payload

let encode_data payload = (payload, Cstruct.length payload)

let decode_protocol proto buf =
  let open Result.Infix in
  match proto with
  | `Tcp ->
      guard (Cstruct.length buf >= 2) `Partial >>= fun () ->
      let plen = Cstruct.BE.get_uint16 buf 0 in
      guard (Cstruct.length buf - 2 >= plen) `Partial >>| fun () ->
      (Cstruct.sub buf 2 plen, Cstruct.shift buf (plen + 2))
  | `Udp -> Ok (buf, Cstruct.empty)

let decode proto buf =
  let open Result.Infix in
  decode_protocol proto buf >>= fun (buf', rest) ->
  guard (Cstruct.length buf' >= 1) `Partial >>= fun () ->
  let opkey = Cstruct.get_uint8 buf' 0 in
  let op, key = (opkey lsr 3, opkey land 0x07) in
  let payload = Cstruct.shift buf' 1 in
  (int_to_operation op >>= function
   | Ack -> decode_header payload >>| fun (ack, _) -> `Ack ack
   | Data_v1 -> Ok (`Data payload)
   | op' -> decode_control payload >>| fun ctl -> `Control (op', ctl))
  >>| fun res -> (key, res, rest)

let operation = function
  | `Ack _ -> Ack
  | `Control (op, _) -> op
  | `Data _ -> Data_v1

let op_key op key =
  let op = operation_to_int op in
  (op lsl 3) lor key

let encode_protocol proto len =
  match proto with
  | `Tcp ->
      let buf = Cstruct.create 2 in
      Cstruct.BE.set_uint16 buf 0 len;
      buf
  | `Udp -> Cstruct.empty

let encode proto (key, p) =
  let payload, len =
    match p with
    | `Ack ack -> encode_header ack
    | `Control (_, control) -> encode_control control
    | `Data d -> (d, Cstruct.length d)
  in
  let op_buf =
    let b = Cstruct.create 1 in
    let op = op_key (operation p) key in
    Cstruct.set_uint8 b 0 op;
    b
  in
  let prefix = encode_protocol proto (succ len) in
  Cstruct.concat [ prefix; op_buf; payload ]

let to_be_signed key p =
  let op = op_key (operation p) key in
  match p with
  | `Ack hdr -> fst (to_be_signed_header op hdr)
  | `Control (_, c) -> to_be_signed_control op c
  | `Data _ -> assert false

type pkt =
  [ `Ack of header | `Control of operation * control | `Data of Cstruct.t ]

type t = int * pkt

let header = function
  | `Ack hdr -> hdr
  | `Control (_, (hdr, _, _)) -> hdr
  | `Data _ -> assert false

let with_header hdr = function
  | `Ack _ -> `Ack hdr
  | `Control (op, (_, id, data)) -> `Control (op, (hdr, id, data))
  | `Data data -> `Data data

let message_id = function
  | `Ack _ -> None
  | `Control (_, (_, msg_id, _)) -> Some msg_id
  | `Data _ -> assert false

let pp ppf (key, p) =
  match p with
  | `Ack a -> Fmt.pf ppf "key %d ack %a" key pp_header a
  | `Control (op, c) ->
      Fmt.pf ppf "key %d control %a: %a" key pp_operation op pp_control c
  | `Data d -> Fmt.pf ppf "key %d data %d bytes" key (Cstruct.length d)

type tls_data = {
  (* key method v2 only! *)
  (* 4 zero bytes *)
  (* key_method_type : int ; (* uint8 *) *)
  pre_master : Cstruct.t; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t; (* 32 bytes *)
  random2 : Cstruct.t; (* 32 bytes *)
  (* 16 bit len *)
  options : string; (* null terminated -- record may end after options! *)
  (* 16 bit len, user (0 terminated), 16 bit len, password (0 terminated) *)
  user_pass : (string * string) option; (* 16 bit len *)
}

let pp_tls_data ppf t =
  Fmt.pf ppf "TLS data PMS %d R1 %d R2 %d options %s %a"
    (Cstruct.length t.pre_master)
    (Cstruct.length t.random1) (Cstruct.length t.random2) t.options
    Fmt.(
      option ~none:(any "no user + pass")
        (append (any "user: ") (pair ~sep:(any ", pass") string string)))
    t.user_pass

let key_method = 0x02

let encode_tls_data t =
  let prefix = Cstruct.create 5 in
  (* 4 zero bytes, and one byte key_method *)
  Cstruct.set_uint8 prefix 4 key_method;
  let key_source = Cstruct.concat [ t.pre_master; t.random1; t.random2 ] in
  let opt_len = Cstruct.create 2 in
  (* the options field, and also username and password are zero-terminated
     in addition to be length-prefixed... *)
  let null = Cstruct.create 1 in
  Cstruct.BE.set_uint16 opt_len 0 (succ (String.length t.options));
  let u_p =
    match t.user_pass with
    | None -> Cstruct.empty
    | Some (u, p) ->
        (* username and password are each 2 byte length, <value>, 0x00 *)
        let u_l = Cstruct.create 2 and p_l = Cstruct.create 2 in
        Cstruct.BE.set_uint16 u_l 0 (succ (String.length u));
        Cstruct.BE.set_uint16 p_l 0 (succ (String.length p));
        Cstruct.concat
          [ u_l; Cstruct.of_string u; null; p_l; Cstruct.of_string p; null ]
  and opt = Cstruct.of_string t.options in
  Cstruct.concat [ prefix; key_source; opt_len; opt; null; u_p ]

let maybe_string prefix buf off = function
  | 0 | 1 -> Ok ""
  | x ->
      let actual_len = pred x in
      (* null-terminated string *)
      let data = Cstruct.(to_string (sub buf off actual_len)) in
      if Cstruct.get_uint8 buf (off + actual_len) = 0x00 then Ok data
      else Error (`Malformed (prefix ^ " is not null-terminated"))

let decode_tls_data ?(with_premaster = false) buf =
  let open Result.Infix in
  let pre_master_start = 5 (* 4 (zero) + 1 (key_method) *) in
  let pre_master_len = if with_premaster then 48 else 0 in
  let random_len = 32 in
  let opt_start =
    (* the options start at
       pre_master_start + 2 (options length) + 32 random1 + 32 random2
       + pre_master_len (if its a client tls data) *)
    pre_master_start + 2 + random_len + random_len + pre_master_len
  in
  guard (Cstruct.length buf >= opt_start) `Partial >>= fun () ->
  guard
    (Cstruct.BE.get_uint32 buf 0 = 0l)
    (`Malformed "tls data must start with 32 bits set to 0")
  >>= fun () ->
  guard
    (Cstruct.get_uint8 buf 4 = key_method)
    (`Malformed "tls data key_method wrong")
  >>= fun () ->
  let pre_master = Cstruct.sub buf pre_master_start pre_master_len in
  let random_start = pre_master_start + pre_master_len in
  let random1 = Cstruct.sub buf random_start random_len
  and random2 = Cstruct.sub buf (random_start + random_len) random_len in
  let opt_len = Cstruct.BE.get_uint16 buf (opt_start - 2) in
  guard (Cstruct.length buf >= opt_start + opt_len) `Partial >>= fun () ->
  maybe_string "TLS data options" buf opt_start opt_len >>= fun options ->
  (if Cstruct.length buf = opt_start + opt_len then Ok None
   else
     (* more bytes - there's username and password (2 bytes len, value, 0x00) *)
     let u_start = opt_start + opt_len in
     guard (Cstruct.length buf >= u_start + 4 (* 2 * 16 bit len *)) `Partial
     >>= fun () ->
     let u_len = Cstruct.BE.get_uint16 buf (opt_start + opt_len) in
     guard (Cstruct.length buf >= u_start + 4 + u_len) `Partial >>= fun () ->
     maybe_string "username" buf (u_start + 2) u_len >>= fun u ->
     let p_start = u_start + 2 + u_len in
     let p_len = Cstruct.BE.get_uint16 buf p_start in
     guard (Cstruct.length buf >= p_start + 2 + u_len + p_len) `Partial
     >>= fun () ->
     maybe_string "password" buf (p_start + 2) p_len >>| fun p ->
     let end_of_data = p_start + 2 + p_len in
     (* for some reason there may be some slack here... *)
     if Cstruct.length buf > end_of_data then
       let data = Cstruct.shift buf end_of_data in
       Log.warn (fun m ->
           m "slack at end of tls_data %s (p is %s)@.%a"
             (Cstruct.to_string data) p Cstruct.hexdump_pp data)
     else ();
     match (u, p) with "", "" -> None | _ -> Some (u, p))
  >>| fun user_pass -> { pre_master; random1; random2; options; user_pass }

let push_request = Cstruct.of_string "PUSH_REQUEST\x00"
let push_reply = Cstruct.of_string "PUSH_REPLY"
