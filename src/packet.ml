(* packet format, as defined in the openvpn-protocol document

   no support for key method v1! *)

module Log =
  (val Logs.(
         src_log
         @@ Src.create ~doc:"Miragevpn library's packet module" "ovpn.packet")
      : Logs.LOG)

type error =
  [ `Tcp_partial | `Partial | `Unknown_operation of int | `Malformed of string ]

let pp_error ppf = function
  | `Tcp_partial -> Fmt.string ppf "pending data"
  | `Partial -> Fmt.string ppf "partial"
  | `Unknown_operation op -> Fmt.pf ppf "unknown operation %d" op
  | `Malformed msg -> Fmt.pf ppf "malformed %s" msg

type operation =
  | Soft_reset_v2
  | Control
  | Ack
  | Data_v1
  | Hard_reset_client_v2
  | Hard_reset_server_v2
  | Hard_reset_client_v3

let operation_to_int, int_to_operation =
  let ops =
    [
      (Soft_reset_v2, 3);
      (Control, 4);
      (Ack, 5);
      (Data_v1, 6);
      (Hard_reset_client_v2, 7);
      (Hard_reset_server_v2, 8);
      (Hard_reset_client_v3, 10);
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
    | Soft_reset_v2 -> "soft reset v2"
    | Control -> "control"
    | Ack -> "ack"
    | Data_v1 -> "data v1"
    | Hard_reset_client_v2 -> "hard reset client v2"
    | Hard_reset_server_v2 -> "hard reset server v2"
    | Hard_reset_client_v3 -> "hard reset client v3")

type packet_id = int32 (* 4 or 8 bytes -- latter in pre-shared key mode *)

let packet_id_len = 4
let cipher_block_size = 16
let aead_nonce = 12
let hdr_len hmac_len = 8 + hmac_len + packet_id_len + 4 + 1
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

let decode_header ~hmac_len buf =
  let open Result.Infix in
  guard (Cstruct.length buf >= hdr_len hmac_len) `Partial >>= fun () ->
  let local_session = Cstruct.BE.get_uint64 buf 0
  and hmac = Cstruct.sub buf 8 hmac_len
  and packet_id = Cstruct.BE.get_uint32 buf (hmac_len + 8)
  and timestamp = Cstruct.BE.get_uint32 buf (hmac_len + 12)
  and arr_len = Cstruct.get_uint8 buf (hmac_len + 16) in
  let rs = if arr_len = 0 then 0 else 8 in
  guard
    (Cstruct.length buf >= hdr_len hmac_len + (packet_id_len * arr_len) + rs)
    `Partial
  >>| fun () ->
  let ack_message_id idx =
    Cstruct.BE.get_uint32 buf (hdr_len hmac_len + (packet_id_len * idx))
  in
  let ack_message_ids = List.init arr_len ack_message_id in
  let remote_session =
    if arr_len > 0 then
      Some
        (Cstruct.BE.get_uint64 buf
           (hdr_len hmac_len + (packet_id_len * arr_len)))
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
    hdr_len hmac_len + (packet_id_len * arr_len) + rs )

let encode_header hdr =
  let id_arr_len = packet_id_len * List.length hdr.ack_message_ids in
  let rsid = if id_arr_len = 0 then 0 else 8 in
  let hmac_len = Cstruct.length hdr.hmac in
  let buf = Cstruct.create (hdr_len hmac_len + rsid + id_arr_len) in
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
      Cstruct.BE.set_uint64 buf (hdr_len hmac_len + id_arr_len) v);
  (buf, hdr_len hmac_len + rsid + id_arr_len)

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

let decode_ack ~hmac_len buf =
  let open Result.Syntax in
  let+ hdr, off = decode_header ~hmac_len buf in
  if off <> Cstruct.length buf then
    Log.debug (fun m ->
        m "decode_ack: %d extra bytes at end of message"
          (Cstruct.length buf - off));
  hdr

let decode_control ~hmac_len buf =
  let open Result.Infix in
  decode_header ~hmac_len buf >>= fun (header, off) ->
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

let decode_protocol proto buf =
  let open Result.Infix in
  match proto with
  | `Tcp ->
      guard (Cstruct.length buf >= 2) `Tcp_partial >>= fun () ->
      let plen = Cstruct.BE.get_uint16 buf 0 in
      guard (Cstruct.length buf - 2 >= plen) `Tcp_partial >>| fun () ->
      (Cstruct.sub buf 2 plen, Cstruct.shift buf (plen + 2))
  | `Udp -> Ok (buf, Cstruct.empty)

let decode_key_op proto buf =
  let open Result.Syntax in
  let* buf, linger = decode_protocol proto buf in
  let* () = guard (Cstruct.length buf >= 1) `Partial in
  let opkey = Cstruct.get_uint8 buf 0 in
  let op, key = (opkey lsr 3, opkey land 0x07) in
  let+ op = int_to_operation op in
  (op, key, Cstruct.shift buf 1, linger)

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
  | `Data _ -> assert false (* Not called with `Data _ *)

module Tls_crypt = struct
  type cleartext_header = {
    local_session : int64;
    packet_id : packet_id;
    timestamp : int32;
    hmac : Cstruct.t; (* always 32 bytes *)
  }

  let hmac_algorithm = `SHA256
  let hmac_len = Mirage_crypto.Hash.SHA256.digest_size (* 32 *)
  let hmac_offset = 16

  (* [encrypted_offset] is the offset of the header payload that is encrypted *)
  let encrypted_offset = hmac_offset + hmac_len
  let clear_hdr_len = hdr_len hmac_len - 1 (* not including acked msg ids *)

  let to_be_signed_header ?(more = 0) op header =
    (* op_key ++ session_id ++ packet_id ++ timestamp ++ ack_len ++ acks ++ remote_session ++ msg_id *)
    let acks_len = List.length header.ack_message_ids * packet_id_len
    and rses_len = if Option.is_some header.remote_session then 8 else 0 in
    let buflen = 1 + 8 + packet_id_len + 4 + 1 + acks_len + rses_len + more in
    let buf = Cstruct.create buflen in
    Cstruct.set_uint8 buf 0 op;
    Cstruct.BE.set_uint64 buf 1 header.local_session;
    Cstruct.BE.set_uint32 buf 9 header.packet_id;
    Cstruct.BE.set_uint32 buf 13 header.timestamp;
    Cstruct.set_uint8 buf 17 (List.length header.ack_message_ids);
    let enc_ack idx ack = Cstruct.BE.set_uint32 buf (18 + (4 * idx)) ack in
    List.iteri enc_ack header.ack_message_ids;
    Option.iter
      (Cstruct.BE.set_uint64 buf (18 + acks_len))
      header.remote_session;
    (buf, 18 + acks_len + rses_len)

  let to_be_signed_control op (header, packet_id, payload) =
    let buf, off =
      to_be_signed_header op header
        ~more:(packet_id_len + Cstruct.length payload)
    in
    Cstruct.BE.set_uint32 buf off packet_id;
    Cstruct.blit payload 0 buf (off + packet_id_len) (Cstruct.length payload);
    buf

  let to_be_signed key p =
    let op = op_key (operation p) key in
    match p with
    | `Ack hdr -> fst (to_be_signed_header op hdr)
    | `Control (Hard_reset_client_v3, (hdr, msg_id, _wkc)) ->
        (* HARD_RESET_CLIENT_V3 is special: the wkc is not considered part of the packet *)
        to_be_signed_control op (hdr, msg_id, Cstruct.empty)
    | `Control (_, c) -> to_be_signed_control op c
    | `Data _ -> assert false (* Not called with `Data _ *)

  let encode_header hdr =
    let acks_len = packet_id_len * List.length hdr.ack_message_ids in
    let rsid_len = if acks_len = 0 then 0 else 8 in
    let hmac_len = Cstruct.length hdr.hmac in
    let buf = Cstruct.create (clear_hdr_len + 1 + acks_len + rsid_len) in
    Cstruct.BE.set_uint64 buf 0 hdr.local_session;
    (* annoyingly the replay packet id and hmac are swapped from the tls-auth header *)
    Cstruct.BE.set_uint32 buf 8 hdr.packet_id;
    Cstruct.BE.set_uint32 buf 12 hdr.timestamp;
    Cstruct.blit hdr.hmac 0 buf 16 hmac_len;
    Cstruct.set_uint8 buf (16 + hmac_len) (List.length hdr.ack_message_ids);
    List.iteri
      (fun i v ->
        Cstruct.BE.set_uint32 buf (hmac_len + 17 + (i * packet_id_len)) v)
      hdr.ack_message_ids;
    Option.iter
      (fun v ->
        assert (rsid_len <> 0);
        Cstruct.BE.set_uint64 buf (clear_hdr_len + 1 + acks_len) v)
      hdr.remote_session;
    (buf, clear_hdr_len + 1 + acks_len + rsid_len)

  let encode_control op (header, packet_id, payload) =
    let hdr_buf, len = encode_header header in
    let packet_id_buf, len = (Cstruct.create 4, len + 4) in
    Cstruct.BE.set_uint32 packet_id_buf 0 packet_id;
    let len =
      match op with
      | Hard_reset_client_v3 ->
          (* In Hard_reset_client_v3 we don't consider wKc part of the payload *)
          len
      | _ -> len + Cstruct.length payload
    in
    (Cstruct.concat [ hdr_buf; packet_id_buf; payload ], len)

  let encode proto (key, p) =
    (* here [len] is the length of the data that is considered part of the packet;
       for Hard_reset_client_v3 the wKc is appended after the packet. Thus
       [len] may be shorter than [Cstruct.length payload]. *)
    let payload, len =
      match p with
      | `Ack ack -> encode_header ack
      | `Control (op, control) -> encode_control op control
      | `Data _ -> assert false (* Not called with `Data _ *)
    in
    let op_buf =
      let b = Cstruct.create 1 in
      let op = op_key (operation p) key in
      Cstruct.set_uint8 b 0 op;
      b
    in
    let prefix = encode_protocol proto (Cstruct.lenv [ op_buf; payload ]) in
    let r = Cstruct.concat [ prefix; op_buf; payload ] in
    (* packet, to_encrypt_offset, to_encrypt_length *)
    ( r,
      Cstruct.length prefix + Cstruct.length op_buf + encrypted_offset,
      len - encrypted_offset )

  let decode_decrypted_header clear_hdr buf =
    let open Result.Syntax in
    let* () = guard (Cstruct.length buf >= 1) `Partial in
    let arr_len = Cstruct.get_uint8 buf 0 in
    let rs_len = if arr_len = 0 then 0 else 8 in
    let+ () =
      guard
        (Cstruct.length buf >= 1 + (packet_id_len * arr_len) + rs_len)
        `Partial
    in
    let ack_message_id idx =
      Cstruct.BE.get_uint32 buf (1 + (packet_id_len * idx))
    in
    let ack_message_ids = List.init arr_len ack_message_id in
    let remote_session =
      if rs_len > 0 then
        Some (Cstruct.BE.get_uint64 buf (1 + (packet_id_len * arr_len)))
      else None
    in
    let { local_session; packet_id; timestamp; hmac } = clear_hdr in
    let res =
      {
        local_session;
        packet_id;
        timestamp;
        hmac;
        ack_message_ids;
        remote_session;
      }
    in
    (res, 1 + (arr_len * packet_id_len) + rs_len)

  let decode_decrypted_ack clear_hdr buf =
    let open Result.Syntax in
    let+ hdr, off = decode_decrypted_header clear_hdr buf in
    if off <> Cstruct.length buf then
      Log.debug (fun m ->
          m "decode_decrypted_ack: %d extra bytes at end of message"
            (Cstruct.length buf - off));
    hdr

  let decode_decrypted_control clear_hdr buf =
    let open Result.Syntax in
    let* hdr, off = decode_decrypted_header clear_hdr buf in
    let+ () = guard (Cstruct.length buf >= off + 4) `Partial in
    let message_id = Cstruct.BE.get_uint32 buf off
    and payload = Cstruct.shift buf (off + 4) in
    (hdr, message_id, payload)

  let decode_cleartext_header buf =
    let open Result.Syntax in
    (* header up till acked message ids *)
    let+ () = guard (Cstruct.length buf >= clear_hdr_len) `Partial in
    let local_session = Cstruct.BE.get_uint64 buf 0
    and packet_id = Cstruct.BE.get_uint32 buf 8
    and timestamp = Cstruct.BE.get_uint32 buf 12
    and hmac = Cstruct.sub buf 16 hmac_len in
    ({ local_session; packet_id; timestamp; hmac }, clear_hdr_len)
end

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
  peer_info : string list option;
}

let pp_tls_data ppf t =
  Fmt.pf ppf "TLS data PMS %d R1 %d R2 %d options %s %a %a"
    (Cstruct.length t.pre_master)
    (Cstruct.length t.random1) (Cstruct.length t.random2) t.options
    Fmt.(
      option ~none:(any "no user + pass")
        (append (any "user: ") (pair ~sep:(any ", pass") string string)))
    t.user_pass
    Fmt.(
      option ~none:(any "no peer-info")
        (append (any "peer-info ") Fmt.(list ~sep:(any ", ") Dump.string)))
    t.peer_info

let key_method = 0x02

(* strings are
   (a) length-prefixed (2 bytes, big endian);
   (b) terminated with 0 byte;
   the terminating 0 byte is accounted for the length *)
let write_string str =
  let len = String.length str in
  let buf = Cstruct.create (len + 3) in
  Cstruct.blit_from_string str 0 buf 2 len;
  Cstruct.BE.set_uint16 buf 0 (succ len);
  buf

let encode_tls_data t =
  let prefix = Cstruct.create 5 in
  (* 4 zero bytes, and one byte key_method *)
  Cstruct.set_uint8 prefix 4 key_method;
  (* the options field, and also username and password are zero-terminated
     in addition to be length-prefixed... *)
  let opt = write_string t.options
  and u_p =
    (* always send username and password, empty if there's none *)
    let u, p = Option.value ~default:("", "") t.user_pass in
    (* username and password are each 2 byte length, <value>, 0x00 *)
    [ write_string u; write_string p ]
  in
  let peer_info =
    Option.map (fun pi -> String.concat "\n" (pi @ [])) t.peer_info
    |> Option.map write_string |> Option.to_list
  in
  (* prefix - 4 zero bytes, key_method
     pre_master
     random1
     random2
     opt string
     user string
     password string
     peer_info
  *)
  Cstruct.concat
    ([ prefix; t.pre_master; t.random1; t.random2; opt ] @ u_p @ peer_info)

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
  (if Cstruct.length buf = opt_start + opt_len then Ok (None, None)
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
     maybe_string "password" buf (p_start + 2) p_len >>= fun p ->
     let user_pass = match (u, p) with "", "" -> None | _ -> Some (u, p) in
     let peer_info_start = p_start + 2 + p_len in
     (* dinosaure: if we don't have enough to have a peer-info (at least 2 bytes),
        we just ignore it and return [None]. *)
     (if Cstruct.length buf <= peer_info_start + 2 then Ok None
      else
        let data = Cstruct.shift buf peer_info_start in
        let len = Cstruct.BE.get_uint16 data 0 in
        let data = Cstruct.shift data 2 in
        guard (Cstruct.length data >= len) `Partial >>= fun () ->
        if Cstruct.length data > len then
          Log.warn (fun m ->
              m "slack at end of tls_data %S @.%a"
                (Cstruct.to_string ~len data)
                Cstruct.hexdump_pp data);
        Ok (if len = 0 then None else Some (Cstruct.to_string ~len data)))
     >>| fun peer_info ->
     (user_pass, Option.map (String.split_on_char '\n') peer_info))
  >>| fun (user_pass, peer_info) ->
  { pre_master; random1; random2; options; user_pass; peer_info }

let push_request = Cstruct.of_string "PUSH_REQUEST\x00"
let push_reply = Cstruct.of_string "PUSH_REPLY"
