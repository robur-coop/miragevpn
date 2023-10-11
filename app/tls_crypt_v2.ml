let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Tls_crypt_v2_key : sig
  type t

  val of_cstruct : Cstruct.t -> (t, [> `Msg of string ]) result
  val to_string : t -> string
  val cipher_key : t -> Mirage_crypto.Cipher_block.AES.CTR.key
  val hmac : t -> Cstruct.t
  val equal : t -> t -> bool
  val pp_hum : t Fmt.t
end = struct
  type t = Cstruct.t (* cipher (64 bytes) + hmac (64 bytes) *)

  let of_cstruct cs =
    if Cstruct.length cs <> 128
    then error_msgf "Invalid tls-crypt-v2 key"
    else
      let len = Array.fold_left max 0 Mirage_crypto.Cipher_block.AES.CTR.key_sizes in
      try
        let secret = Cstruct.sub cs 0 len in
        let _ = Mirage_crypto.Cipher_block.AES.CTR.of_secret secret in Ok cs
      with exn -> error_msgf "Invalid AES-CTR secret key: %S" (Printexc.to_string exn)

  let to_string t = Cstruct.to_string t

  let cipher_key cs =
    let len = Array.fold_left max 0 Mirage_crypto.Cipher_block.AES.CTR.key_sizes in
    Mirage_crypto.Cipher_block.AES.CTR.of_secret (Cstruct.sub cs 0 len)

  let hmac cs = Cstruct.sub cs 64 64
  let equal a b = Eqaf_cstruct.equal a b

  let pp_hum ppf cs =
    let cipher_key = Cstruct.(to_string (sub cs 0 64)) in
    let hmac = Cstruct.(to_string (sub cs 64 64)) in
    Fmt.pf ppf "Cipher Key: @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) cipher_key;
    Fmt.pf ppf "HMAC Key:   @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) hmac
end

let _TLS_CRYPT_V2_CLIENT_KEY_LEN = 2048 / 8
let _TLS_CRYPT_V2_MAX_WKC_LEN = 1024
let _TLS_CRYPT_V2_TAG_SIZE = 256 / 8

let load_file filename =
  let ic = open_in filename in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  let finally () = close_in ic in
  Fun.protect ~finally @@ fun () ->
    really_input ic rs 0 ln;
    Bytes.unsafe_to_string rs

module List = struct
  include List

  let chop lst = match List.rev lst with
    | [] -> invalid_arg "List.chop"
    | _ :: lst -> List.rev lst

  let trim lst =
    List.fold_left (fun acc -> function
      | "" -> acc
      | str -> str :: acc) [] lst |> List.rev
end

module Metadata = struct
  type t =
    | User of string
    | Timestamp of Ptime.t

  let now () =
    Timestamp (Ptime_clock.now ())

  let to_cstruct = function
    | User str ->
        let cs = Cstruct.create (1 + String.length str) in
        Cstruct.set_uint8 cs 0 0;
        Cstruct.blit_from_string str 0 cs 1 (String.length str);
        cs
    | Timestamp ptime ->
        let n = Int64.of_float (Ptime.to_float_s ptime) in
        let cs = Cstruct.create (1 + 8) in
        Cstruct.set_uint8 cs 0 1;
        Cstruct.BE.set_uint64 cs 1 n;
        cs

  let of_cstruct cs =
    match Cstruct.get_uint8 cs 0 with
    | 0 ->
        if Cstruct.length cs > 1
        then Ok (User Cstruct.(to_string (sub cs 1 (length cs - 1))))
        else error_msgf "Invalid user metadata"
    | 1 ->
        begin
          try let n = Cstruct.BE.get_uint64 cs 1 in
              let n = Int64.to_float n in
              ( match Ptime.of_float_s n with
              | Some ptime -> Ok (Timestamp ptime)
              | None -> error_msgf "Invalid timestamp" )
          with _ -> error_msgf "Invalid timestamp metadata" end
    | _ -> error_msgf "Invalid metadata"
    | exception _ -> error_msgf "Invalid metadata"

  let pp_hum ppf = function
    | User str -> Fmt.pf ppf "User:       %S\n%!" str
    | Timestamp ptime -> Fmt.pf ppf "Timestamp:  %a\n%!" (Ptime.pp_rfc3339 ()) ptime
end

let load_pem ~name filename =
  let ic = open_in filename in
  let ln = in_channel_length ic in
  let rs = Bytes.create ln in
  really_input ic rs 0 ln;
  let str = load_file filename in
  match String.split_on_char '\n' str with
  | [ _ ] -> error_msgf "Invalid %s" name
  | header :: b64_and_footer when header = "-----BEGIN " ^ name ^ "-----" ->
    let b64_and_footer = List.trim b64_and_footer in
    let footer = List.hd (List.rev b64_and_footer) in
    if footer <> "-----END " ^ name ^ "-----"
    then error_msgf "Invalid %s" name
    else
      let b64 = String.concat "" (List.chop b64_and_footer) in
      Base64.decode b64
  | _ -> error_msgf "Invalid %s" name

let load_tls_crypt_v2_server_key filename =
  let ( let* ) = Result.bind in
  let* key = load_pem ~name:"OpenVPN tls-crypt-v2 server key" filename in
  Tls_crypt_v2_key.of_cstruct (Cstruct.of_string key)

let guard ~msg test =
  if test () then Ok () else Error (`Msg msg)

let tls_crypt_V2_unwrap_client server_key cs =
  let ( let* ) = Result.bind in
  let* () = guard ~msg:"Failed to read length" @@ fun () -> Cstruct.length cs >= 2 in
  let net_len = Cstruct.BE.get_uint16 cs (Cstruct.length cs - 2) in
  let* () = guard ~msg:"Invalid length" @@ fun () -> net_len = Cstruct.length cs in
  let* () = guard ~msg:"Failed to read tag" @@ fun () -> Cstruct.length cs >= _TLS_CRYPT_V2_TAG_SIZE in
  let tag = Cstruct.sub cs 0 _TLS_CRYPT_V2_TAG_SIZE in
  let module AES_CTR = Mirage_crypto.Cipher_block.AES.CTR in
  let ctr = AES_CTR.ctr_of_cstruct tag in
  let* key_and_metadata =
    try let payload = Cstruct.sub cs _TLS_CRYPT_V2_TAG_SIZE (net_len - _TLS_CRYPT_V2_TAG_SIZE - 2) in
        Ok (AES_CTR.decrypt ~key:(Tls_crypt_v2_key.cipher_key server_key) ~ctr payload)
    with _ -> error_msgf "Could not decrypt client key" in
  let ctx = Mirage_crypto.Hash.SHA256.hmac_empty ~key:(Tls_crypt_v2_key.hmac server_key) in
  let ctx = Mirage_crypto.Hash.SHA256.hmac_feed ctx (Cstruct.sub cs (Cstruct.length cs - 2) 2) in
  let ctx = Mirage_crypto.Hash.SHA256.hmac_feed ctx key_and_metadata in
  let tag' = Mirage_crypto.Hash.SHA256.hmac_get ctx in
  let* () = guard ~msg:"Client key authentication error" @@ fun () -> Eqaf_cstruct.equal tag tag' = false in
  let* () = guard ~msg:"Failed to read the client key" @@ fun () -> Cstruct.length key_and_metadata >= (128 * 2) in
    let* a = Tls_crypt_v2_key.of_cstruct (Cstruct.sub key_and_metadata 0 128) in
    let* b = Tls_crypt_v2_key.of_cstruct (Cstruct.sub key_and_metadata 128 128) in
  let metadata = Cstruct.sub key_and_metadata (128 * 2) (Cstruct.length key_and_metadata - (128 * 2)) in
  let* metadata = Metadata.of_cstruct metadata in
  Ok (a, b, metadata)

let load_tls_crypt_v2_client_key server_key filename =
  let ( let* ) = Result.bind in
  let* str = load_pem ~name:"OpenVPN tls-crypt-v2 client key" filename in
  let cs = Cstruct.of_string str in
  let* () = guard ~msg:"Can not read tls-crypt-v2 client key length" @@ fun () ->
    Cstruct.length cs >= 2 in
  let net_len = Cstruct.BE.get_uint16 cs (Cstruct.length cs - 2) in
  let* () = guard ~msg:"Can not locate tls-crypt-v2 wrapped client key" @@ fun () ->
    Cstruct.length cs >= net_len in
  let wkc = Cstruct.sub cs (Cstruct.length cs - net_len) net_len in
  let* () = guard ~msg:"Can not locate tls-crypt-v2 client key" @@ fun () ->
    Cstruct.length cs - net_len >= (128 * 2) in
  let kc = Cstruct.sub cs 0 (Cstruct.length cs - net_len) in
  let* a = Tls_crypt_v2_key.of_cstruct (Cstruct.sub kc 0 128) in
  let* b = Tls_crypt_v2_key.of_cstruct (Cstruct.sub kc 128 128) in
  let* (a', b', metadata) = tls_crypt_V2_unwrap_client server_key wkc in
  let* () = guard ~msg:"Client keys don't correspond" @@ fun () ->
    Tls_crypt_v2_key.equal a a' in
  let* () = guard ~msg:"Client keys don't correspond" @@ fun () ->
    Tls_crypt_v2_key.equal b b' in
  Ok (a, b, metadata)

let () =
  match Sys.argv with
  | [| _; "tls-crypt-v2"; "server"; filename |] when Sys.file_exists filename ->
    begin match load_tls_crypt_v2_server_key filename with
    | Ok key -> Fmt.pr "%a%!" Tls_crypt_v2_key.pp_hum key
    | Error (`Msg msg) -> Fmt.epr "%s: %s\n%!" Sys.executable_name msg end
  | [| _; "tls-crypt-v2"; "client"; filename; server |] when
    Sys.file_exists filename && Sys.file_exists server ->
    let result =
      let ( let* ) = Result.bind in
      let* server_key = load_tls_crypt_v2_server_key server in
      let* client_key = load_tls_crypt_v2_client_key server_key filename in
      Ok (server_key, client_key) in
    begin match result with
    | Ok (server_key, (a, b, metadata)) ->
        Fmt.pr "Server key:\n%!";
        Fmt.pr "%a%!" Tls_crypt_v2_key.pp_hum server_key;
        Fmt.pr "Client key:\n%!";
        Fmt.pr "%a%!" Tls_crypt_v2_key.pp_hum a;
        Fmt.pr "%a%!" Tls_crypt_v2_key.pp_hum b;
        Fmt.pr "Metadata:\n%!";
        Fmt.pr "%a%!" Metadata.pp_hum metadata
    | Error (`Msg msg) -> Fmt.epr "%s: %s\n%!" Sys.executable_name msg end
  | _ -> assert false
