let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let guard ~msg test = if test () then Ok () else Error (`Msg msg)

module List = struct
  include List

  let chop lst =
    match List.rev lst with
    | [] -> invalid_arg "List.chop"
    | _ :: lst -> List.rev lst

  let trim lst =
    List.fold_left (fun acc -> function "" -> acc | str -> str :: acc) [] lst
    |> List.rev
end

module String = struct
  include String

  let split_at n str =
    let rec go acc str off len =
      if len = 0 then List.rev acc
      else
        let len' = min n len in
        let str' = String.sub str off len' in
        go (str' :: acc) str (off + len') (len - len')
    in
    go [] str 0 (String.length str)
end

let _TLS_CRYPT_V2_CLIENT_KEY_LEN = 2048 / 8
let _TLS_CRYPT_V2_MAX_WKC_LEN = 1024
let _TLS_CRYPT_V2_TAG_SIZE = 256 / 8
let _TLS_CRYPT_V2_MIN_WKC_LEN =
  _TLS_CRYPT_V2_TAG_SIZE +
  _TLS_CRYPT_V2_CLIENT_KEY_LEN +
  1 + 2

let _TLS_CRYPT_V2_MAX_METADATA_LEN =
  _TLS_CRYPT_V2_MAX_WKC_LEN
  - (_TLS_CRYPT_V2_CLIENT_KEY_LEN + _TLS_CRYPT_V2_TAG_SIZE + 2)

let pem_of_lines ~name seq =
  let seq =
    Seq.drop_while (fun str -> String.length str > 0 && str.[0] = '#') seq
  in
  match List.of_seq seq with
  | [ _ ] -> error_msgf "Invalid %s" name
  | header :: b64_and_footer when header = "-----BEGIN " ^ name ^ "-----" ->
      let b64_and_footer = List.trim b64_and_footer in
      let footer = List.hd (List.rev b64_and_footer) in
      if footer <> "-----END " ^ name ^ "-----" then
        error_msgf "Invalid %s" name
      else
        let b64 = String.concat "" (List.chop b64_and_footer) in
        Base64.decode b64
  | _ -> error_msgf "Invalid %s" name

let hex_of_lines ~name seq =
  let seq =
    Seq.drop_while (fun str -> String.length str > 0 && str.[0] = '#') seq
  in
  match List.of_seq seq with
  | [ _ ] -> error_msgf "Invalid %s" name
  | header :: hex_and_footer when header = "-----BEGIN " ^ name ^ "-----" -> (
      let hex_and_footer = List.trim hex_and_footer in
      let footer = List.hd (List.rev hex_and_footer) in
      if footer <> "-----END " ^ name ^ "-----" then
        error_msgf "Invalid %s" name
      else
        let hex = List.chop hex_and_footer in
        let buf = Buffer.create 0x100 in
        let f str =
          for i = 0 to (String.length str / 2) - 1 do
            let chr = Hex.to_char str.[i * 2] str.[(i * 2) + 1] in
            Buffer.add_char buf chr
          done
        in
        try
          List.iter f hex;
          Ok (Buffer.contents buf)
        with _ -> error_msgf "Invalid %s" name)
  | _ -> error_msgf "Invalid %s" name

module Key : sig
  type t

  val of_cstruct : Cstruct.t -> (t, [> `Msg of string ]) result

  val unsafe_to_cstruct : t -> Cstruct.t
  val to_string : t -> string
  val cipher_key : t -> Mirage_crypto.Cipher_block.AES.CTR.key
  val hmac : t -> Cstruct.t
  val equal : t -> t -> bool
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val to_base64 : t -> string
end = struct
  type t = Cstruct.t (* cipher (64 bytes) + hmac (64 bytes) *)

  let len_of_secret_aes_ctr_key =
    Array.to_list Mirage_crypto.Cipher_block.AES.CTR.key_sizes
    |> List.filter (( > ) 128) (* ∀x. 128 > x <=> ∀x. x <= 128 *)
    |> List.fold_left max 0

  (* NOTE: it's a bit paranoid but we ensure that [mirage-crypto] exposes values
     which fit with an OpenVPN key (128 bytes). *)
  let () = assert (len_of_secret_aes_ctr_key > 0)

  let of_cstruct cs =
    if Cstruct.length cs <> 128 then error_msgf "Invalid tls-crypt key"
    else Ok cs

  let unsafe_to_cstruct x = x
  let to_string t = Cstruct.to_string t

  let cipher_key cs =
    Mirage_crypto.Cipher_block.AES.CTR.of_secret
      (Cstruct.sub cs 0 len_of_secret_aes_ctr_key)

  let hmac cs = Cstruct.sub cs 64 Mirage_crypto.Hash.SHA256.digest_size

  let equal = Eqaf_cstruct.equal

  let generate ?g () = Mirage_crypto_rng.generate ?g 128

  let to_base64 cs =
    let str = Cstruct.to_string cs in
    Base64.encode_string ~pad:true str
end

module Metadata = struct
  type t = User of string | Timestamp of Ptime.t

  let timestamp now = Timestamp now

  let user str =
    if String.length str >= _TLS_CRYPT_V2_MAX_METADATA_LEN then
      invalid_arg "Tls_crypt.Metadata.user";
    User str

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
        if Cstruct.length cs > 1 then
          Ok (User Cstruct.(to_string (sub cs 1 (length cs - 1))))
        else error_msgf "Invalid user metadata"
    | 1 -> (
        if Cstruct.length cs <> 1 + 8 then
          error_msgf "Invalid timestamp: invalid length"
        else
          try
            let n = Cstruct.BE.get_uint64 cs 1 in
            let n = Int64.to_float n in
            match Ptime.of_float_s n with
            | Some ptime -> Ok (Timestamp ptime)
            | None -> error_msgf "Invalid timestamp"
          with _ -> error_msgf "Invalid timestamp metadata")
    | _ -> error_msgf "Invalid metadata"
    | exception _ -> error_msgf "Invalid metadata"

  let pp_hum ppf = function
    | User str -> Fmt.pf ppf "User:       %S\n%!" str
    | Timestamp ptime ->
        Fmt.pf ppf "Timestamp:  %a\n%!" (Ptime.pp_rfc3339 ()) ptime
end

module Server : sig
  type t = Key.t

  val load : lines:string Seq.t -> (t, [> `Msg of string ]) result

  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val save : t -> string Seq.t
  val pp : t Fmt.t
  val equal : t -> t -> bool
end = struct
  type t = Key.t

  let load ~lines =
    let ( let* ) = Result.bind in
    let* key = pem_of_lines ~name:"OpenVPN tls-crypt-v2 server key" lines in
    Key.of_cstruct (Cstruct.of_string key)

  let generate ?g () = Key.generate ?g ()

  let save server_key =
    let b64 = Key.to_base64 server_key in
    let lines =
      "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
      :: String.split_at 64 b64
      @ [ "-----END OpenVPN tls-crypt-v2 server key-----"; "" ]
    in
    List.to_seq lines

  let pp = Fmt.(using Key.to_base64 string)
  let equal = Key.equal
end

module Tls_crypt : sig
  type t

  val server_key : t -> Key.t
  val client_key : t -> Key.t

  val of_cstruct : Cstruct.t -> (t, [> `Msg of string ]) result

  val load_v1 : string Seq.t -> (t, [> `Msg of string ]) result

  val generate : ?g:Mirage_crypto_rng.g -> unit-> t

  val save_v1 : t -> string Seq.t
  val equal : t -> t -> bool
end = struct
  type t = Key.t * Key.t

  let of_cstruct buf =
    let open Result.Syntax in
    let* () =
      guard ~msg:"Invalid tls-crypt key" @@ fun () ->
      Cstruct.length buf = 256
    in
    let* server_key = Key.of_cstruct (Cstruct.sub buf 0 128) in
    let* client_key = Key.of_cstruct (Cstruct.sub buf 128 128) in
    Ok (server_key, client_key)


  let server_key (k, _) = k
  let client_key (_, k) = k

  let load_v1 lines =
    let ( let* ) = Result.bind in
    let* str = hex_of_lines ~name:"OpenVPN Static key V1" lines in
    let cs = Cstruct.of_string str in
    let* () =
      guard ~msg:"Truncated OpenVPN Static key V1" @@ fun () ->
      Cstruct.length cs >= 256
    in
    let* a = Key.of_cstruct (Cstruct.sub cs 0 128) in
    let* b = Key.of_cstruct (Cstruct.sub cs 128 128) in
    Ok (a, b)

  let generate ?g () =
    let a = Key.generate ?g () in
    let b = Key.generate ?g () in
    (a, b)

  let save_v1 (a, b) =
    let k =
      Cstruct.concat [ Key.unsafe_to_cstruct a; Key.unsafe_to_cstruct b ]
    in
    let (`Hex h) = Hex.of_cstruct k in
    let lines = List.init (256 / 16) (fun i -> String.sub h (i * 32) 32) in
    let lines =
      ("-----BEGIN OpenVPN Static key V1-----" :: lines)
      @ [ "-----END OpenVPN Static key V1-----"; "" ]
    in
    List.to_seq lines

  let equal (a, b) (a', b') =
    Key.equal a a' && Key.equal b b'
end

module Wrapped_key : sig
  type t
  val of_cstruct : Cstruct.t -> (Cstruct.t * t, [> `Msg of string ]) result
  val wrap : key:Server.t -> Tls_crypt.t -> Metadata.t -> t
  val unwrap : key:Server.t -> t -> (Tls_crypt.t * Metadata.t, [> `Msg of string ]) result
  val unsafe_to_cstruct : t -> Cstruct.t
end = struct
  type t = Cstruct.t

  let unsafe_to_cstruct t = t

  let of_cstruct buf =
    let open Result.Syntax in
    let* () =
      guard ~msg:"Can not read wKc length" @@ fun () ->
      Cstruct.length buf >= 2
    in
    let net_len = Cstruct.BE.get_uint16 buf (Cstruct.length buf - 2) in
    let* () =
      guard ~msg:"Can not locate wKc" @@ fun () ->
      Cstruct.length buf >= net_len
    in
    let* () =
      guard ~msg:"wKc too small" @@ fun () ->
      net_len >= _TLS_CRYPT_V2_MIN_WKC_LEN
    in
    let+ () =
      guard ~msg:"wKc too big" @@ fun () ->
      net_len <= _TLS_CRYPT_V2_MAX_WKC_LEN
    in
    Cstruct.split buf (Cstruct.length buf - net_len)

  let wrap ~key:server_key key metadata =
    let a = Key.unsafe_to_cstruct (Tls_crypt.server_key key) in
    let b = Key.unsafe_to_cstruct (Tls_crypt.client_key key) in
    let metadata = Metadata.to_cstruct metadata in
    let net_len =
      _TLS_CRYPT_V2_TAG_SIZE + Cstruct.lenv [a; b; metadata] + 2
    in
    let net_len =
      let cs = Cstruct.create 2 in
      Cstruct.BE.set_uint16 cs 0 net_len;
      cs
    in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_empty ~key:(Key.hmac server_key) in
    let ctx =
      List.fold_left
        Mirage_crypto.Hash.SHA256.hmac_feed 
        ctx
        [net_len; a; b; metadata]
    in
    let tag = Mirage_crypto.Hash.SHA256.hmac_get ctx in
    let module AES_CTR = Mirage_crypto.Cipher_block.AES.CTR in
    let ctr = AES_CTR.ctr_of_cstruct tag in
    let encrypted =
      AES_CTR.encrypt
        ~key:(Key.cipher_key server_key)
        ~ctr
        (Cstruct.concat [ a; b; metadata ])
    in
    Cstruct.concat [ tag; encrypted; net_len ]

  let unwrap ~key:server_key wkc =
    let open Result.Syntax in
    let tag = Cstruct.sub wkc 0 _TLS_CRYPT_V2_TAG_SIZE in
    let module AES_CTR = Mirage_crypto.Cipher_block.AES.CTR in
    let ctr = AES_CTR.ctr_of_cstruct tag in
    let* key_and_metadata =
      try
        let payload =
          Cstruct.sub wkc _TLS_CRYPT_V2_TAG_SIZE
            (Cstruct.length wkc - _TLS_CRYPT_V2_TAG_SIZE - 2)
        in
        Ok (AES_CTR.decrypt ~key:(Key.cipher_key server_key) ~ctr payload)
      with _ -> error_msgf "Could not decrypt client key"
    in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_empty ~key:(Key.hmac server_key) in
    let ctx =
      Mirage_crypto.Hash.SHA256.hmac_feed ctx
        (Cstruct.sub wkc (Cstruct.length wkc - 2) 2)
    in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_feed ctx key_and_metadata in
    let tag' = Mirage_crypto.Hash.SHA256.hmac_get ctx in
    let* () =
      guard ~msg:"Client key authentication error" @@ fun () ->
      Eqaf_cstruct.equal tag tag'
    in
    let* () =
      guard ~msg:"Failed to read the client key" @@ fun () ->
      Cstruct.length key_and_metadata >= 128 * 2
    in
    let* key = Tls_crypt.of_cstruct (Cstruct.sub key_and_metadata 0 256) in
    let metadata =
      Cstruct.sub key_and_metadata (128 * 2)
        (Cstruct.length key_and_metadata - (128 * 2))
    in
    let* metadata = Metadata.of_cstruct metadata in
    Ok (key, metadata)
end

let load_tls_crypt_v2_client lines =
  let open Result.Syntax in
  let* str = pem_of_lines ~name:"OpenVPN tls-crypt-v2 client key" lines in
  let cs = Cstruct.of_string str in
  let* key, wkc = Wrapped_key.of_cstruct cs in
  let+ key = Tls_crypt.of_cstruct key in
  (key, wkc)

let save_tls_crypt_v2_client key wkc =
  let a = Key.unsafe_to_cstruct (Tls_crypt.server_key key) in
  let b = Key.unsafe_to_cstruct (Tls_crypt.client_key key) in
  let wkc = Wrapped_key.unsafe_to_cstruct wkc in
  let payload = Cstruct.to_string (Cstruct.concat [a; b; wkc]) in
  let b64 = Base64.encode_string ~pad:true payload in
  let lines = String.split_at 64 b64 in
  let lines =
    ("-----BEGIN OpenVPN tls-crypt-v2 client key-----" :: lines)
    @ [ "-----END OpenVPN tls-crypt-v2 client key-----"; "" ]
  in
  List.to_seq lines
