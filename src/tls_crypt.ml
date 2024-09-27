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
  _TLS_CRYPT_V2_TAG_SIZE + _TLS_CRYPT_V2_CLIENT_KEY_LEN + 1 + 2

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
          let data = Ohex.decode str in
          Buffer.add_string buf data
        in
        try
          List.iter f hex;
          Ok (Buffer.contents buf)
        with _ -> error_msgf "Invalid %s" name)
  | _ -> error_msgf "Invalid %s" name

module Key : sig
  type t

  val of_octets : string -> (t, [> `Msg of string ]) result
  val to_octets : t -> string
  val cipher_key : t -> Mirage_crypto.AES.CTR.key
  val hmac : t -> string
  val equal : t -> t -> bool
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val to_base64 : t -> string
end = struct
  type t = string (* cipher (64 bytes) + hmac (64 bytes) *)

  let len_of_secret_aes_ctr_key =
    Array.to_list Mirage_crypto.AES.CTR.key_sizes
    |> List.filter (( > ) 128) (* ∀x. 128 > x <=> ∀x. x <= 128 *)
    |> List.fold_left max 0

  (* NOTE: it's a bit paranoid but we ensure that [mirage-crypto] exposes values
     which fit with an OpenVPN key (128 bytes). *)
  let () = assert (len_of_secret_aes_ctr_key > 0)

  let of_octets cs =
    if String.length cs <> 128 then error_msgf "Invalid tls-crypt key"
    else Ok cs

  let to_octets t = t

  let cipher_key cs =
    Mirage_crypto.AES.CTR.of_secret (String.sub cs 0 len_of_secret_aes_ctr_key)

  let hmac cs = String.sub cs 64 Digestif.SHA256.digest_size
  let equal = Eqaf.equal
  let generate ?g () = Mirage_crypto_rng.generate ?g 128
  let to_base64 cs = Base64.encode_string ~pad:true cs
end

module Metadata = struct
  type t = User of string | Timestamp of Ptime.t

  let timestamp now = Timestamp now

  let user str =
    if String.length str >= _TLS_CRYPT_V2_MAX_METADATA_LEN then
      invalid_arg "Tls_crypt.Metadata.user";
    User str

  let to_octets = function
    | User str -> "\000" ^ str
    | Timestamp ptime ->
        let n = Int64.of_float (Ptime.to_float_s ptime) in
        let cs = Bytes.create (1 + 8) in
        Bytes.set_uint8 cs 0 1;
        Bytes.set_int64_be cs 1 n;
        Bytes.unsafe_to_string cs

  let of_octets cs =
    match String.get_uint8 cs 0 with
    | 0 ->
        if String.length cs > 1 then Ok (User String.(sub cs 1 (length cs - 1)))
        else error_msgf "Invalid user metadata"
    | 1 -> (
        if String.length cs <> 1 + 8 then
          error_msgf "Invalid timestamp: invalid length"
        else
          try
            let n = String.get_int64_be cs 1 in
            let n = Int64.to_float n in
            match Ptime.of_float_s n with
            | Some ptime -> Ok (Timestamp ptime)
            | None -> error_msgf "Invalid timestamp"
          with _ -> error_msgf "Invalid timestamp metadata")
    | _ -> error_msgf "Invalid metadata"
    | exception _ -> error_msgf "Invalid metadata"

  let[@coverage off] pp_hum ppf = function
    | User str -> Fmt.pf ppf "User:       %S\n%!" str
    | Timestamp ptime ->
        Fmt.pf ppf "Timestamp:  %a\n%!" (Ptime.pp_rfc3339 ()) ptime
end

module V2_server : sig
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
    Key.of_octets key

  let generate ?g () = Key.generate ?g ()

  let save server_key =
    let b64 = Key.to_base64 server_key in
    let lines =
      "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
      :: String.split_at 64 b64
      @ [ "-----END OpenVPN tls-crypt-v2 server key-----"; "" ]
    in
    List.to_seq lines

  let[@coverage off] pp = Fmt.(using Key.to_base64 string)
  let equal = Key.equal
end

module Tls_crypt : sig
  type t

  val server_key : t -> Key.t
  val client_key : t -> Key.t
  val of_octets : string -> (t, [> `Msg of string ]) result
  val load_v1 : string Seq.t -> (t, [> `Msg of string ]) result
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val save_v1 : t -> string Seq.t
  val equal : t -> t -> bool
end = struct
  type t = Key.t * Key.t

  let of_octets buf =
    let open Result.Syntax in
    let* () =
      guard ~msg:"Invalid tls-crypt key" @@ fun () -> String.length buf = 256
    in
    let* server_key = Key.of_octets (String.sub buf 0 128) in
    let* client_key = Key.of_octets (String.sub buf 128 128) in
    Ok (server_key, client_key)

  let server_key (k, _) = k
  let client_key (_, k) = k

  let load_v1 lines =
    let ( let* ) = Result.bind in
    let* str = hex_of_lines ~name:"OpenVPN Static key V1" lines in
    let* () =
      guard ~msg:"Truncated OpenVPN Static key V1" @@ fun () ->
      String.length str >= 256
    in
    let* a = Key.of_octets (String.sub str 0 128) in
    let* b = Key.of_octets (String.sub str 128 128) in
    Ok (a, b)

  let generate ?g () =
    let a = Key.generate ?g () in
    let b = Key.generate ?g () in
    (a, b)

  let save_v1 (a, b) =
    let k = Key.to_octets a ^ Key.to_octets b in
    let h = Ohex.encode k in
    let lines = List.init (256 / 16) (fun i -> String.sub h (i * 32) 32) in
    let lines =
      ("-----BEGIN OpenVPN Static key V1-----" :: lines)
      @ [ "-----END OpenVPN Static key V1-----"; "" ]
    in
    List.to_seq lines

  let equal (a, b) (a', b') = Key.equal a a' && Key.equal b b'
end

module Wrapped_key : sig
  type t

  val of_octets : string -> (string * t, [> `Msg of string ]) result
  val wrap : key:V2_server.t -> Tls_crypt.t -> Metadata.t -> t

  val unwrap :
    key:V2_server.t ->
    t ->
    (Tls_crypt.t * Metadata.t, [> `Msg of string ]) result

  val to_octets : t -> string
  val equal : t -> t -> bool
end = struct
  type t = string

  let to_octets t = t
  let equal = Eqaf.equal

  let of_octets buf =
    let open Result.Syntax in
    let* () =
      guard ~msg:"Can not read wKc length" @@ fun () -> String.length buf >= 2
    in
    let net_len = String.get_uint16_be buf (String.length buf - 2) in
    let* () =
      guard ~msg:"Can not locate wKc" @@ fun () -> String.length buf >= net_len
    in
    let* () =
      guard ~msg:"wKc too small" @@ fun () ->
      net_len >= _TLS_CRYPT_V2_MIN_WKC_LEN
    in
    let+ () =
      guard ~msg:"wKc too big" @@ fun () -> net_len <= _TLS_CRYPT_V2_MAX_WKC_LEN
    in
    let cut = String.length buf - net_len in
    (String.sub buf 0 cut, String.sub buf cut (String.length buf - cut))

  let wrap ~key:server_key key metadata =
    let a = Key.to_octets (Tls_crypt.server_key key) in
    let b = Key.to_octets (Tls_crypt.client_key key) in
    let metadata = Metadata.to_octets metadata in
    let net_len =
      _TLS_CRYPT_V2_TAG_SIZE
      + List.fold_left ( + ) 0 (List.map String.length [ a; b; metadata ])
      + 2
    in
    let net_len =
      let cs = Bytes.create 2 in
      Bytes.set_uint16_be cs 0 net_len;
      Bytes.unsafe_to_string cs
    in
    let tag =
      let key = Key.hmac server_key in
      Digestif.SHA256.(
        to_raw_string (hmacv_string ~key [ net_len; a; b; metadata ]))
    in
    let module AES_CTR = Mirage_crypto.AES.CTR in
    let ctr = AES_CTR.ctr_of_octets tag in
    let encrypted =
      AES_CTR.encrypt
        ~key:(Key.cipher_key server_key)
        ~ctr
        (String.concat "" [ a; b; metadata ])
    in
    String.concat "" [ tag; encrypted; net_len ]

  let unwrap ~key:server_key wkc =
    let open Result.Syntax in
    let tag = String.sub wkc 0 _TLS_CRYPT_V2_TAG_SIZE in
    let module AES_CTR = Mirage_crypto.AES.CTR in
    let ctr = AES_CTR.ctr_of_octets tag in
    let* key_and_metadata =
      try
        let payload =
          String.sub wkc _TLS_CRYPT_V2_TAG_SIZE
            (String.length wkc - _TLS_CRYPT_V2_TAG_SIZE - 2)
        in
        Ok (AES_CTR.decrypt ~key:(Key.cipher_key server_key) ~ctr payload)
      with _ -> error_msgf "Could not decrypt client key"
    in
    let tag' =
      let key = Key.hmac server_key in
      Digestif.SHA256.(
        to_raw_string
          (hmacv_string ~key
             [ String.sub wkc (String.length wkc - 2) 2; key_and_metadata ]))
    in
    let* () =
      guard ~msg:"Client key authentication error" @@ fun () ->
      Eqaf.equal tag tag'
    in
    let* () =
      guard ~msg:"Failed to read the client key" @@ fun () ->
      String.length key_and_metadata >= 128 * 2
    in
    let* key = Tls_crypt.of_octets (String.sub key_and_metadata 0 256) in
    let metadata =
      String.sub key_and_metadata (128 * 2)
        (String.length key_and_metadata - (128 * 2))
    in
    let* metadata = Metadata.of_octets metadata in
    Ok (key, metadata)
end

let load_tls_crypt_v2_client lines =
  let open Result.Syntax in
  let* str = pem_of_lines ~name:"OpenVPN tls-crypt-v2 client key" lines in
  let* key, wkc = Wrapped_key.of_octets str in
  let+ key = Tls_crypt.of_octets key in
  (key, wkc)

let save_tls_crypt_v2_client key wkc =
  let a = Key.to_octets (Tls_crypt.server_key key) in
  let b = Key.to_octets (Tls_crypt.client_key key) in
  let wkc = Wrapped_key.to_octets wkc in
  let payload = String.concat "" [ a; b; wkc ] in
  let b64 = Base64.encode_string ~pad:true payload in
  let lines = String.split_at 64 b64 in
  let lines =
    ("-----BEGIN OpenVPN tls-crypt-v2 client key-----" :: lines)
    @ [ "-----END OpenVPN tls-crypt-v2 client key-----"; "" ]
  in
  List.to_seq lines

include Tls_crypt
