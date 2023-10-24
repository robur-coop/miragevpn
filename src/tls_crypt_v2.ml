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

let pem_of_lines ~name seq =
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

module Key : sig
  type t

  val of_cstruct : Cstruct.t -> (t, [> `Msg of string ]) result
  val to_cstruct : t -> Cstruct.t
  val to_string : t -> string
  val cipher_key : t -> Mirage_crypto.Cipher_block.AES.CTR.key
  val hmac : t -> Cstruct.t
  val equal : t -> t -> bool
  val pp_hum : t Fmt.t
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val to_base64 : t -> string
end = struct
  type t = Cstruct.t (* cipher (64 bytes) + hmac (64 bytes) *)

  let of_cstruct cs =
    if Cstruct.length cs <> 128 then error_msgf "Invalid tls-crypt-v2 key"
    else
      let len =
        Array.fold_left max 0 Mirage_crypto.Cipher_block.AES.CTR.key_sizes
      in
      try
        let secret = Cstruct.sub cs 0 len in
        let _ = Mirage_crypto.Cipher_block.AES.CTR.of_secret secret in
        Ok cs
      with exn ->
        error_msgf "Invalid AES-CTR secret key: %S" (Printexc.to_string exn)

  let to_cstruct x = x
  let to_string t = Cstruct.to_string t

  let cipher_key cs =
    let len =
      Array.fold_left max 0 Mirage_crypto.Cipher_block.AES.CTR.key_sizes
    in
    Mirage_crypto.Cipher_block.AES.CTR.of_secret (Cstruct.sub cs 0 len)

  let hmac cs = Cstruct.sub cs 64 Mirage_crypto.Hash.SHA256.digest_size
  let equal a b = Eqaf_cstruct.equal a b
  let generate ?g () = Mirage_crypto_rng.generate ?g 128

  let pp_hum ppf cs =
    let cipher_key = Cstruct.(to_string (sub cs 0 64)) in
    let hmac = Cstruct.(to_string (sub cs 64 64)) in
    Fmt.pf ppf "Cipher Key: @[<hov>%a@]\n%!"
      (Hxd_string.pp Hxd.default)
      cipher_key;
    Fmt.pf ppf "HMAC Key:   @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) hmac

  let to_base64 cs =
    let str = Cstruct.to_string cs in
    Base64.encode_string ~pad:true str
end

module Metadata = struct
  type t = User of string | Timestamp of Ptime.t

  let timestamp now = Timestamp now
  let user str = User str

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

module rec Server : sig
  type t

  val load : lines:string Seq.t -> (t, [> `Msg of string ]) result
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val save : key:t -> string Seq.t
end = struct
  type t = Key.t

  let load ~lines =
    let ( let* ) = Result.bind in
    let* key = pem_of_lines ~name:"OpenVPN tls-crypt-v2 server key" lines in
    Key.of_cstruct (Cstruct.of_string key)

  let generate ?g () = Key.generate ?g ()

  let save ~key:server_key =
    let b64 = Key.to_base64 server_key in
    let lines =
      "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
      :: String.split_at 65 b64
      @ [ "-----END OpenVPN tls-crypt-v2 server key-----"; "" ]
    in
    List.to_seq lines
end

and Client : sig
  type t

  val unwrap : key:Server.t -> Cstruct.t -> (t, [> `Msg of string ]) result
  val wrap : key:Server.t -> t -> Cstruct.t

  val load :
    key:Server.t -> lines:string Seq.t -> (t, [> `Msg of string ]) result

  val generate :
    ?g:Mirage_crypto_rng.g -> now:(unit -> Ptime.t) -> Metadata.t option -> t

  val save : key:Server.t -> Client.t -> string Seq.t
end = struct
  type t = Key.t * Key.t * Metadata.t

  let unwrap ~key:server_key cs =
    let ( let* ) = Result.bind in
    let* () =
      guard ~msg:"Failed to read length" @@ fun () -> Cstruct.length cs >= 2
    in
    let net_len = Cstruct.BE.get_uint16 cs (Cstruct.length cs - 2) in
    let* () =
      guard ~msg:"Invalid length" @@ fun () -> net_len = Cstruct.length cs
    in
    let* () =
      guard ~msg:"Failed to read tag" @@ fun () ->
      Cstruct.length cs >= _TLS_CRYPT_V2_TAG_SIZE
    in
    let tag = Cstruct.sub cs 0 _TLS_CRYPT_V2_TAG_SIZE in
    let module AES_CTR = Mirage_crypto.Cipher_block.AES.CTR in
    let ctr = AES_CTR.ctr_of_cstruct tag in
    let* key_and_metadata =
      try
        let payload =
          Cstruct.sub cs _TLS_CRYPT_V2_TAG_SIZE
            (net_len - _TLS_CRYPT_V2_TAG_SIZE - 2)
        in
        Ok (AES_CTR.decrypt ~key:(Key.cipher_key server_key) ~ctr payload)
      with _ -> error_msgf "Could not decrypt client key"
    in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_empty ~key:(Key.hmac server_key) in
    let ctx =
      Mirage_crypto.Hash.SHA256.hmac_feed ctx
        (Cstruct.sub cs (Cstruct.length cs - 2) 2)
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
    let* a = Key.of_cstruct (Cstruct.sub key_and_metadata 0 128) in
    let* b = Key.of_cstruct (Cstruct.sub key_and_metadata 128 128) in
    let metadata =
      Cstruct.sub key_and_metadata (128 * 2)
        (Cstruct.length key_and_metadata - (128 * 2))
    in
    let* metadata = Metadata.of_cstruct metadata in
    Ok (a, b, metadata)

  let load ~key:server_key ~lines =
    let ( let* ) = Result.bind in
    let* str = pem_of_lines ~name:"OpenVPN tls-crypt-v2 client key" lines in
    let cs = Cstruct.of_string str in
    let* () =
      guard ~msg:"Can not read tls-crypt-v2 client key length" @@ fun () ->
      Cstruct.length cs >= 2
    in
    let net_len = Cstruct.BE.get_uint16 cs (Cstruct.length cs - 2) in
    let* () =
      guard ~msg:"Can not locate tls-crypt-v2 wrapped client key" @@ fun () ->
      Cstruct.length cs >= net_len
    in
    let wkc = Cstruct.sub cs (Cstruct.length cs - net_len) net_len in
    let* () =
      guard ~msg:"Can not locate tls-crypt-v2 client key" @@ fun () ->
      Cstruct.length cs - net_len >= 128 * 2
    in
    let kc = Cstruct.sub cs 0 (Cstruct.length cs - net_len) in
    let* a = Key.of_cstruct (Cstruct.sub kc 0 128) in
    let* b = Key.of_cstruct (Cstruct.sub kc 128 128) in
    let* a', b', metadata = unwrap ~key:server_key wkc in
    let* () =
      guard ~msg:"Client keys don't correspond" @@ fun () -> Key.equal a a'
    in
    let* () =
      guard ~msg:"Client keys don't correspond" @@ fun () -> Key.equal b b'
    in
    Ok (a, b, metadata)

  let generate ?g ~now metadata =
    let metadata =
      match metadata with
      | None -> Metadata.timestamp (now ())
      | Some metadata -> metadata
    in
    let a = Key.generate ?g () in
    let b = Key.generate ?g () in
    (a, b, metadata)

  let wrap ~key:server_key (a, b, metadata) =
    let a = Key.to_cstruct a in
    let b = Key.to_cstruct b in
    let cs = Cstruct.concat [ a; b ] in
    let metadata = Metadata.to_cstruct metadata in
    let net_len =
      Cstruct.length cs + Cstruct.length metadata
      + Mirage_crypto.Hash.SHA256.digest_size + 2
    in
    let net_len =
      let cs = Cstruct.create 2 in
      Cstruct.BE.set_uint16 cs 0 net_len;
      cs
    in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_empty ~key:(Key.hmac server_key) in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_feed ctx net_len in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_feed ctx cs in
    let ctx = Mirage_crypto.Hash.SHA256.hmac_feed ctx metadata in
    let tag = Mirage_crypto.Hash.SHA256.hmac_get ctx in
    let module AES_CTR = Mirage_crypto.Cipher_block.AES.CTR in
    let ctr = AES_CTR.ctr_of_cstruct tag in
    let wkc =
      AES_CTR.encrypt
        ~key:(Key.cipher_key server_key)
        ~ctr
        (Cstruct.concat [ cs; metadata ])
    in
    Cstruct.concat [ tag; wkc; net_len ]

  let save ~key:server_key client_key =
    let kc =
      let a, b, _ = client_key in
      Cstruct.concat [ Key.to_cstruct a; Key.to_cstruct b ]
    in
    let wkc = wrap ~key:server_key client_key in
    let payload = Cstruct.concat [ kc; wkc ] in
    let payload = Cstruct.to_string payload in
    let b64 = Base64.encode_string ~pad:true payload in
    let lines = String.split_at 64 b64 in
    let lines =
      ("-----BEGIN OpenVPN tls-crypt-v2 client key-----" :: lines)
      @ [ "-----END OpenVPN tls-crypt-v2 client key-----"; "" ]
    in
    List.to_seq lines
end
