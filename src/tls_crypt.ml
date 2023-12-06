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

let _TLS_CRYPT_V2_MAX_METADATA_LEN =
  _TLS_CRYPT_V2_MAX_WKC_LEN
  - (_TLS_CRYPT_V2_CLIENT_KEY_LEN + _TLS_CRYPT_V2_TAG_SIZE + 2)

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

let hex_of_lines ~name seq =
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
  type version = [ `V1 | `V2 ]
  type t

  val version : t -> version

  val of_cstruct :
    ?version:version -> Cstruct.t -> (t, [> `Msg of string ]) result

  val unsafe_to_cstruct : t -> Cstruct.t
  val to_string : t -> string
  val cipher_key : t -> Mirage_crypto.Cipher_block.AES.CTR.key
  val hmac : t -> Cstruct.t
  val equal : t -> t -> bool
  val generate : ?version:version -> ?g:Mirage_crypto_rng.g -> unit -> t
  val to_base64 : t -> string
end = struct
  type version = [ `V1 | `V2 ]
  type t = version * Cstruct.t (* cipher (64 bytes) + hmac (64 bytes) *)

  let len_of_secret_aes_ctr_key =
    Array.to_list Mirage_crypto.Cipher_block.AES.CTR.key_sizes
    |> List.filter (( > ) 128) (* ∀x. 128 > x <=> ∀x. x <= 128 *)
    |> List.fold_left max 0

  (* NOTE: it's a bit paranoid but we ensure that [mirage-crypto] exposes values
     which fit with an OpenVPN key (128 bytes). *)
  let () = assert (len_of_secret_aes_ctr_key > 0)
  let version = fst

  let of_cstruct ?(version = `V2) cs =
    if Cstruct.length cs <> 128 then error_msgf "Invalid tls-crypt key"
    else Ok (version, cs)

  let unsafe_to_cstruct (_, x) = x
  let to_string (_, t) = Cstruct.to_string t

  let cipher_key (_, cs) =
    Mirage_crypto.Cipher_block.AES.CTR.of_secret
      (Cstruct.sub cs 0 len_of_secret_aes_ctr_key)

  let hmac (_, cs) = Cstruct.sub cs 64 Mirage_crypto.Hash.SHA256.digest_size

  let equal (va, a) (vb, b) =
    match (va, vb) with
    | `V1, `V1 | `V2, `V2 -> Eqaf_cstruct.equal a b
    | _ -> false

  let generate ?(version = `V2) ?g () =
    (version, Mirage_crypto_rng.generate ?g 128)

  let to_base64 (_, cs) =
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

  val load :
    Key.version -> lines:string Seq.t -> (t, [> `Msg of string ]) result

  val generate : ?version:Key.version -> ?g:Mirage_crypto_rng.g -> unit -> t
  val save : t -> string Seq.t
end = struct
  type t = Key.t

  let load version ~lines =
    match version with
    | `V2 ->
        let ( let* ) = Result.bind in
        let* key = pem_of_lines ~name:"OpenVPN tls-crypt-v2 server key" lines in
        Key.of_cstruct (Cstruct.of_string key)
    | `V1 -> assert false

  let generate ?version ?g () = Key.generate ?version ?g ()

  let save server_key =
    match Key.version server_key with
    | `V2 ->
        let b64 = Key.to_base64 server_key in
        let lines =
          "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
          :: String.split_at 64 b64
          @ [ "-----END OpenVPN tls-crypt-v2 server key-----"; "" ]
        in
        List.to_seq lines
    | `V1 -> assert false
end

module Client : sig
  type t

  val server_key : t -> Key.t
  val client_key : t -> Key.t
  val wkc : t -> Cstruct.t option

  val load :
    ?version:Key.version ->
    ?key:Server.t ->
    string Seq.t ->
    (t, [> `Msg of string ]) result

  val generate :
    ?version:Key.version ->
    ?g:Mirage_crypto_rng.g ->
    ?metadata:Server.t * Metadata.t option ->
    (unit -> Ptime.t) ->
    t

  val save : t -> string Seq.t
  val equal : t -> t -> bool
end = struct
  type extra =
    | Unencrypted of { wkc : Cstruct.t; metadata : Metadata.t }
    | Encrypted of Cstruct.t
    | None

  type t = Key.t * Key.t * extra
  (* let (s, c, m) = key in
     assert (Key.version s = Key.version c) (* same version *)
     if fst s = `V2 then assert (m <> None) (* for v2, metadata is available *) *)

  let server_key (k, _, _) = k
  let client_key (_, k, _) = k

  let wkc (_, _, v) =
    match v with
    | Unencrypted { wkc; _ } -> Some wkc
    | Encrypted wkc -> Some wkc
    | None -> Option.none

  let unwrap ~key:server_key cs =
    if Key.version server_key = `V1 then
      invalid_arg "Invalid server key version";
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

  let load_v2 ?key:server_key lines =
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
      Cstruct.length cs = net_len
    in
    let wkc = Cstruct.sub cs (Cstruct.length cs - net_len) net_len in
    let* () =
      guard ~msg:"Can not locate tls-crypt-v2 client key" @@ fun () ->
      Cstruct.length cs - net_len >= 128 * 2
    in
    let kc = Cstruct.sub cs 0 (Cstruct.length cs - net_len) in
    let* a = Key.of_cstruct ~version:`V2 (Cstruct.sub kc 0 128) in
    let* b = Key.of_cstruct ~version:`V2 (Cstruct.sub kc 128 128) in
    match server_key with
    | Some server_key ->
        let* a', b', metadata = unwrap ~key:server_key wkc in
        let* () =
          guard ~msg:"Client keys don't correspond" @@ fun () -> Key.equal a a'
        in
        let* () =
          guard ~msg:"Client keys don't correspond" @@ fun () -> Key.equal b b'
        in
        Ok (a, b, Unencrypted { wkc; metadata })
    | None -> Ok (a, b, Encrypted wkc)

  let load_v1 lines =
    let ( let* ) = Result.bind in
    let* str = hex_of_lines ~name:"OpenVPN Static key V1" lines in
    let cs = Cstruct.of_string str in
    let* () =
      guard ~msg:"Truncated OpenVPN Static key V1" @@ fun () ->
      Cstruct.length cs >= 256
    in
    let* a = Key.of_cstruct ~version:`V1 (Cstruct.sub cs 0 128) in
    let* b = Key.of_cstruct ~version:`V1 (Cstruct.sub cs 128 128) in
    Ok (a, b, None)

  let wrap ~key:server_key (a, b, metadata) =
    if Key.version server_key = `V1 then
      invalid_arg "Invalid server key version";
    let a = Key.unsafe_to_cstruct a in
    let b = Key.unsafe_to_cstruct b in
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

  let generate ?(version = `V2) ?g ?metadata now =
    let a = Key.generate ~version ?g () in
    let b = Key.generate ~version ?g () in
    let metadata =
      match (metadata, version) with
      | Some (key, Option.None), `V2 ->
          let metadata = Metadata.timestamp (now ()) in
          let wkc = wrap ~key (a, b, metadata) in
          Unencrypted { wkc; metadata }
      | Some (key, Some metadata), `V2 ->
          let wkc = wrap ~key (a, b, metadata) in
          Unencrypted { wkc; metadata }
      | None, `V2 ->
          invalid_arg
            "tls-crypt-v2 client key generation requires the server key"
      | _, `V1 -> None
    in
    (a, b, metadata)

  let save_v2 (a, b, extra) =
    let kc =
      Cstruct.concat [ Key.unsafe_to_cstruct a; Key.unsafe_to_cstruct b ]
    in
    let wkc =
      match extra with
      | Unencrypted { wkc; _ } -> wkc
      | Encrypted wkc -> wkc
      | None -> assert false
    in
    let payload = Cstruct.concat [ kc; wkc ] in
    let payload = Cstruct.to_string payload in
    let b64 = Base64.encode_string ~pad:true payload in
    let lines = String.split_at 64 b64 in
    let lines =
      ("-----BEGIN OpenVPN tls-crypt-v2 client key-----" :: lines)
      @ [ "-----END OpenVPN tls-crypt-v2 client key-----"; "" ]
    in
    List.to_seq lines

  let save_v1 (a, b, _) =
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

  let load ?(version = `V2) ?key lines =
    match (Option.map Key.version key, version) with
    | Some `V2, `V2 | None, `V2 -> load_v2 ?key lines
    | Some `V1, `V1 | None, `V1 -> load_v1 lines
    | Some `V1, `V2 | Some `V2, `V1 -> error_msgf "Incompatible key version"

  let save ((a, b, _) as client_key) =
    match (Key.version a, Key.version b) with
    | `V2, `V2 -> save_v2 client_key
    | `V1, `V1 -> save_v1 client_key
    | _ -> assert false

  let equal (a, b, extra) (a', b', extra') =
    Key.equal a a' && Key.equal b b'
    &&
    match (extra, extra') with
    | ( (Unencrypted { wkc; _ } | Encrypted wkc),
        (Unencrypted { wkc = wkc'; _ } | Encrypted wkc') ) ->
        Cstruct.equal wkc wkc'
    | None, None -> true
    | _ -> false
end
