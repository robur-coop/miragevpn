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
end

module Metadata : sig
  type t

  val timestamp : Ptime.t -> t
  val user : string -> t
  val to_cstruct : t -> Cstruct.t
  val of_cstruct : Cstruct.t -> (t, [> `Msg of string ]) result
  val pp_hum : t Fmt.t
end

module Server : sig
  type t

  val load : lines:string Seq.t -> (t, [> `Msg of string ]) result
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val save : t -> string Seq.t
  val pp : t Fmt.t
  val equal : t -> t -> bool
end

module Tls_crypt : sig
  type t

  val server_key : t -> Key.t
  val client_key : t -> Key.t
  val load_v1 : string Seq.t -> (t, [> `Msg of string ]) result
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val save_v1 : t -> string Seq.t
  val equal : t -> t -> bool
end

module Wrapped_key : sig
  type t

  val of_cstruct : Cstruct.t -> (Cstruct.t * t, [> `Msg of string ]) result
  val wrap : key:Server.t -> Tls_crypt.t -> Metadata.t -> t

  val unwrap :
    key:Server.t -> t -> (Tls_crypt.t * Metadata.t, [> `Msg of string ]) result

  val unsafe_to_cstruct : t -> Cstruct.t
end

val load_tls_crypt_v2_client :
  string Seq.t -> (Tls_crypt.t * Wrapped_key.t, [> `Msg of string ]) result

val save_tls_crypt_v2_client : Tls_crypt.t -> Wrapped_key.t -> string Seq.t
