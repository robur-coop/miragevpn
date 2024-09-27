module Key : sig
  type t

  val of_octets : string -> (t, [> `Msg of string ]) result
  val to_octets : t -> string
  val cipher_key : t -> Mirage_crypto.AES.CTR.key
  val hmac : t -> string
  val equal : t -> t -> bool
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val to_base64 : t -> string
end

type t

module Metadata : sig
  type t

  val timestamp : Ptime.t -> t
  val user : string -> t
  val to_octets : t -> string
  val of_octets : string -> (t, [> `Msg of string ]) result
  val pp_hum : t Fmt.t
end

module V2_server : sig
  type t

  val load : lines:string Seq.t -> (t, [> `Msg of string ]) result
  val generate : ?g:Mirage_crypto_rng.g -> unit -> t
  val save : t -> string Seq.t
  val pp : t Fmt.t
  val equal : t -> t -> bool
end

module Wrapped_key : sig
  type tls_crypt := t
  type t

  val of_octets : string -> (string * t, [> `Msg of string ]) result
  val wrap : key:V2_server.t -> tls_crypt -> Metadata.t -> t

  val unwrap :
    key:V2_server.t -> t -> (tls_crypt * Metadata.t, [> `Msg of string ]) result

  val to_octets : t -> string
  val equal : t -> t -> bool
end

val load_tls_crypt_v2_client :
  string Seq.t -> (t * Wrapped_key.t, [> `Msg of string ]) result

val save_tls_crypt_v2_client : t -> Wrapped_key.t -> string Seq.t
val server_key : t -> Key.t
val client_key : t -> Key.t
val load_v1 : string Seq.t -> (t, [> `Msg of string ]) result
val generate : ?g:Mirage_crypto_rng.g -> unit -> t
val save_v1 : t -> string Seq.t
val equal : t -> t -> bool
