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
  val save : key:t -> string Seq.t
end

module Client : sig
  type t

  val unwrap : key:Server.t -> Cstruct.t -> (t, [> `Msg of string ]) result
  val wrap : key:Server.t -> t -> Cstruct.t

  val load :
    key:Server.t -> lines:string Seq.t -> (t, [> `Msg of string ]) result

  val generate :
    ?g:Mirage_crypto_rng.g -> now:(unit -> Ptime.t) -> Metadata.t option -> t

  val save : key:Server.t -> t -> string Seq.t
end
