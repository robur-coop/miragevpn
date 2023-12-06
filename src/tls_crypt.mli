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

  val load :
    Key.version -> lines:string Seq.t -> (t, [> `Msg of string ]) result

  val generate : ?version:Key.version -> ?g:Mirage_crypto_rng.g -> unit -> t
  val save : t -> string Seq.t
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
end
