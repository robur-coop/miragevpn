type t

val client : Openvpn_config.t -> Ptime.t -> (int -> Cstruct.t) -> unit ->
  (t * Cstruct.t, Rresult.R.msg) result

type error

val pp_error : error Fmt.t

val incoming : t -> Ptime.t -> Cstruct.t -> (t * Cstruct.t list, error) result

val outgoing : t -> Ptime.t -> Cstruct.t -> (t * Cstruct.t list, [ `Not_ready ]) result
