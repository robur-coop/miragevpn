type t

val client : Openvpn_config.t -> Ptime.t -> (int -> Cstruct.t) -> unit ->
  (t * Cstruct.t, Rresult.R.msg) result

type error

val pp_error : error Fmt.t

val incoming : t -> Ptime.t -> Cstruct.t -> (t * Cstruct.t list * Cstruct.t list, error) result

val outgoing : t -> Cstruct.t -> (t * Cstruct.t list, [ `Not_ready ]) result

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

val ready : t -> ip_config option
