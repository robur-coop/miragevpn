type t

val client : Openvpn_config.t -> Ptime.t -> int64 -> (int -> Cstruct.t) -> unit ->
  (t * ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list * Cstruct.t,
   Rresult.R.msg) result

type error

val pp_error : error Fmt.t

val incoming : t -> Ptime.t -> int64 -> Cstruct.t -> (t * Cstruct.t list * Cstruct.t list, error) result

val outgoing : t -> int64 -> Cstruct.t -> (t * Cstruct.t list, [ `Not_ready ]) result

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

val timer : t -> int64 -> t * Cstruct.t list

val ready : t -> ip_config option
