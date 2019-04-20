
type line
val pp_line : line Fmt.t

type 'a inline_or_path = [ `Need_inline of 'a
                         | `Path of (string * 'a) ]

module Conf_map : sig
  type flag = unit
  type 'a k =
    | Auth_retry : [`Nointeract] k
    | Auth_user_pass : (string * string) k (** username, password*)
    | Bind     : bool k
    | Ca       : X509.t k
    | Cipher   : string k
    | Comp_lzo : flag k
    | Connect_retry : (int * int) k
    | Dev      : [`Null | `Tun of int | `Tap of int] k
    | Float    : flag k
    | Ifconfig_nowarn : flag k
    | Keepalive: (int * int) k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Persist_key : flag k
    | Pull     : flag k
    | Proto    : [`Tcp | `Udp] k (** TODO should Proto be bound to a remote? *)
    | Remote : ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list k
    | Remote_cert_tls : [`Server | `Client] k
    | Remote_random : flag k
    | Replay_window : (int * int) k
    | Resolv_retry  : [`Infinite | `Seconds of int] k
    | Tls_auth : (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tls_client    : flag k
    | Tls_min : [`v1_3 | `v1_2 | `v1_1 ] k
    | Tun_mtu : int k
    | Verb : int k
  module K : Gmap.KEY with type 'a t = 'a k
  include module type of Gmap.Make(K)

  val is_valid_client_config : t -> (unit, string) result
end

type parser_partial_state
type parser_state = [`Done of Conf_map.t
                    | `Partial of parser_partial_state
                    | `Need_file of (string * parser_partial_state) ]
type parser_effect = [`File of string * string] option

val parse_easy : string_of_file:(string -> (string,string) result) ->
  string -> (Conf_map.t, string) result
(** looks up references to external files also*)
