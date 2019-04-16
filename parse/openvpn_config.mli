
type line
val pp_line : line Fmt.t

val parse : string -> (line list, string) result
type inline_or_path = [ `Inline | `Path of string ]

module Conf_map : sig
  type flag = unit
  type 'a k =
    | Auth_retry : [`Nointeract] k
    | Auth_user_pass : inline_or_path k
    | Bind     : bool k
    | Ca       : X509.t k
    | Cipher   : string k
    | Comp_lzo : flag k
    | Float    : flag k
    | Keepalive: (int * int) k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Pull     : flag k
    | Remote : ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list k
    | Remote_random : flag k
    | Replay_window : (int * int) k
    | Tls_client    : flag k
    | Tls_auth_payload : (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tun_mtu : int k
    | Verb : int k
  module K : Gmap.KEY with type 'a t = 'a k
  include module type of Gmap.Make(K)
end

val parse_gadt : line list -> (Conf_map.t, string) result

val is_valid_client_config : Conf_map.t -> bool
