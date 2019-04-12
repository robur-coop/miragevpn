
type line = [
  | `Auth_retry of [ `Nointeract ]
  | `Auth_user_pass of [ `Inline | `Path of string ]
  | `Bind
  | `Blank
  | `Ca of [ `Inline | `Path of string ]
  | `Cipher of string
  | `Client
  | `Comp_lzo
  | `Connect_retry of int * int
  | `Dev of [ `Null | `Tap of int | `Tun of int ]
  | `Float
  | `Ifconfig_nowarn
  | `Inline of string * string
  | `Keepalive of int * int
  | `Mssfix of int
  | `Mute_replay_warnings
  | `Nobind
  | `Passtos
  | `Persist_key
  | `Pkcs12 of [ `Inline | `Path of string ]
  | `Proto of [ `Tcp | `Udp ]
  | `Proto_force of [ `Tcp | `Udp ]
  | `Remote of [`Domain of Domain_name.t | `IP of Ipaddr.t ] * int
  | `Remote_cert_key_usage of int
  | `Remote_cert_tls of [ `Server ]
  | `Remote_random
  | `Replay_window of int * int
  | `Resolv_retry of [ `Infinite ]
  | `Socks_proxy of string * int * [ `Inline | `Path of string ]
  | `TLS_min of [ `v1_1 | `v1_2 | `v1_3 ]
  | `Tls_auth of [ `Inline | `Path of string ]
  | `Tls_client
  | `Tun_mtu of int
  | `Verb of int
]

val pp_line : line Fmt.t

val parse : string -> (line list, string) result
type inline_or_path = [ `Inline | `Path of string ]

module Conf_map : sig
  type flag = unit
  type 'a k =
    | Auth_retry : [`Nointeract] k
    | Auth_user_pass : inline_or_path k
    | Bind     : bool k
    | Cipher   : string k
    | Client   : flag k
    | Comp_lzo : flag k
    | Float    : flag k
    | Keepalive: (int * int) k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
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
