(** OpenVPN configuration parsing module *)

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

  | Tls_version_min : ([`v1_3 | `v1_2 | `v1_1 ] * bool) k
  (** [v * or_highest]: if [or_highest] then v = the highest version supported
      by the TLS library.*)

  | Tun_mtu : int k
  | Verb : int k
module K : Gmap.KEY with type 'a t = 'a k
include module type of Gmap.Make(K)

val pp : Format.formatter -> t -> unit
(** [pp ppf t] is [t] printed in a near approximation of the openvpn
    configuration-format onto the [ppf] formatter.

    It should be mostly possible to re-use such a dump as a configuration file
    with*)

val eq : eq
(** [eq] is an implementation of [cmp] for use with [{!equal} cmp t t2]*)

val is_valid_client_config : t -> (unit, string) result

val parse : string_of_file:(string -> (string,string) result) ->
  string -> (t, string) result
(** Parses a configuration string, looking up references to external files
    as needed.*)
