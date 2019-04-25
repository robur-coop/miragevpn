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
  | Dhcp_disable_nbt: flag k
  | Dhcp_dns: Ipaddr.t list k
  | Dhcp_ntp: Ipaddr.t list k
  | Dhcp_domain: Domain_name.t k
  | Float    : flag k

  | Ifconfig : (Ipaddr.t * Ipaddr.t) k
  (**  TODO --ifconfig parameters which are IP addresses can also be  speci‐
              fied as a DNS or /etc/hosts file resolvable name.*)

  | Ifconfig_nowarn : flag k
  | Keepalive: (int * int) k
  | Mssfix   : int k
  | Mute_replay_warnings : flag k
  | Passtos  : flag k
  | Persist_key : flag k
  | Ping      : int k
  | Ping_exit : int k
  | Ping_restart : int k
  | Pull     : flag k
  | Proto    : [`Tcp | `Udp] k (** TODO should Proto be bound to a remote? *)
  | Remote : ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list k
  | Remote_cert_tls : [`Server | `Client] k
  | Remote_random : flag k
  | Replay_window : (int * int) k
  | Resolv_retry  : [`Infinite | `Seconds of int] k
  | Route : ([`ip of Ipaddr.t | `net_gateway | `remote_host | `vpn_gateway]
             * Ipaddr.t option
             * [`ip of Ipaddr.t | `net_gateway | `remote_host
               | `vpn_gateway] option
             * int option) k
  | Route_gateway : Ipaddr.t option k (** [None] -> default to DHCP *)
  | Tls_auth : (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
  | Tls_client    : flag k

  | Tls_version_min : ([`v1_3 | `v1_2 | `v1_1 ] * bool) k
  (** [v * or_highest]: if [or_highest] then v = the highest version supported
      by the TLS library.*)

  | Topology : [`net30 | `p2p | `subnet] k
  | Tun_mtu : int k
  | Verb : int k

include Gmap.S with type 'a key = 'a k

val pp : Format.formatter -> t -> unit
(** [pp ppf t] is [t] printed in a near approximation of the openvpn
    configuration-format onto the [ppf] formatter.

    It should be mostly possible to re-use such a dump as a configuration file
    with*)

val eq : eq
(** [eq] is an implementation of [cmp] for use with [{!equal} cmp t t2]*)

val is_valid_client_config : t -> (unit,  [> Rresult.R.msg]) result

val parse : string_of_file:(string -> (string, Rresult.R.msg) result) ->
  string -> (t, [> Rresult.R.msg]) result
(** Parses a configuration string, looking up references to external files
    as needed.*)
