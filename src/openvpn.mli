open Rresult


module Config : sig
  (** OpenVPN configuration parsing module *)

  type flag = unit

  type 'a k =
    | Auth_retry : [`Nointeract] k
    | Auth_user_pass : (string * string) k (** username, password*)
    | Bind     : (int option * [`Domain of [ `host ] Domain_name.t
                               | `IP of Ipaddr.t] option) option k
    (** local [port],[host] to bind to.
        Defaults to [Some (None, None)], see [--bind] in [man openvpn].

        [None] if [nobind].

        [port] is [Some p] if [lport p] was specified.
        Only numeric ports are accepted by this implementation
        ([openvpn] also allows [lport x]
        where [x] matches a port name from [/etc/services]).

        [host] is governed by [--local] and defaults to [None]
        (meaning "bind all interfaces").

        [bind ipv6only] is unimplemented.
    *)


    | Ca       : X509.t k
    | Cipher   : string k
    | Comp_lzo : flag k
    | Connect_retry : (int * int) k

    | Dev      : [`Null | `Tun of int option | `Tap of int option] k
    (** if Tap/Tun is [None], a device must be allocated dynamically. *)

    | Dhcp_disable_nbt: flag k
    | Dhcp_dns: Ipaddr.t list k
    | Dhcp_ntp: Ipaddr.t list k
    | Dhcp_domain: [ `host ] Domain_name.t k
    | Float    : flag k

    | Ifconfig : (Ipaddr.t * Ipaddr.t) k
    (**  TODO --ifconfig parameters which are IP addresses can also be  speci‐
              fied as a DNS or /etc/hosts file resolvable name.*)

    | Ifconfig_nowarn : flag k
    | Link_mtu : int k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Persist_key : flag k
    | Persist_tun : flag k
    | Ping_interval : int k
    | Ping_timeout : [`Restart of int | `Exit of int] k
    | Pull     : flag k

    | Proto    : ([`IPv6 | `IPv4] option
                  * [`Udp | `Tcp of [`Server | `Client] option]) k
    (** TODO should Proto be bound to a remote? *)

    | Remote : ([`Domain of [ `host ] Domain_name.t | `IP of Ipaddr.t] * int) list k
    | Remote_cert_tls : [`Server | `Client] k
    | Remote_random : flag k
    | Renegotiate_seconds : int k (* reneg-sec *)
    | Replay_window : (int * int) k
    | Resolv_retry  : [`Infinite | `Seconds of int] k
    | Route : ([`ip of Ipaddr.t | `net_gateway | `remote_host | `vpn_gateway]
               * Ipaddr.Prefix.t option
               * [`ip of Ipaddr.t | `net_gateway | `remote_host
                 | `vpn_gateway] option
               * [`Default | `Metric of int]) list k
    (** Route consists of: network , netmask , gateway , metric *)

    | Route_delay : (int * int) k
    (** [n,w] seconds to wait after connection establishment before adding
        routes to the routing table. *)

    | Route_gateway : [ `IP of Ipaddr.t
                      | `Default
                      | `DHCP ] k
    (** DHCP: should be executed on the encrypted VPN LAN interface *)

    | Route_metric : [`Default | `Metric of int] k
    (** Default metric for [Route _] directives *)

    | Tls_auth : ([`Incoming | `Outgoing] option
                  * Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tls_cert     : X509.t k

    | Tls_mode   : [`Client | `Server] k
    (** Governed by the [tls-client] and [tls-server] directives.
        Indirectly also by [client]. *)

    | Tls_key      : X509.private_key k
    (** TODO Tls_key : X509.private_key * [`Incoming|`Outgoing] k
        --key-direction governs this for inlined files
        see comment in {!a_key} *)

    | Tls_version_min : ([`v1_3 | `v1_2 | `v1_1 ] * bool) k
    (** [v * or_highest]: if [or_highest] then v = the highest version supported
        by the TLS library. *)

    | Topology : [`net30 | `p2p | `subnet] k
    | Tun_mtu : int k
    | Verb : int k

  include Gmap.S with type 'a key = 'a k

  val pp : Format.formatter -> t -> unit
  (** [pp ppf t] is [t] printed in a near approximation of the openvpn
      configuration-format onto the [ppf] formatter.

      It should be mostly possible to re-use such a dump as a configuration file
      with *)

  val eq : eq
  (** [eq] is an implementation of [cmp] for use with [{!equal} cmp t t2] *)

  val client_generate_connect_options : t -> (string, R.msg) result
  (** Exports the excerpts from the client configuration sent to the server
      when the client initially connects. *)

  val client_merge_server_config : t -> string -> (t, R.msg) result
  (** Apply config excerpt from server received upon initial connection.
      [client_merge_server_config client_config server_config] is a success if
      [server_config] does not conflict with [client_config].
      TODO return conflicting subset as error
      - atm: do what validate_server_options did, returning unmodified.
  *)

  val merge_push_reply : t -> string -> (t, [> R.msg]) result
  (** [merge_push_reply client_config push_config] is a successful
      merge of [client_config] and [push_config] if [push_config] does not
      conflict with [client_config].
      TODO return conflicting subset as error
  *)

  val parse_client : string_of_file:(string -> (string, R.msg) result) ->
    string -> (t, [> R.msg]) result
  (** Parses a configuration string, looking up references to external files
      as needed. Validates the client configuration. Default client options are
      applied. *)
end

type t
(** The abstract type of an OpenVPN connection. *)

val client : Config.t -> Ptime.t -> int64 -> (int -> Cstruct.t) -> unit ->
  (t * ([`Domain of [ `host ] Domain_name.t | `IP of Ipaddr.t] * int) list * Cstruct.t,
   Rresult.R.msg) result
(** [client config now ts rng ()] constructs a [t], returns the remote to
    connect to, an initial buffer to send to the remote. It returns an error
    if the configuration does not contain a tls-auth element. *)

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

val ready : t -> ip_config option
(** [ready t] is [Some ip] if the OpenVPN connection is up, [None] otherwise. *)

type error
(** The type of errors when processing incoming data. *)

val pp_error : error Fmt.t
(** [pp_error ppf e] pretty prints the error [e]. *)

val incoming : t -> Ptime.t -> int64 -> Cstruct.t ->
  (t * Cstruct.t list * Cstruct.t list, error) result
(** [incoming t now ts data] processes [data], returning a new connection state,
    a list of buffers to be sent to the peer, and a list of decrypted
    application data. *)

val outgoing : t -> int64 -> Cstruct.t -> (t * Cstruct.t list, [ `Not_ready ]) result
(** [outgoing t ts data] prepares [data] to be sent over the OpenVPN connection.
    If the connection is not ready yet, [`Not_ready] is returned instead. *)

val timer : t -> Ptime.t -> int64 -> t * Cstruct.t list
(** [timer t ts] should be called every second. It ensures that ping packets are
    sent if the connection has been idle for some time, also deals with rekeying
    when configured limits (time, bytes, packets) are reached. The returned list
    of data is to be transmitted to the peer. *)
