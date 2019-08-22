open Rresult


module Config : sig
  (** OpenVPN configuration parsing module *)

  type flag = unit

  type 'a k =
    | Auth_nocache : flag k
    (* Erase user-provided credentials ([Askpass] and [Auth_user_pass]) from
       program memory after their user.
       DOES NOT affect [--http-proxy-user-pass].
    *)

    | Auth_retry : [`Interact | `Nointeract | `None] k
    (** [`Interact]: Interactively ask user for new Auth_user_pass value
                     before retrying an authentication attempt.
        [`Nointeract]: Retry an authentication attempt with same Auth_user_pass
        [`None]: Exit with fatal error if authentication fails (default)
    *)

    | Auth_user_pass : (string * string) k (** username, password*)
    | Bind     : (int option * [`Domain of [ `host ] Domain_name.t
                               | `Ip of Ipaddr.t] option) option k
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


    | Ca       : X509.Certificate.t k
    | Cipher   : string k
    | Comp_lzo : flag k
    | Connect_retry : (int * int) k

    | Connect_retry_max : [`Unlimited | `Times of int] k
    (** How many times to retry each remote before giving up.
        The counter for each remote/connection should be reset upon the
        successful establishment of a  connection.*)

    | Connect_timeout : int k
    (** [connect-timeout] a.k.a. [server-poll-timeout]
        Timeout a connection attempt to a remote server after [SECONDS].
    *)

    | Dev      : [`Null | `Tun of int option | `Tap of int option] k
    (** if Tap/Tun is [None], a device must be allocated dynamically. *)

    | Dhcp_disable_nbt: flag k
    | Dhcp_dns: Ipaddr.t list k
    | Dhcp_ntp: Ipaddr.t list k
    | Dhcp_domain: [ `host ] Domain_name.t k
    | Float    : flag k

    | Handshake_window : int k
    (** TLS-based key exchange must finalize within [n] seconds of handshake
        initiation by any peer. If it fails to do so, we attempt to reset
        our connection with the peer and try again.
        Even in the event of handshake failure we will still use our
        expiring key for up to --tran-window seconds to maintain continuity
        of transmission of tunnel data.
        TODO pasted from `man openvpn`
    *)

    | Ifconfig : (Ipaddr.t * Ipaddr.t) k
    (**  TODO --ifconfig parameters which are IP addresses can also be  speci‐
              fied as a DNS or /etc/hosts file resolvable name.*)

    | Ifconfig_nowarn : flag k

    | Link_mtu : int k
    (** MTU of the network interface used to receive/transmit encrypted packets,
        e.g. the network interface that connects OpenVPN client and server. *)

    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Persist_key : flag k
    | Persist_tun : flag k

    | Ping_interval : [`Not_configured | `Seconds of int] k
    (** The [ping] config directive.
        Will send a OpenVPN ping packet (ie {b not} IP/ICMP) over the
        control channel after [seconds] of inactivity on the
        control/data channel to tell the peer that we are still alive.
        Defaults to [`Not_configured] (equivalent to `ping 0`),
        which means no pings will be sent.
        TODO ?The peer will be notified of the value of this configuration
        upon connection, and thus will know whether or not to expect pings
        from us?
    *)

    | Ping_timeout : [`Restart of int | `Exit of int] k
    | Pull     : flag k

    | Proto    : ([`Ipv6 | `Ipv4] option
                  * [`Udp | `Tcp of [`Server | `Client] option]) k
    (** TODO should Proto be bound to a remote? *)

    | Remote : ([ `Domain of [ `host ] Domain_name.t * [`Ipv4 | `Ipv6 | `Any]
                | `Ip of Ipaddr.t] * int * [`Udp | `Tcp]) list k
    | Remote_cert_tls : [`Server | `Client] k
    | Remote_random : flag k

    | Renegotiate_bytes : int k
    (** reneg-bytes *)

    | Renegotiate_packets : int k
    (** reneg-pkts *)

    | Renegotiate_seconds : int k
    (** reneg-sec *)

    | Replay_window : (int * int) k
    | Resolv_retry  : [`Infinite | `Seconds of int] k
    | Route : ([ `Ip of Ipaddr.t | `Net_gateway | `Remote_host | `Vpn_gateway]
               * Ipaddr.Prefix.t option
               * [ `Ip of Ipaddr.t | `Net_gateway | `Remote_host
                 | `Vpn_gateway] option
               * [ `Default | `Metric of int]) list k
    (** Route consists of: network , netmask , gateway , metric *)

    | Route_delay : (int * int) k
    (** [n,w] seconds to wait after connection establishment before adding
        routes to the routing table. *)

    | Route_gateway : [ `Ip of Ipaddr.t
                      | `Default
                      | `Dhcp ] k
    (** DHCP: should be executed on the encrypted VPN LAN interface *)

    | Route_metric : [`Default | `Metric of int] k
    (** Default metric for [Route _] directives *)

    | Tls_auth : ([`Incoming | `Outgoing] option
                  * Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tls_cert     : X509.Certificate.t k

    | Tls_mode   : [`Client | `Server] k
    (** Governed by the [tls-client] and [tls-server] directives.
        Indirectly also by [client]. *)

    | Tls_key      : X509.Private_key.t k
    (** TODO Tls_key : X509.private_key * [`Incoming|`Outgoing] k
        --key-direction governs this for inlined files
        see comment in {!a_key} *)

    | Tls_timeout : int k
    (** Retransmit control channel packet after not receiving an ACK for
        [n] seconds. TODO: presumably does not apply to TCP? *)

    | Tls_version_min : ([`V1_3 | `V1_2 | `V1_1 ] * bool) k
    (** [v * or_highest]: if [or_highest] then v = the highest version supported
        by the TLS library. *)

    | Topology : [`Net30 | `P2p | `Subnet] k

    | Transition_window : int k
    (* our old key can live this many seconds after a new key
       renegotiation begins. Feature allows for a graceful transition from old
       to new key, and removes the key renegotiation sequence from the
       critical path of tunnel data forwarding.
       TODO pasted from `man openvpn`
    *)

    | Tun_mtu : int k
    (* MTU of the local TUN interface used to receive (from the user's operating system), or transmit (decrypted), plaintext packets.
       TODO: is this also used for the IP payloads of 'dev tap' configurations?
       TODO: openvpn manpage says something about deriving Link_mtu from this *)

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

type ip_config = {
  ip : Ipaddr.V4.t ;
  prefix : Ipaddr.V4.Prefix.t ;
  gateway : Ipaddr.V4.t ;
}

val pp_ip_config : ip_config Fmt.t

type event = [
  | `Resolved of Ipaddr.t
  | `Resolve_failed
  | `Connected
  | `Connection_failed
  | `Tick
  | `Data of Cstruct.t
]

val pp_event : event Fmt.t

type action = [
  | `Resolve of [ `host ] Domain_name.t * [`Ipv4 | `Ipv6 | `Any]
  | `Connect of Ipaddr.t * int * [`Tcp | `Udp]
  | `Disconnect
  | `Exit
  | `Established of ip_config * int
  | `Payload of Cstruct.t list
]

val pp_action : action Fmt.t

val client : Config.t -> int64 -> (int -> Cstruct.t) ->
  (t * action, Rresult.R.msg) result
(** [client config ts rng] constructs a [t], returns the remote to
    connect to, an initial buffer to send to the remote. It returns an error
    if the configuration does not contain a tls-auth element. *)

type error
(** The type of errors when processing incoming data. *)

val pp_error : error Fmt.t
(** [pp_error ppf e] pretty prints the error [e]. *)

val handle : t -> Ptime.t -> int64 -> event -> (t * Cstruct.t list * action option, error) result

val outgoing : t -> int64 -> Cstruct.t -> (t * Cstruct.t, [ `Not_ready ]) result
(** [outgoing t ts data] prepares [data] to be sent over the OpenVPN connection.
    If the connection is not ready yet, [`Not_ready] is returned instead. *)
