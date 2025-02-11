module Config : sig
  (** OpenVPN configuration parsing module *)

  type flag = unit

  module Protocol_flag : sig
    type t

    val to_string : t -> string
  end

  type 'a k =
    | Auth : [< Digestif.hash' > `MD5 `SHA1 `SHA224 `SHA256 `SHA384 `SHA512 ] k
    | Auth_nocache : flag k
      (* Erase user-provided credentials ([Askpass] and [Auth_user_pass]) from
         program memory after their user.
         DOES NOT affect [--http-proxy-user-pass].
      *)
    | Auth_retry : [ `Interact | `Nointeract | `None ] k
        (** [`Interact]: Interactively ask user for new Auth_user_pass value
                     before retrying an authentication attempt.
        [`Nointeract]: Retry an authentication attempt with same Auth_user_pass
        [`None]: Exit with fatal error if authentication fails (default)
    *)
    | Auth_user_pass : (string * string) k  (** username, password*)
    | Auth_user_pass_verify : (string * [ `Via_env | `Via_file ]) k
    | Ca : X509.Certificate.t list k
    | Cipher
        : [ `AES_256_CBC | `AES_128_GCM | `AES_256_GCM | `CHACHA20_POLY1305 ] k
    | Client_to_client : flag k
    | Comp_lzo : flag k
    | Connect_retry : (int * int) k
    | Connect_retry_max : [ `Unlimited | `Times of int ] k
        (** How many times to retry each remote before giving up.
        The counter for each remote/connection should be reset upon the
        successful establishment of a  connection.*)
    | Connect_timeout : int k
        (** [connect-timeout] a.k.a. [server-poll-timeout]
        Timeout a connection attempt to a remote server after [SECONDS].
    *)
    | Data_ciphers : [ `AES_128_GCM | `AES_256_GCM | `CHACHA20_POLY1305 ] list k
    | Dev : ([ `Tun | `Tap ] * string option) k
        (** The device to be used for the unencrypted traffic.
        The optional string is a device name, the [dev] directive.
        The polymorphic variant specifies the [dev-type].
        The [dev-type] is inferred from the [dev] name if the latter
        consists of a "tap" or "tun" prefix followed by an
        integer between 0 and 128.
        If no device name is given, or the device name is
        simply "tun" or "tap", the device must be allocated dynamically. *)
    | Dhcp_disable_nbt : flag k
    | Dhcp_dns : Ipaddr.t list k
    | Dhcp_ntp : Ipaddr.t list k
    | Dhcp_domain : [ `host ] Domain_name.t k
    | Float : flag k
    | Handshake_window : int k
        (** TLS-based key exchange must finalize within [n] seconds of handshake
        initiation by any peer. If it fails to do so, we attempt to reset
        our connection with the peer and try again.
        Even in the event of handshake failure we will still use our
        expiring key for up to --tran-window seconds to maintain continuity
        of transmission of tunnel data.
        TODO pasted from `man openvpn`
    *)
    | Ifconfig : (Ipaddr.V4.t * Ipaddr.V4.t) k
        (**  TODO --ifconfig parameters which are IP addresses can also be  speci‐
              fied as a DNS or /etc/hosts file resolvable name.*)
    | Ifconfig_nowarn : flag k
    | Key_derivation : [ `Tls_ekm ] k
    | Link_mtu : int k
        (** MTU of the network interface used to receive/transmit encrypted packets,
        e.g. the network interface that connects OpenVPN client and server. *)
    | Local : Ipaddr.t k
    | Lport : int k
    | Mssfix : int k
    | Mute_replay_warnings : flag k
    | Passtos : flag k
    | Peer_fingerprint : string list k
    | Persist_key : flag k
    | Persist_tun : flag k
    | Ping_interval : [ `Not_configured | `Seconds of int ] k
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
    | Ping_timeout : [ `Restart of int | `Exit of int ] k
    | Pkcs12 : X509.PKCS12.t k
    | Port : int k
    | Pull : flag k
    | Push : string list k
    | Proto
        : ([ `Ipv6 | `Ipv4 ] option
          * [ `Udp | `Tcp of [ `Server | `Client ] option ])
          k
    | Proto_force : [ `Udp | `Tcp ] k
    | Protocol_flags : Protocol_flag.t list k
    | Redirect_gateway
        : [ `Def1
          | `Local
          | `Auto_local
          | `Bypass_dhcp
          | `Bypass_dns
          | `Block_local
          | `Ipv6
          | `Not_ipv4 ]
          list
          k
    | Remote
        : ([ `Domain of [ `host ] Domain_name.t * [ `Ipv4 | `Ipv6 | `Any ]
           | `Ip of Ipaddr.t ]
          * int option
          * [ `Udp | `Tcp ] option)
          list
          k
    | Remote_cert_tls : [ `Server | `Client ] k
    | Remote_random : flag k
    | Renegotiate_bytes : int k  (** reneg-bytes *)
    | Renegotiate_packets : int k  (** reneg-pkts *)
    | Renegotiate_seconds : int k  (** reneg-sec *)
    | Replay_window : (int * int) k
    | Resolv_retry : [ `Infinite | `Seconds of int ] k
    | Route
        : ([ `Ip of Ipaddr.V4.t | `Net_gateway | `Remote_host | `Vpn_gateway ]
          * Ipaddr.V4.t option
          * [ `Ip of Ipaddr.V4.t | `Net_gateway | `Remote_host | `Vpn_gateway ]
            option
          * int option)
          list
          k  (** Route consists of: network , netmask , gateway , metric *)
    | Route_delay : (int * int) k
        (** [n,w] seconds to wait after connection establishment before adding
        routes to the routing table. *)
    | Route_gateway : [ `Ip of Ipaddr.V4.t | `Dhcp ] k
        (** DHCP: should be executed on the encrypted VPN LAN interface *)
    | Route_metric : int k  (** Default metric for [Route _] directives *)
    | Route_nopull : flag k
    | Rport : int k
    | Script_security : int k
    | Secret
        : ([ `Incoming | `Outgoing ] option * string * string * string * string)
          k
    | Server : Ipaddr.V4.Prefix.t k
    | Tls_auth
        : ([ `Incoming | `Outgoing ] option * string * string * string * string)
          k
    | Tls_cert : X509.Certificate.t k
    | Tls_mode : [ `Client | `Server ] k
        (** Governed by the [tls-client] and [tls-server] directives.
        Indirectly also by [client]. *)
    | Tls_key : X509.Private_key.t k
    | Tls_timeout : int k
        (** Retransmit control channel packet after not receiving an ACK for
        [n] seconds. TODO: presumably does not apply to TCP? *)
    | Tls_version_min : (Tls.Core.tls_version * bool) k
        (** [v * or_highest]: if [or_highest] then v = the highest version supported
        by the TLS library. *)
    | Tls_version_max : Tls.Core.tls_version k
    | Tls_cipher : Tls.Ciphersuite.ciphersuite list k
    | Tls_ciphersuite : Tls.Ciphersuite.ciphersuite13 list k
    | Tls_crypt : Tls_crypt.t k
    | Tls_crypt_v2_client : (Tls_crypt.t * Tls_crypt.Wrapped_key.t * bool) k
        (** [Tls_crypt_v2_client (key, wkc, force_cookie)] *)
    | Tls_crypt_v2_server : (Tls_crypt.V2_server.t * bool) k
        (** [Tls_crypt_v2_server (key, force_cookie)] *)
    | Topology : [ `Net30 | `P2p | `Subnet ] k
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
    | Verify_client_cert : [ `None | `Optional | `Required ] k
    | Verify_x509_name : [ `host ] Domain_name.t k

  include Gmap.S with type 'a key = 'a k

  val pp : Format.formatter -> t -> unit
  (** [pp ppf t] is [t] printed in a near approximation of the openvpn
      configuration-format onto the [ppf] formatter.

      It should be mostly possible to re-use such a dump as a configuration file
      with *)

  val eq : eq
  (** [eq] is an implementation of [cmp] for use with [{!equal} cmp t t2] *)

  val client_merge_server_config :
    t -> string -> (t, [> `Msg of string ]) result
  (** Apply config excerpt from server received upon initial connection.
      [client_merge_server_config client_config server_config] is a success if
      [server_config] does not conflict with [client_config].
      TODO return conflicting subset as error
      - atm: do what validate_server_options did, returning unmodified.
  *)

  val merge_push_reply : t -> string -> (t, [> `Msg of string ]) result
  (** [merge_push_reply client_config push_config] is a successful
      merge of [client_config] and [push_config] if [push_config] does not
      conflict with [client_config].
      TODO return conflicting subset as error
  *)

  val parse_server :
    string_of_file:(string -> (string, [ `Msg of string ]) result) ->
    string ->
    (t, [> `Msg of string ]) result
  (** Parses a configuration string, looking up references to external files
      as needed. Validates the server configuration. Default options are
      applied. *)

  val parse_client :
    string_of_file:(string -> (string, [ `Msg of string ]) result) ->
    string ->
    (t, [> `Msg of string ]) result
  (** Parses a configuration string, looking up references to external files
      as needed. Validates the client configuration. Default options are
      applied. *)
end

module Tls_crypt = Tls_crypt

type t
(** The abstract type of an OpenVPN connection. *)

type server
type ip_config = { cidr : Ipaddr.V4.Prefix.t; gateway : Ipaddr.V4.t }
type route_info

val pp_ip_config : ip_config Fmt.t
val server_bind_port : Config.t -> int

val remotes :
  Config.t ->
  ([ `Domain of [ `host ] Domain_name.t * [ `Ipv4 | `Ipv6 | `Any ]
   | `Ip of Ipaddr.t ]
  * int
  * [ `Udp | `Tcp ])
  list

val proto : Config.t -> [ `Any | `Ipv4 | `Ipv6 ] * [ `Udp | `Tcp ]

val routes :
  shares_subnet:bool ->
  net_gateway:Ipaddr.V4.t option ->
  remote_host:Ipaddr.V4.t option ->
  route_info ->
  (Ipaddr.V4.Prefix.t * Ipaddr.V4.t * int) list

type event =
  [ `Resolved of Ipaddr.t
  | `Resolve_failed
  | `Connected
  | `Connection_failed
  | `Tick
  | `Data of string ]

val pp_event : event Fmt.t

type initial_action =
  [ `Resolve of [ `host ] Domain_name.t * [ `Ipv4 | `Ipv6 | `Any ]
  | `Connect of Ipaddr.t * int * [ `Tcp | `Udp ] ]

type cc_message =
  [ `Cc_exit | `Cc_restart of string option | `Cc_halt of string option ]

type action =
  [ initial_action
  | `Exit
  | `Established of ip_config * int * route_info
  | cc_message ]

val pp_action : action Fmt.t

val client :
  ?pkcs12_password:string ->
  Config.t ->
  (t * initial_action, [> `Msg of string ]) result
(** [client config] constructs a [t], returns the remote to
    connect to, an initial buffer to send to the remote. It returns an error
    if the configuration does not contain a tls-auth element. *)

val server :
  ?really_no_authentication:bool ->
  is_not_taken:(Ipaddr.V4.t -> bool) ->
  ?auth_user_pass:(user:string -> pass:string -> bool) ->
  Config.t ->
  ( server * (Ipaddr.V4.t * Ipaddr.V4.Prefix.t) * int,
    [> `Msg of string ] )
  result
(** [server config ~is_not_taken ~auth_user_pass] constructs a
    [server], its [ip, netmask] and [port].  The callback [is_not_taken] is
    provided to avoid IP address collisions. The callback [auth_user_pass]
    validates username and password of each connection. It returns an error if
    the configuration does not contain a tls-auth element. *)

type error
(** The type of errors when processing incoming data. *)

val pp_error : error Fmt.t
(** [pp_error ppf e] pretty prints the error [e]. *)

val handle :
  t -> event -> (t * string list * string list * action option, error) result
(** [handle t event] handles the [event] with the state [t]. The return value is
    the new state, a list of packets to transmit to the other peer, a list of
    payloads to foward to the application, and maybe an action to handle. *)

val outgoing : t -> string -> (t * string, [ `Not_ready ]) result
(** [outgoing t data] prepares [data] to be sent over the OpenVPN connection.
    If the connection is not ready yet, [`Not_ready] is returned instead. *)

val send_control_message :
  t -> string -> (t * string list, [ `Not_ready ]) result
(** [send_control_message t message] sends [message] over the control channel. *)

val new_connection :
  server ->
  string ->
  (t * string list * string list * action option, error) result
(** [new_connection server] is to be called when the server accepted a new
    TCP connection, a state [t] is constructed - which can be used with
    {!handle}. *)
