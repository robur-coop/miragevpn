(* control flow of a server (forwarding only)
    - config + stack (+rng +pclock +mclock) -> Miragevpn.server ++ int
    - Listen / accept on returned port
    - new_connection server ts -> Miragevpn.t [ server loop ]
     - established / connected -> Miragevpn.established <ip> session
    - established ++ read on connection -> handle + forward/write to destination
*)
module Server (S : Tcpip.Stack.V4V6) : sig
  type t

  val connect :
    ?really_no_authentication:bool ->
    ?payloadv4_from_tunnel:(Ipv4_packet.t -> Cstruct.t -> unit Lwt.t) ->
    Miragevpn.Config.t ->
    S.t ->
    t

  val write : t -> Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t
end

module Client_router (S : Tcpip.Stack.V4V6) : sig
  type t

  val mtu : t -> int
  val get_ip : t -> Ipaddr.V4.t
  val configured_ips : t -> Ipaddr.V4.Prefix.t list

  val connect :
    Miragevpn.Config.t -> S.t -> (t, [ `Msg of string ]) result Lwt.t

  (* TODO some way to tear down the connection gracefully *)

  val read : t -> Cstruct.t list Lwt.t
  val write : t -> Cstruct.t -> bool Lwt.t
end

module Client_stack (S : Tcpip.Stack.V4V6) : sig
  include Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t

  val connect :
    Miragevpn.Config.t ->
    S.t ->
    ( t
      * (tcp:callback ->
        udp:callback ->
        default:(proto:int -> callback) ->
        t ->
        unit Lwt.t),
      [ `Msg of string ] )
    result
    Lwt.t
end
