
module Make (R : Mirage_random.C) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) : sig
  type t

  val mtu : t -> int

  val get_ip : t -> Ipaddr.V4.t

  val connect : Openvpn.Config.t -> S.t -> (t, [ `Msg of string ]) result Lwt.t

  (* TODO some way to tear down the connection gracefully *)

  (* TODO is this a good read signature? *)
  val read : t -> Cstruct.t list Lwt.t

  val write : t -> Cstruct.t -> bool Lwt.t
end

module Make_stack (R : Mirage_random.C) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) : sig
  include Mirage_protocols_lwt.IPV4

  val connect : Openvpn.Config.t -> S.t ->
    (t * (tcp:callback -> udp:callback -> default:(proto:int -> callback) -> t -> unit io),
     [ `Msg of string ]) result io
end
