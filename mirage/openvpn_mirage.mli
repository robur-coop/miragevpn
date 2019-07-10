
module Make (R : Mirage_random.C) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) : sig
  include Mirage_protocols_lwt.IPV4

  val connect : Openvpn.Config.t -> S.t ->
    (t * (tcp:callback -> udp:callback -> default:(proto:int -> callback) -> t -> unit io),
     [ `Msg of string ]) result io
end
