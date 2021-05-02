(* synopsis: openvpn-connected stack that sends OpenVPN pings. *)

(* similar to the lwt-client, but via mirage. handles ICMP echo requests by
   replying to them via the tunnel *)

(* this does not implement the design-data-flow, but hardcodes usage of the
   "internal stack" (i.e. no forwarding and second ethernet interface!) *)

open Lwt.Infix

module Main (R : Mirage_random.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4V6) (FS: Mirage_kv.RO) = struct

  module O = Openvpn_mirage.Make_stack(R)(M)(P)(T)(S)
  module I = Icmpv4.Make(O)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
      let string_of_file _ = Error (`Msg "not supported") in
      Openvpn.Config.parse_client ~string_of_file data

  let cb icmp ~proto ~src ~dst buf =
    match proto with
    | 1 ->
      Logs.warn (fun m -> m "received ICMP frame %a -> %a (%d bytes)"
                    Ipaddr.V4.pp src Ipaddr.V4.pp dst (Cstruct.len buf));
      I.input icmp ~src ~dst buf
    | _ ->
      Logs.info (fun m -> m "received IPv4 frame (proto %d) %a -> %a (%d bytes)"
                    proto Ipaddr.V4.pp src Ipaddr.V4.pp dst (Cstruct.len buf));
      Lwt.return_unit

  let start _ _ _ _ s data =
    (let open Lwt_result.Infix in
     read_config data >>= fun config ->
     O.connect config s >>= fun (t, reader) ->
     Logs.info (fun m -> m "tunnel established");
     Lwt_result.ok (I.connect t) >>= fun i ->
     let cb = cb i in
     Lwt_result.ok (reader ~tcp:(cb ~proto:6) ~udp:(cb ~proto:17) ~default:cb t)) >|= function
    | Ok () -> Logs.warn (fun m -> m "reader finished without error...");
    | Error `Msg e -> Logs.err (fun m -> m "error %s" e)
end
