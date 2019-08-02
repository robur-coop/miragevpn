(* synopsis: openvpn-connected stack that sends OpenVPN pings. *)

(* similar to the lwt-client, but via mirage. handles ICMP echo requests by
   replying to them via the tunnel *)

(* this does not implement the design-data-flow, but hardcodes usage of the
   "internal stack" (i.e. no forwarding and second ethernet interface!) *)

open Lwt.Infix

module Main (R : Mirage_random.C) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time_lwt.S)
    (S : Mirage_stack_lwt.V4)
    (N : Mirage_net_lwt.S) (E : Mirage_protocols_lwt.ETHERNET) (A : Mirage_protocols_lwt.ARP) (I : Mirage_protocols_lwt.IPV4)
    (FS: Mirage_kv_lwt.RO) = struct

  module O = Openvpn_mirage.Make(R)(M)(P)(T)(S)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
      let string_of_file _ = Error (`Msg "not supported") in
      Openvpn.Config.parse_client ~string_of_file data

  let log = Logs.Src.create "nat" ~doc:"NAT device"
  module Log = (val Logs.src_log log : Logs.LOG)
  module Private_routing = Routing.Make(Log)(A)

  let start _ _ _ _ s net eth arp ip data _ =
    let private_ip_net, private_ip = Key_gen.private_ipv4 () in
    read_config data >>= function
    | Error (`Msg m) -> Lwt.fail_with m
    | Ok config ->
      O.connect config s >>= function
      | Error (`Msg m) -> Lwt.fail_with m
      | Ok ovpn ->
        Logs.info (fun m -> m "tunnel established");
        let output_tunnel packet =
          O.write ovpn (Cstruct.concat (Nat_packet.to_cstruct packet)) >|= fun res ->
          if not res then Log.err (fun m -> m "failed to write data via tunnel")
        and output_private packet =
          let dst = match packet with `IPv4 (p, _) -> p.Ipv4_packet.dst in
          Private_routing.destination_mac private_ip_net None arp dst >>= function
          | Error e ->
            Log.err (fun m -> m "could not send packet, error: %s"
                        (match e with `Local -> "local" | `Gateway -> "gateway"));
            Lwt.return_unit
          | Ok dst ->
            E.write eth dst `IPv4 (fun b ->
                match Nat_packet.into_cstruct packet b with
                | Ok n -> n
                | Error e ->
                  Log.err (fun m -> m "error %a while Nat_packet.into_cstruct"
                              Nat_packet.pp_error e);
                  0) >|= function
            | Ok () -> ()
            | Error e ->
              Log.err (fun m -> m "error %a while writing" E.pp_error e)
        in
        let rec ingest_private table packet =
          Log.debug (fun f -> f "Private interface got a packet: %a"
                        Nat_packet.pp packet);
          let dst = match packet with `IPv4 (p, _) -> p.Ipv4_packet.dst in
          if Ipaddr.V4.compare dst private_ip = 0 then begin
            Log.debug (fun m -> m "ignoring ip packet for ourselves");
            Lwt.return_unit
          end else
            Mirage_nat_lru.translate table packet >>= function
            | Ok packet -> output_tunnel packet
            | Error `Untranslated -> add_rule table packet
            | Error `TTL_exceeded ->
              Log.warn (fun f -> f "TTL exceeded"); Lwt.return_unit
        and add_rule table packet =
          let public_ip = O.get_ip ovpn
          and port = Randomconv.int16 R.generate
          in
          Mirage_nat_lru.add table ~now:(M.elapsed_ns ()) packet (public_ip, port) `NAT >>= function
          | Error e ->
            Log.debug (fun m -> m "Failed to add a NAT rule: %a"
                          Mirage_nat.pp_error e);
            Lwt.return_unit
          | Ok () -> ingest_private table packet
        in
        let ingest_public table cs =
          match Nat_packet.of_ipv4_packet cs with
          | Error e ->
            Log.err (fun m -> m "ingest_public nat_packet.of_ipv4 err %a"
                        Nat_packet.pp_error e);
            Lwt.return_unit
          | Ok packet ->
            Mirage_nat_lru.translate table packet >>= function
            | Ok packet -> output_private packet
            | Error e ->
              let msg = match e with
                | `TTL_exceeded -> "ttl exceeded" | `Untranslated -> "no match"
              in
              Log.warn (fun m -> m "error when translating %s" msg);
              Lwt.return_unit
        in
        Mirage_nat_lru.empty ~tcp_size:1024 ~udp_size:1024 ~icmp_size:20 >>= fun table ->
        let listen_private =
          let ipv4 p = match Nat_packet.of_ipv4_packet p with
            | Error e ->
              Log.err (fun m -> m "listen_private failed Nat.of_ipv4_packet %a"
                          Nat_packet.pp_error e);
              Lwt.return_unit
            | Ok pkt -> ingest_private table pkt
          and arpv4 = A.input arp
          in
          let header_size = Ethernet_wire.sizeof_ethernet
          and input = E.input ~arpv4 ~ipv4 ~ipv6:(fun _ -> Lwt.return_unit) eth in
          N.listen ~header_size net input >|= function
          | Error e -> Log.err (fun m -> m "private interface stopped: %a"
                                     N.pp_error e)
          | Ok () -> Log.debug (fun m -> m "private interface terminated normally")
        in
        let rec listen_ovpn () =
          O.read ovpn >>= fun datas ->
          Lwt_list.iter_s (ingest_public table) datas >>= fun () ->
          listen_ovpn ()
        in
        Lwt.pick [ listen_private ; listen_ovpn () ]
end
