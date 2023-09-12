(* synopsis: openvpn-connected stack that sends OpenVPN pings. *)

(* similar to the lwt-client, but via mirage. handles ICMP echo requests by
   replying to them via the tunnel *)

(* this does not implement the design-data-flow, but hardcodes usage of the
   "internal stack" (i.e. no forwarding and second ethernet interface!) *)

open Lwt.Infix

module Main
    (R : Mirage_random.S)
    (M : Mirage_clock.MCLOCK)
    (P : Mirage_clock.PCLOCK)
    (T : Mirage_time.S)
    (S : Tcpip.Stack.V4V6)
    (N : Mirage_net.S)
    (E : Ethernet.S)
    (A : Arp.S)
    (_ : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t)
    (FS : Mirage_kv.RO) =
struct
  module O = Miragevpn_mirage.Make (R) (M) (P) (T) (S)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
        let string_of_file _ = Error (`Msg "not supported") in
        Miragevpn.Config.parse_client ~string_of_file data

  let log = Logs.Src.create "nat" ~doc:"NAT device"

  module Log = (val Logs.src_log log : Logs.LOG)
  module Private_routing = Routing.Make (Log) (A)

  let start _ _ _ _ s net eth arp _ip data =
    let private_ip_cidr = Key_gen.private_ipv4 () in
    read_config data >>= function
    | Error (`Msg m) -> failwith m
    | Ok config -> (
        O.connect config s >>= function
        | Error (`Msg m) -> failwith m
        | Ok ovpn ->
            Logs.info (fun m -> m "tunnel established");
            let output_tunnel packet =
              match Nat_packet.to_cstruct ~mtu:(O.mtu ovpn) packet with
              | Ok pkts ->
                  Lwt_list.fold_left_s
                    (fun r p -> if r then O.write ovpn p else Lwt.return r)
                    true pkts
                  >|= fun res ->
                  if not res then
                    Log.err (fun m -> m "failed to write data via tunnel")
              | Error e ->
                  Log.err (fun m ->
                      m "NAT to_cstruct failed %a" Nat_packet.pp_error e);
                  Lwt.return_unit
            and output_private packet =
              let dst = match packet with `IPv4 (p, _) -> p.Ipv4_packet.dst in
              Private_routing.destination_mac private_ip_cidr None arp dst
              >>= function
              | Error e ->
                  Log.err (fun m ->
                      m "could not send packet, error: %s"
                        (match e with
                        | `Local -> "local"
                        | `Gateway -> "gateway"));
                  Lwt.return_unit
              | Ok dst -> (
                  let more = ref [] in
                  E.write eth dst `IPv4 (fun b ->
                      match Nat_packet.into_cstruct packet b with
                      | Ok (n, adds) ->
                          more := adds;
                          n
                      | Error e ->
                          (* E.write takes a fill function (Cstruct.t -> int), which
                             can not result in an error. Now, if Nat_packet results in
                             an error (e.g. need to fragment, but fragmentation is not
                             allowed (don't fragment bit is set)), we can't pass this
                             information up the stack. Instead we log an error and
                             return 0 -- thus an empty Ethernet header will be
                             transmitted on the wire. *)
                          (* TODO an ICMP error should be sent to the packet origin *)
                          Log.err (fun m ->
                              m "error %a while Nat_packet.into_cstruct"
                                Nat_packet.pp_error e);
                          0)
                  >>= function
                  | Ok () ->
                      Lwt_list.iter_s
                        (fun pkt ->
                          let size = Cstruct.length pkt in
                          E.write eth dst `IPv4 ~size (fun buf ->
                              Cstruct.blit pkt 0 buf 0 size;
                              size)
                          >|= function
                          | Error e ->
                              Log.err (fun f ->
                                  f "Failed to send packet to private %a"
                                    E.pp_error e)
                          | Ok () -> ())
                        !more
                  | Error e ->
                      Log.err (fun m -> m "error %a while writing" E.pp_error e);
                      Lwt.return_unit)
            in
            let rec ingest_private table packet =
              Log.debug (fun f ->
                  f "Private interface got a packet: %a" Nat_packet.pp packet);
              let dst = match packet with `IPv4 (p, _) -> p.Ipv4_packet.dst in
              if
                Ipaddr.V4.compare dst (Ipaddr.V4.Prefix.address private_ip_cidr)
                = 0
              then (
                Log.debug (fun m -> m "ignoring ip packet for ourselves");
                Lwt.return_unit)
              else
                Mirage_nat_lru.translate table packet >>= function
                | Ok packet -> output_tunnel packet
                | Error `Untranslated -> add_rule table packet
                | Error `TTL_exceeded ->
                    (* TODO should report ICMP error message to src *)
                    Log.warn (fun f -> f "TTL exceeded");
                    Lwt.return_unit
            and add_rule table packet =
              let public_ip = O.get_ip ovpn
              and port = Randomconv.int16 R.generate in
              Mirage_nat_lru.add table packet (public_ip, port) `NAT
              >>= function
              | Error e ->
                  Log.debug (fun m ->
                      m "Failed to add a NAT rule: %a" Mirage_nat.pp_error e);
                  Lwt.return_unit
              | Ok () -> ingest_private table packet
            in
            let ingest_public cache now table cs =
              let cache', res = Nat_packet.of_ipv4_packet !cache ~now cs in
              cache := cache';
              match res with
              | Error e ->
                  Log.err (fun m ->
                      m "ingest_public nat_packet.of_ipv4 err %a"
                        Nat_packet.pp_error e);
                  Lwt.return_unit
              | Ok None -> Lwt.return_unit
              | Ok (Some packet) -> (
                  Mirage_nat_lru.translate table packet >>= function
                  | Ok packet -> output_private packet
                  | Error e ->
                      let msg =
                        match e with
                        | `TTL_exceeded -> "ttl exceeded"
                        | `Untranslated -> "no match"
                      in
                      Log.warn (fun m -> m "error when translating %s" msg);
                      Lwt.return_unit)
            in
            Mirage_nat_lru.empty ~tcp_size:1024 ~udp_size:1024 ~icmp_size:20
            >>= fun table ->
            let listen_private =
              let cache = ref (Fragments.Cache.empty (256 * 1024)) in
              let ipv4 p =
                let cache', res =
                  Nat_packet.of_ipv4_packet !cache ~now:(M.elapsed_ns ()) p
                in
                cache := cache';
                match res with
                | Error e ->
                    Log.err (fun m ->
                        m "listen_private failed Nat.of_ipv4_packet %a"
                          Nat_packet.pp_error e);
                    Lwt.return_unit
                | Ok None -> Lwt.return_unit
                | Ok (Some pkt) -> ingest_private table pkt
              and arpv4 = A.input arp in
              let header_size = Ethernet.Packet.sizeof_ethernet
              and input =
                E.input ~arpv4 ~ipv4 ~ipv6:(fun _ -> Lwt.return_unit) eth
              in
              N.listen ~header_size net input >|= function
              | Error e ->
                  Log.err (fun m ->
                      m "private interface stopped: %a" N.pp_error e)
              | Ok () ->
                  Log.debug (fun m -> m "private interface terminated normally")
            in
            let ovpn_cache = ref (Fragments.Cache.empty (256 * 1024)) in
            let rec listen_ovpn () =
              O.read ovpn >>= fun datas ->
              Lwt_list.iter_s
                (ingest_public ovpn_cache (M.elapsed_ns ()) table)
                datas
              >>= fun () -> listen_ovpn ()
            in
            Lwt.pick [ listen_private; listen_ovpn () ])
end
