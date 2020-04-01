(* setup is as follows:
   the stack `s` is used for the openvpn tunnel
   on the private network interface we are a gateway (for our private network):
   - each packet received there that is addressed to us (at the ethernet layer) is forwarded via the tunnel [fragmentation may apply]
   - a packet read from the tunnel is forwarded onto the private network interface [reassembly may apply]

   --> the 'cb' below is called for each IPv4 frame that we received over the tunnel:
    - figure out depending on "dst" whether it needs to be forwarded via private network interface
    -> we can use Static_ipv4.write (with ~src) for sending out ipv4 packets
   --> another task needs to listen on the private network needs to send IPv4 packets from the private network over the tunnel
    -> we need a custom "listen" on ipv4 (arp as usual) which does not discard packets which are not addressed to us
*)
open Lwt.Infix

module Main (R : Mirage_random.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4)
    (N : Mirage_net.S) (E : Mirage_protocols.ETHERNET) (A : Mirage_protocols.ARP) (I : Mirage_protocols.IPV4) (FS: Mirage_kv.RO) = struct

  module O = Openvpn_mirage.Make(R)(M)(P)(T)(S)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
      let string_of_file _ = Error (`Msg "not supported") in
      Openvpn.Config.parse_client ~string_of_file data

  let local_network ip =
    let net, my_ip = Key_gen.private_ipv4 () in
    if Ipaddr.V4.compare my_ip ip = 0 then begin
      Logs.warn (fun m -> m "a packet directed to us (ignoring)");
      false
    end else
      Ipaddr.V4.Prefix.mem ip net

  type t = {
    ovpn : O.t ;
    mutable ovpn_fragments : Fragments.Cache.t ;
    private_ip : I.t ;
    mutable private_fragments : Fragments.Cache.t ;
  }

  let private_recv net eth arp t =
    let our_listen =
      E.input
        ~arpv4:(A.input arp)
        ~ipv4:(fun _ -> Logs.warn (fun m -> m "ignoring IPv4"); Lwt.return_unit)
        ~ipv6:(fun _ -> Logs.warn (fun m -> m "ignoring IPv6"); Lwt.return_unit)
        eth
    and forward_packet ip_hdr payload =
      let c, pkt = Fragments.process t.private_fragments (M.elapsed_ns ()) ip_hdr payload in
      t.private_fragments <- c;
      Logs.info (fun m -> m "%B forwarding packet %a"
                    (match pkt with None -> false | Some _ -> true)
                    Ipv4_packet.pp ip_hdr);
      match pkt with
      | None -> Lwt.return_unit
      | Some (hdr, pay) ->
        (* we need to check mtu and potentially fragment *)
        let hdr_cs =
          Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len pay) hdr
        in
        O.write t.ovpn (Cstruct.append hdr_cs pay) >|= fun _ ->
        ()
    in
    let listen buf =
      (* addressed on ethernet layer to us _and_ on ip layer src = local_network *)
      (* and ip layer dst <> local_network *)
      let should_be_routed eth_hdr ip_hdr =
        Macaddr.compare eth_hdr.Ethernet_packet.destination (N.mac net) = 0 &&
        local_network ip_hdr.Ipv4_packet.src &&
        not (local_network ip_hdr.Ipv4_packet.dst)
      in
      match Ethernet_packet.Unmarshal.of_cstruct buf with
      | Ok (eth_hdr, payload) when eth_hdr.Ethernet_packet.ethertype = `IPv4 ->
        begin match Ipv4_packet.Unmarshal.of_cstruct payload with
          | Ok (ip_hdr, payload) ->
            if should_be_routed eth_hdr ip_hdr then
              forward_packet ip_hdr payload
            else
              our_listen buf
          | Error e ->
            Logs.err (fun m -> m "couldn't decode ipv4 packet %s: %a"
                         e Cstruct.hexdump_pp buf);
            Lwt.return_unit
        end
      | Error e ->
        Logs.err (fun m -> m "couldn't decode ethernet packet %s: %a"
                     e Cstruct.hexdump_pp buf);
        Lwt.return_unit
      | Ok _ -> our_listen buf
    in
    N.listen net ~header_size:Ethernet_wire.sizeof_ethernet listen >|= function
    | Error e ->
      Logs.warn (fun m -> m "error %a listening on private network" N.pp_error e)
    | Ok () ->
      Logs.info (fun m -> m "listening on private network finished")

  (* packets received over the tunnel *)
  let rec ovpn_recv t =
    O.read t.ovpn >>= fun datas ->
    let ts = M.elapsed_ns () in
    Lwt_list.fold_left_s (fun c data ->
        match Ipv4_packet.Unmarshal.of_cstruct data with
        | Ok (hdr, payload) ->
          let c, pkt = Fragments.process c ts hdr payload in
          begin match pkt with
            | None -> ()
            | Some (hdr, payload) ->
              if local_network hdr.Ipv4_packet.dst then
                match Ipv4_packet.(Unmarshal.int_to_protocol hdr.proto) with
                | None ->
                  Logs.warn (fun m -> m "ignoring %a (cannot decode protocol)"
                                Ipv4_packet.pp hdr)
                | Some proto ->
                  Lwt.async (fun () ->
                      I.write t.private_ip ~src:hdr.Ipv4_packet.src hdr.Ipv4_packet.dst
                        proto (fun _ -> 0) [ payload ] >|= function
                      | Ok () -> ()
                      | Error e ->
                        Logs.err (fun m -> m "error %a while forwarding %a"
                                     I.pp_error e Ipv4_packet.pp hdr))
              else
                Logs.warn (fun m -> m "ignoring %a (not for our network)"
                              Ipv4_packet.pp hdr)
          end;
          Lwt.return c
        | Error msg ->
          Logs.err (fun m -> m "failed to decode ipv4 packet %s: %a"
                       msg Cstruct.hexdump_pp data);
          Lwt.return c)
      t.ovpn_fragments datas >>= fun frags ->
    t.ovpn_fragments <- frags;
    ovpn_recv t

  let start _ _ _ _ s net eth arp ip data =
    (let open Lwt_result.Infix in
     read_config data >>= fun config ->
     O.connect config s >>= fun ovpn ->
     Logs.info (fun m -> m "tunnel established");
     let t = {
       ovpn ; ovpn_fragments = Fragments.Cache.empty (256 * 1024) ;
       private_ip = ip ; private_fragments = Fragments.Cache.empty (256 * 1024) ;
     } in
     Lwt_result.ok (Lwt.join [ ovpn_recv t ; private_recv net eth arp t ])
    ) >|= function
    | Ok () -> Logs.warn (fun m -> m "unikernel finished without error...");
    | Error `Msg e -> Logs.err (fun m -> m "error %s" e)
end
