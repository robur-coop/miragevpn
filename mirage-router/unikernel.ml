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

(* according to RFC 1812 (requirements for routers), an incoming ipv4 fragment
   should be forwarded, potentially fragmented into multiple pieces if the mtu
   is smaller. i.e. instead of reassembling the full packet, send out each
   incoming fragment individually. this makes a lot of sense in setups where
   the >router< may be only one route from the source to destination, and not
   every ip fragment takes the same route.

   in our specific setup, this is not the case, and it feels more appropriate
   (better for the network) to reassemble and only forward full ipv4 packets.

   a difference would be either if there's a fault-tolerant setup, or if
   fragmented packets are used for real-time communication. my intuition is
   that path mtu discovery or 512 byte sized udp payload have won.

   we strip all ipv4 options (i.e. source route / record route / etc.), but
   i think ipv4 options are barely used in the wild, so this is fine.
*)

open Lwt.Infix

module Main (R : Mirage_random.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4V6)
    (N : Mirage_net.S) (E : Mirage_protocols.ETHERNET) (A : Mirage_protocols.ARP) (I : Mirage_protocols.IPV4) (FS: Mirage_kv.RO) = struct

  module O = Openvpn_mirage.Make(R)(M)(P)(T)(S)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
      let string_of_file _ = Error (`Msg "not supported") in
      Openvpn.Config.parse_client ~string_of_file data

  let local_network ip =
    let cidr = Key_gen.private_ipv4 () in
    if Ipaddr.V4.compare (Ipaddr.V4.Prefix.address cidr) ip = 0 then begin
      Logs.warn (fun m -> m "a packet directed to us (ignoring)");
      false
    end else
      Ipaddr.V4.Prefix.mem ip cidr

  let forward_or_reject hdr payload mtu =
    (* there are actually four potential outcomes here:
       - packet is good to be forwarded
       - packet gets an ICMP error report
       - packet is a fragment and should be dropped (not handling, as noted
         above we're reassembling)
       - packet is an ICMP error and getting dropped (do not reply)
    *)
    let open Icmpv4_packet in
    let open Icmpv4_wire in
    let icmp_err ?(subheader = Unused) ?(code = 0) ty =
      (* ICMP packet is 8 byte header, plus original IP header, plus original
         payload (8 bytes) *)
      let plen = min 8 (Cstruct.len payload) in
      let orig_payload = Cstruct.sub payload 0 plen in
      let ip_hdr =
        Ipv4_packet.Marshal.make_cstruct ~payload_len:plen hdr
      in
      let payload = Cstruct.append ip_hdr orig_payload in
      let icmp = { code ; ty ; subheader } in
      let icmp_buf = Marshal.make_cstruct icmp ~payload in
      Cstruct.append icmp_buf payload
    in
    let is_icmp =
      match Ipv4_packet.Unmarshal.int_to_protocol hdr.Ipv4_packet.proto with
      | Some `ICMP -> true
      | _ -> false
    and is_first_fragment = hdr.Ipv4_packet.off land 0x1FFF = 0
    in
    if hdr.Ipv4_packet.ttl <= 1 then (* time to live exceeded *)
      if is_first_fragment then
        if is_icmp then begin
          Logs.warn (fun m -> m "received ICMP %a which TTL exceeded"
                        Ipv4_packet.pp hdr);
          Error `Drop
        end else
          Error (`Icmp (icmp_err Time_exceeded))
      else begin
        Logs.warn (fun m -> m "packet not first fragment %a, TTL exceeded"
                        Ipv4_packet.pp hdr);
        Error `Drop
      end
    else if hdr.Ipv4_packet.off land 0x4000 = 0x4000 &&
            Cstruct.len payload > mtu then (* don't fragment set and would fragment *)
      if is_first_fragment then
        if is_icmp then begin
          Logs.warn (fun m -> m "received ICMP packet %a where don't fragment is set, but would fragment"
                        Ipv4_packet.pp hdr);
          Error `Drop
        end else
          let code = unreachable_reason_to_int Would_fragment
          and subheader = Next_hop_mtu mtu
          in
          Error (`Icmp (icmp_err ~subheader ~code Destination_unreachable))
      else begin
        Logs.warn (fun m -> m "packet not first fragment %a, would fragment"
                      Ipv4_packet.pp hdr);
        Error `Drop
      end
    else
      let hdr = { hdr with Ipv4_packet.ttl = pred hdr.Ipv4_packet.ttl } in
      Ok hdr

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
      let c, pkt =
        Fragments.process t.private_fragments (M.elapsed_ns ()) ip_hdr payload
      in
      t.private_fragments <- c;
      Logs.info (fun m -> m "%B forwarding packet %a"
                    (match pkt with None -> false | Some _ -> true)
                    Ipv4_packet.pp ip_hdr);
      match pkt with
      | None -> Lwt.return_unit
      | Some (hdr, pay) ->
        let pay_mtu = O.mtu t.ovpn - 20 in
        match forward_or_reject hdr pay pay_mtu with
        | Ok hdr ->
          let hdr, fst, rest =
            if Cstruct.len pay > pay_mtu then
              let fst, rest = Cstruct.split pay pay_mtu in
              (* need to set 'more fragments' bit in the IPv4 header *)
              let hdr = { hdr with Ipv4_packet.off = 0x2000 } in
              hdr, fst, Fragments.fragment ~mtu:pay_mtu hdr rest
            else
              hdr, pay, []
          in
          let hdr_cs =
            Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len fst) hdr
          in
          let write_one data = O.write t.ovpn data >|= fun _ -> () in
          write_one (Cstruct.append hdr_cs pay) >>= fun () ->
          Lwt_list.iter_s write_one rest
        | Error (`Icmp payload) ->
          Lwt.async (fun () ->
              I.write t.private_ip ~ttl:255 hdr.Ipv4_packet.src `ICMP
                (fun _ -> 0) [ payload ] >|= function
              | Ok () -> ()
              | Error err ->
                Logs.warn (fun m -> m "error %a while sending an ICMP error"
                              I.pp_error err));
          Lwt.return_unit
        | Error `Drop -> Lwt.return_unit
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
                  Logs.warn (fun m -> m "ignoring %a (cannot decode IP protocol number)"
                                Ipv4_packet.pp hdr)
                | Some proto ->
                  match forward_or_reject hdr payload (I.mtu t.private_ip ~dst:hdr.Ipv4_packet.dst) with
                  | Ok hdr ->
                    Lwt.async (fun () ->
                        (* The IPv4.write here takes care of fragmenting the packet*)
                        I.write t.private_ip ~ttl:hdr.Ipv4_packet.ttl
                          ~src:hdr.Ipv4_packet.src hdr.Ipv4_packet.dst
                          proto (fun _ -> 0) [ payload ] >|= function
                        | Ok () -> ()
                        | Error e ->
                          (* could send back host unreachable if this was an arp timeout *)
                          Logs.err (fun m -> m "error %a while forwarding %a"
                                       I.pp_error e Ipv4_packet.pp hdr))
                  | Error (`Icmp pay) ->
                    (* send icmp error back via ovpn *)
                    let hdr = {
                      hdr with Ipv4_packet.ttl = 255 ;
                               src = List.hd (I.get_ip t.private_ip) ; (* or which ip should be used? *)
                               dst = hdr.Ipv4_packet.src ;
                               proto = Ipv4_packet.Marshal.protocol_to_int `ICMP
                    } in
                    let payload_len = Cstruct.len pay in
                    let hdr_cs = Ipv4_packet.Marshal.make_cstruct ~payload_len hdr in
                    Lwt.async (fun () ->
                      O.write t.ovpn (Cstruct.append hdr_cs pay) >|= fun _ ->
                      ())
                  | Error `Drop -> ()
              else
                Logs.warn (fun m -> m "ignoring %a (IPv4 packet received via the tunnel, which destination is not our network %a)"
                              Ipv4_packet.pp hdr Ipaddr.V4.Prefix.pp (Key_gen.private_ipv4 ()))
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
