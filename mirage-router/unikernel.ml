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

module K = struct
  open Cmdliner

  let nat =
    let doc = Arg.info ~doc:"Use network address translation (NAT) on local traffic before sending over the tunnel."
        ["nat"]
    in
    Mirage_runtime.register_arg Arg.(value & flag doc)

  let nat_table_size =
    let doc = Arg.info ~doc:"The size of the NAT table (n/100 -> ICMP, n/2 -> TCP, n/2 -> UDP)." ["nat-table-size"] in
    Mirage_runtime.register_arg Arg.(value & opt int 2048 doc)
end

module Main
    (R : Mirage_crypto_rng_mirage.S)
    (M : Mirage_clock.MCLOCK)
    (P : Mirage_clock.PCLOCK)
    (T : Mirage_time.S)
    (S : Tcpip.Stack.V4V6)
    (N : Mirage_net.S)
    (E : Ethernet.S)
    (A : Arp.S)
    (I : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t and type prefix = Ipaddr.V4.Prefix.t)
    (B : Mirage_block.S) =
struct
  module O = Miragevpn_mirage.Client_router (R) (M) (P) (T) (S)

  let strip_0_suffix cfg =
    let rec find0 idx =
      if idx < Cstruct.length cfg then
        if Cstruct.get_uint8 cfg idx = 0 then idx else find0 (succ idx)
      else idx
    in
    Cstruct.sub cfg 0 (find0 0)

  let read_data block =
    B.get_info block >>= fun { Mirage_block.sector_size; size_sectors; _ } ->
    let data =
      let rec more acc = function
        | 0 -> acc
        | n -> more (Cstruct.create sector_size :: acc) (pred n)
      in
      more [] (Int64.to_int size_sectors)
    in
    B.read block 0L data >|= function
    | Ok () -> Ok data
    | Error e -> Error (`Msg (Fmt.to_to_string B.pp_error e))

  let read_config block =
    let open Lwt_result.Infix in
    read_data block >>= fun data ->
    let config = strip_0_suffix (Cstruct.concat data) in
    let string_of_file _ = Error (`Msg "not supported") in
    Lwt.return
      (Miragevpn.Config.parse_client ~string_of_file (Cstruct.to_string config))

  let local_network my_cidr ip =
    if Ipaddr.V4.compare (Ipaddr.V4.Prefix.address my_cidr) ip = 0 then
      (* Logs.warn (fun m -> m "a packet directed to us (ignoring)"); *)
      false
    else if Ipaddr.V4.compare (Ipaddr.V4.Prefix.broadcast my_cidr) ip = 0 then (
      Logs.debug (fun m -> m "dropping broadcast (RFC 2644)");
      false)
    else Ipaddr.V4.Prefix.mem ip my_cidr

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
      let plen = min 8 (Cstruct.length payload) in
      let orig_payload = Cstruct.sub payload 0 plen in
      let ip_hdr = Ipv4_packet.Marshal.make_cstruct ~payload_len:plen hdr in
      let payload = Cstruct.append ip_hdr orig_payload in
      let icmp = { code; ty; subheader } in
      let icmp_buf = Marshal.make_cstruct icmp ~payload in
      Cstruct.append icmp_buf payload
    in
    let is_icmp =
      match Ipv4_packet.Unmarshal.int_to_protocol hdr.Ipv4_packet.proto with
      | Some `ICMP -> true
      | _ -> false
    and is_first_fragment = hdr.Ipv4_packet.off land 0x1FFF = 0 in
    if hdr.Ipv4_packet.ttl <= 1 then
      (* time to live exceeded *)
      if is_first_fragment then
        if is_icmp then (
          Logs.warn (fun m ->
              m "received ICMP %a which TTL exceeded" Ipv4_packet.pp hdr);
          Error `Drop)
        else Error (`Icmp (icmp_err Time_exceeded))
      else (
        Logs.warn (fun m ->
            m "packet not first fragment %a, TTL exceeded" Ipv4_packet.pp hdr);
        Error `Drop)
    else if
      hdr.Ipv4_packet.off land 0x4000 = 0x4000 && Cstruct.length payload > mtu
    then
      (* don't fragment set and would fragment *)
      if is_first_fragment then
        if is_icmp then (
          Logs.warn (fun m ->
              m
                "received ICMP packet %a where don't fragment is set, but \
                 would fragment"
                Ipv4_packet.pp hdr);
          Error `Drop)
        else
          let code = unreachable_reason_to_int Would_fragment
          and subheader = Next_hop_mtu mtu in
          Error (`Icmp (icmp_err ~subheader ~code Destination_unreachable))
      else (
        Logs.warn (fun m ->
            m "packet not first fragment %a, would fragment" Ipv4_packet.pp hdr);
        Error `Drop)
    else
      let hdr = { hdr with Ipv4_packet.ttl = pred hdr.Ipv4_packet.ttl } in
      Ok hdr

  type t = {
    nat : Mirage_nat_lru.t option ;
    ovpn : O.t;
    mutable ovpn_fragments : Fragments.Cache.t;
    private_ip : I.t;
    mutable private_fragments : Fragments.Cache.t;
  }

  module Nat = struct
    let of_ipv4 ip_hdr payload =
      match Ipv4_packet.(Unmarshal.int_to_protocol ip_hdr.proto) with
      | Some `TCP ->
        begin match Tcp.Tcp_packet.Unmarshal.of_cstruct payload with
          | Error e ->
            Logs.debug (fun m -> m "Failed to parse TCP packet: %s@.%a" e
                           Cstruct.hexdump_pp payload);
            None
          | Ok (tcp, payload) -> Some (`IPv4 (ip_hdr, `TCP (tcp, payload)))
        end
      | Some `UDP ->
        begin match Udp_packet.Unmarshal.of_cstruct payload with
          | Error e ->
            Logs.debug (fun m -> m "Failed to parse UDP packet: %s@.%a" e
                           Cstruct.hexdump_pp payload);
            None
          | Ok (udp, payload) -> Some (`IPv4 (ip_hdr, `UDP (udp, payload)))
        end
      | Some `ICMP ->
        begin match Icmpv4_packet.Unmarshal.of_cstruct payload with
          | Error e ->
            Logs.debug (fun m -> m "Failed to parse ICMP packet: %s@.%a" e
                           Cstruct.hexdump_pp payload);
            None
          | Ok (header, payload) -> Some (`IPv4 (ip_hdr, `ICMP (header, payload)))
        end
      | _ ->
        Logs.debug (fun m -> m "Ignoring non-TCP/UDP/ICMP packet: %a"
                       Ipv4_packet.pp ip_hdr);
        None

    let payload_to_buf pkt =
      match pkt with
      | `IPv4 (ip_hdr, p) ->
        let src = ip_hdr.Ipv4_packet.src and dst = ip_hdr.dst in
        match p with
        | `ICMP (icmp_header, payload) -> begin
            let payload_start = Icmpv4_wire.sizeof_icmpv4 in
            let buf = Cstruct.create (payload_start + Cstruct.length payload) in
            Cstruct.blit payload 0 buf payload_start (Cstruct.length payload);
            match Icmpv4_packet.Marshal.into_cstruct icmp_header ~payload buf with
            | Error s ->
              Logs.warn (fun m -> m "Error writing ICMPv4 packet: %s" s);
              Error ()
            | Ok () -> Ok (buf, `ICMP, ip_hdr)
          end
        | `UDP (udp_header, udp_payload) -> begin
            let payload_start = Udp_wire.sizeof_udp in
            let buf = Cstruct.create (payload_start + Cstruct.length udp_payload) in
            Cstruct.blit udp_payload 0 buf payload_start (Cstruct.length udp_payload);
            let pseudoheader =
              Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP
                (Cstruct.length udp_payload + Udp_wire.sizeof_udp)
            in
            match Udp_packet.Marshal.into_cstruct
                    ~pseudoheader ~payload:udp_payload udp_header buf
            with
            | Error s ->
              Logs.warn (fun m -> m "Error writing UDP packet: %s" s);
              Error ()
            | Ok () -> Ok (buf, `UDP, ip_hdr)
          end
        | `TCP (tcp_header, tcp_payload) -> begin
            let payload_start =
              let options_length = Tcp.Options.lenv tcp_header.Tcp.Tcp_packet.options in
              (Tcp.Tcp_wire.sizeof_tcp + options_length)
            in
            let buf = Cstruct.create (payload_start + Cstruct.length tcp_payload) in
            Cstruct.blit tcp_payload 0 buf payload_start (Cstruct.length tcp_payload);
            (* and now transport header *)
            let pseudoheader =
              Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP
                (Cstruct.length tcp_payload + payload_start)
            in
            match Tcp.Tcp_packet.Marshal.into_cstruct
                    ~pseudoheader tcp_header
                    ~payload:tcp_payload buf
            with
            | Error s ->
              Logs.warn (fun m -> m "Error writing TCP packet: %s" s);
              Error ()
            | Ok _ -> Ok (buf, `TCP, ip_hdr)
          end

    let output_tunnel t packet =
      match Nat_packet.to_cstruct ~mtu:(O.mtu t.ovpn - Ipv4_wire.sizeof_ipv4) packet with
      | Ok pkts ->
        Lwt_list.fold_left_s
          (fun r p -> if r then O.write t.ovpn p else Lwt.return r)
          true pkts
        >|= fun res ->
        if not res then
          Logs.err (fun m -> m "failed to write data via tunnel")
      | Error e ->
        Logs.err (fun m ->
            m "NAT to_cstruct failed %a" Nat_packet.pp_error e);
        Lwt.return_unit

    let add_rule t table packet =
      let public_ip =
        Ipaddr.V4.Prefix.address (List.hd (O.configured_ips t.ovpn))
      in
      match
        Mirage_nat_lru.add table packet public_ip
          (fun () -> Some (Randomconv.int16 R.generate)) `NAT
      with
      | Error e ->
        Logs.debug (fun m ->
            m "Failed to add a NAT rule: %a" Mirage_nat.pp_error e);
        Lwt.return_unit
      | Ok () ->
        match Mirage_nat_lru.translate table packet with
        | Ok packet -> output_tunnel t packet
        | Error `Untranslated ->
          Logs.warn (fun m -> m "can't translate packet, giving up");
          Lwt.return_unit
        | Error `TTL_exceeded ->
          (* TODO should report ICMP error message to src *)
          Logs.warn (fun f -> f "TTL exceeded");
          Lwt.return_unit

    let ingest_private t table packet =
      Logs.debug (fun f ->
          f "Private interface got a packet: %a" Nat_packet.pp packet);
      match Mirage_nat_lru.translate table packet with
      | Ok packet -> output_tunnel t packet
      | Error `Untranslated -> add_rule t table packet
      | Error `TTL_exceeded ->
        (* TODO should report ICMP error message to src *)
        Logs.warn (fun f -> f "TTL exceeded");
        Lwt.return_unit

    let output_private t nat_packet =
      match payload_to_buf nat_packet with
      | Ok (buf, proto, ip_hdr) ->
        (I.write t.private_ip ~ttl:ip_hdr.Ipv4_packet.ttl
           ~src:ip_hdr.src ip_hdr.dst proto (fun _ -> 0) [ buf ]
         >|= function
         | Ok () -> ()
         | Error _e ->
           (* could send back host unreachable if this was an arp timeout *)
           (* Logs.err (fun m -> m "error %a while forwarding %a"
              I.pp_error e Ipv4_packet.pp hdr)) *)
           ())
        | Error () -> Lwt.return_unit
  end

  let forward_packet_over_tunnel t ip_hdr pay =
    let pay_mtu = O.mtu t.ovpn - Ipv4_wire.sizeof_ipv4 (* the unencrypted IP header *) in
    match forward_or_reject ip_hdr pay pay_mtu with
    | Ok hdr ->
      let hdr, fst, rest =
        if Cstruct.length pay > pay_mtu then
          let fst, rest = Cstruct.split pay pay_mtu in
          (* need to set 'more fragments' bit in the IPv4 header *)
          let hdr = { hdr with Ipv4_packet.off = 0x2000 } in
          (hdr, fst, Fragments.fragment ~mtu:pay_mtu hdr rest)
        else (hdr, pay, [])
      in
      let hdr_cs =
        Ipv4_packet.Marshal.make_cstruct
          ~payload_len:(Cstruct.length fst) hdr
      in
      (* TODO respect the return value from write *)
      let write_one data = O.write t.ovpn data >|= fun _ -> () in
      write_one (Cstruct.append hdr_cs pay) >>= fun () ->
      Lwt_list.iter_s write_one rest
    | Error (`Icmp payload) ->
      (I.write t.private_ip ~ttl:255 ip_hdr.Ipv4_packet.src `ICMP
         (fun _ -> 0) [ payload ] >|= function
           | Ok () -> ()
           | Error err ->
             Logs.warn (fun m -> m "error %a while sending an ICMP error"
                           I.pp_error err))
    | Error `Drop -> Lwt.return_unit

  let push_packet_over_tunnel t private_ip ip_hdr payload =
    let c, pkt =
      Fragments.process t.private_fragments (M.elapsed_ns ()) ip_hdr payload
    in
    t.private_fragments <- c;
    match pkt with
    | None -> Lwt.return_unit
    | Some (ip_hdr, payload) ->
      match t.nat with
      | None -> forward_packet_over_tunnel t ip_hdr payload
      | Some table ->
        match Nat.of_ipv4 ip_hdr payload with
        | None -> Lwt.return_unit
        | Some pkt -> Nat.ingest_private t table pkt

  let private_recv t private_ip net eth arp =
    let ipv4 payload =
      (* addressed with src = local_network and dst <> local_network *)
      let should_be_routed ip_hdr =
        local_network private_ip ip_hdr.Ipv4_packet.src
        && not (local_network private_ip ip_hdr.Ipv4_packet.dst)
      in
      match Ipv4_packet.Unmarshal.of_cstruct payload with
      | Ok (ip_hdr, payload) ->
        if should_be_routed ip_hdr then
          push_packet_over_tunnel t private_ip ip_hdr payload
        else
          (Logs.warn (fun m -> m "ignoring IPv4 which should not be routed (IP header: %a)"
                         Ipv4_packet.pp ip_hdr);
           Lwt.return_unit)
      | Error e ->
        Logs.err (fun m ->
            m "couldn't decode IPv4 packet %s: %a" e Cstruct.hexdump_pp payload);
        Lwt.return_unit
    in
    let input =
      E.input ~arpv4:(A.input arp)
        ~ipv4
        ~ipv6:(fun _ ->
          Logs.warn (fun m -> m "ignoring IPv6 packet");
          Lwt.return_unit)
        eth
    in
    N.listen net ~header_size:Ethernet.Packet.sizeof_ethernet input
    >|= function
    | Error e ->
        Logs.warn (fun m ->
            m "error %a listening on private network" N.pp_error e)
    | Ok () -> Logs.info (fun m -> m "listening on private network finished")

  (* packets received over the tunnel *)
  let rec ovpn_recv t private_ip =
    O.read t.ovpn >>= fun datas ->
    let ts = M.elapsed_ns () in
    Lwt_list.fold_left_s
      (fun c data ->
        match Ipv4_packet.Unmarshal.of_cstruct data with
        | Ok (hdr, payload) ->
            let c, pkt = Fragments.process c ts hdr payload in
            (match pkt with
            | None -> ()
            | Some (hdr, payload) ->
              match t.nat with
              | Some table ->
                (match Nat.of_ipv4 hdr payload with
                 | None -> ()
                 | Some packet ->
                   match Mirage_nat_lru.translate table packet with
                   | Ok packet ->
                     Lwt.async (fun () -> Nat.output_private t packet)
                   | Error e ->
                     (* TODO should return ICMP error *)
                     let msg =
                       match e with
                       | `TTL_exceeded -> "ttl exceeded"
                       | `Untranslated -> "no match"
                     in
                     Logs.warn (fun m -> m "error when translating %s" msg))
              | None ->
                if local_network private_ip hdr.Ipv4_packet.dst then
                  match Ipv4_packet.(Unmarshal.int_to_protocol hdr.proto) with
                  | None ->
                      Logs.warn (fun m ->
                          m "ignoring %a (cannot decode IP protocol number)"
                            Ipv4_packet.pp hdr)
                  | Some proto -> (
                      match
                        forward_or_reject hdr payload
                          (I.mtu t.private_ip ~dst:hdr.Ipv4_packet.dst)
                      with
                      | Ok hdr ->
                          Lwt.async (fun () ->
                              (* The IPv4.write here takes care of fragmenting the packet*)
                              I.write t.private_ip ~ttl:hdr.Ipv4_packet.ttl
                                ~src:hdr.Ipv4_packet.src hdr.Ipv4_packet.dst
                                proto
                                (fun _ -> 0)
                                [ payload ]
                              >|= function
                              | Ok () -> ()
                              | Error _e ->
                                  (* could send back host unreachable if this was an arp timeout *)
                                  (* Logs.err (fun m -> m "error %a while forwarding %a"
                                                 I.pp_error e Ipv4_packet.pp hdr)) *)
                                  ())
                      | Error (`Icmp pay) ->
                          (* send icmp error back via ovpn *)
                          let hdr =
                            {
                              hdr with
                              Ipv4_packet.ttl = 255;
                              src = Ipaddr.V4.Prefix.address (List.hd (I.configured_ips t.private_ip));
                              (* or which ip should be used? *)
                              dst = hdr.Ipv4_packet.src;
                              proto = Ipv4_packet.Marshal.protocol_to_int `ICMP;
                            }
                          in
                          let payload_len = Cstruct.length pay in
                          let hdr_cs =
                            Ipv4_packet.Marshal.make_cstruct ~payload_len hdr
                          in
                          Lwt.async (fun () ->
                              O.write t.ovpn (Cstruct.append hdr_cs pay)
                              >|= fun _ -> ())
                      | Error `Drop -> ())
                else
                  (* Logs.warn (fun m -> m "ignoring %a (IPv4 packet received via the tunnel, which destination is not our network %a)"
                                Ipv4_packet.pp hdr Ipaddr.V4.Prefix.pp private_ip)) *)
                  ());
            Lwt.return c
        | Error msg ->
            Logs.err (fun m ->
                m "failed to decode ipv4 packet %s: %a" msg Cstruct.hexdump_pp
                  data);
            Lwt.return c)
      t.ovpn_fragments datas
    >>= fun frags ->
    t.ovpn_fragments <- frags;
    ovpn_recv t private_ip

  let start _ _ _ _ s net eth arp ip block =
    (* TODO maybe rename private to local? *)
    (let open Lwt_result.Infix in
     read_config block >>= fun config ->
     let nat =
       if K.nat () then
         let icmp_size = K.nat_table_size () / 100 in
         let tcp_size = (K.nat_table_size () - icmp_size) / 2 in
         Logs.info (fun m -> m "Using NAT with %u ICMP, %u TCP, and %u UDP entries"
                       icmp_size tcp_size tcp_size);
         Some (Mirage_nat_lru.empty ~tcp_size ~udp_size:tcp_size ~icmp_size)
       else (
         Logs.info (fun m -> m "Not using NAT");
         None)
     in
     O.connect config s >>= fun ovpn ->
     Logs.info (fun m -> m "tunnel established");
     let t =
       {
         nat;
         ovpn;
         ovpn_fragments = Fragments.Cache.empty (256 * 1024);
         private_ip = ip;
         private_fragments = Fragments.Cache.empty (256 * 1024);
       }
     in
     let private_ip = List.hd (I.configured_ips ip) in
     Lwt_result.ok (Lwt.join
                      [ ovpn_recv t private_ip;
                        private_recv t private_ip net eth arp ]))
    >|= function
    | Ok () -> Logs.warn (fun m -> m "unikernel finished without error...")
    | Error (`Msg e) -> Logs.err (fun m -> m "error %s" e)
end
