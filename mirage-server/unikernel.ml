open Lwt.Infix

module K = struct
  open Cmdliner

  let ipv4 =
    Mirage_runtime_network.V4.network (Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24")

  let ipv4_gateway =
    Mirage_runtime_network.V4.gateway None

  let ipv4_only = Mirage_runtime_network.ipv4_only ()

  let ipv6_only = Mirage_runtime_network.ipv6_only ()

  let nat_table_size =
    let doc = Arg.info ~doc:"The size of the NAT table (n/100 -> ICMP, n/2 -> TCP, n/2 -> UDP)." ["nat-table-size"] in
    Arg.(value & opt int 2048 doc)
end

module Main
    (R : Mirage_random.S)
    (M : Mirage_clock.MCLOCK)
    (P : Mirage_clock.PCLOCK)
    (T : Mirage_time.S)
    (N : Mirage_net.S)
    (E : Ethernet.S)
    (A : Arp.S)
    (IPV6 : Tcpip.Ip.S with type ipaddr = Ipaddr.V6.t and type prefix = Ipaddr.V6.Prefix.t)
    (B : Mirage_block.S) =
struct

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
  end

  let is_listening_port_proto config proto port =
    let cfg_proto = ((snd (Miragevpn.proto config)) :> [ `Tcp | `Udp | `Icmp ])
    and cfg_port = Miragevpn.server_bind_port config
    in
    proto = cfg_proto && port = cfg_port

  (* construct a stack and divert packets to NAT that are not the listening port *)
  module Ipv4 = struct
    module I = Static_ipv4.Make (R) (M) (E) (A)

    type t = I.t * Mirage_nat_lru.t * Miragevpn.Config.t
    type error = I.error
    type ipaddr = I.ipaddr
    type prefix = I.prefix
    type callback = I.callback

    let pp_error = I.pp_error
    let pp_ipaddr = I.pp_ipaddr
    let pp_prefix = I.pp_prefix

    let disconnect (t, table, _) =
      Mirage_nat_lru.reset table;
      I.disconnect t

    let write (t, _, _) = I.write t

    let pseudoheader (t, _, _) = I.pseudoheader t

    let src (t, _, _) = I.src t

    [@@@alert "-deprecated"]
    let get_ip (t, _, _) = I.get_ip t
    [@@@alert "+deprecated"]

    let configured_ips (t, _, _) = I.configured_ips t

    let mtu (t, _, _) = I.mtu t

    let _write = ref (fun _ _ -> Lwt.return_unit)

    let input (ipv4_stack, table, config) ~tcp ~udp ~default buf =
      match Ipv4_packet.Unmarshal.of_cstruct buf with
      | Error _ ->
        Lwt.return_unit
      | Ok (hdr, payload) ->
        match Nat.of_ipv4 hdr payload with
        | None -> Lwt.return_unit
        | Some pkt ->
          let port, proto = match pkt with
            | `IPv4 (_, `TCP (tcp_hdr, _)) -> tcp_hdr.dst_port, `Tcp
            | `IPv4 (_, `UDP (udp_hdr, _)) -> udp_hdr.dst_port, `Udp
            | `IPv4 (_, `ICMP (_, _)) -> 0, `Icmp
          in
          if is_listening_port_proto config proto port then
            I.input ipv4_stack ~tcp ~udp ~default buf
          else
            match Mirage_nat_lru.translate table pkt with
            | Ok packet ->
              begin
              match Nat.payload_to_buf packet with
              | Ok (buf, _proto, ip_hdr) ->
                let pkt = Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.length buf) ip_hdr in
                !_write ip_hdr.dst (Cstruct.append pkt buf)
              | Error () -> Lwt.return_unit
            end
            | Error e ->
              (* TODO should return ICMP error *)
              let msg =
                match e with
                  | `TTL_exceeded -> "ttl exceeded"
                  | `Untranslated -> "no match"
              in
              Logs.warn (fun m -> m "error when translating %s" msg);
              Lwt.return_unit

    let inject_write write = _write := write

    let connect ?no_init ~cidr ?gateway ?fragment_cache_size eth arp table config =
      I.connect ?no_init ~cidr ?gateway ?fragment_cache_size eth arp >|= fun stack ->
      (stack, table, config)
  end

  module IPV4V6 = Tcpip_stack_direct.IPV4V6(Ipv4)(IPV6)
  module ICMP = Icmpv4.Make(Ipv4)
  module UDP = Udp.Make(IPV4V6)(R)
  module TCP = Tcp.Flow.Make(IPV4V6)(T)(M)(R)

  module S = Tcpip_stack_direct.MakeV4V6(T)(R)(N)(E)(A)(IPV4V6)(ICMP)(UDP)(TCP)

  module O = Miragevpn_mirage.Server (R) (M) (P) (T) (S)

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
      (Miragevpn.Config.parse_server ~string_of_file (Cstruct.to_string config))

  let find_free_port config protocol =
    let rec free () =
      let port = Randomconv.int16 R.generate in
      if is_listening_port_proto config protocol port then free ()
      else
         Some port
    in
    free

  let payloadv4_from_tunnel config table s ip_hdr payload =
    (* TODO: (a) fragmentation processing (b) should_be_routed / send errors back to client *)
    (* apply NAT *)
    match Nat.of_ipv4 ip_hdr payload with
    | None -> Lwt.return_unit
    | Some packet ->
      let packet =
        match Mirage_nat_lru.translate table packet with
        | Ok packet -> Some packet
        | Error `Untranslated ->
begin
      let public_ip =
        match S.IP.src (S.ip s) ~dst:(Ipaddr.V4 ip_hdr.dst) with
        | Ipaddr.V4 ip -> ip
        | Ipaddr.V6 _ -> assert false
      in
      let ip_proto = match packet with `IPv4 (_, `TCP _) -> `Tcp | `IPv4 (_, `UDP _) -> `Udp | `IPv4 (_, `ICMP _) -> `Icmp
      in
      match
        Mirage_nat_lru.add table packet public_ip (find_free_port config ip_proto) `NAT
      with
      | Error e ->
        Logs.debug (fun m ->
            m "Failed to add a NAT rule: %a" Mirage_nat.pp_error e);
        None
      | Ok () ->
        match Mirage_nat_lru.translate table packet with
        | Ok packet -> Some packet
        | Error `Untranslated ->
          Logs.warn (fun m -> m "can't translate packet, giving up");
          None
        | Error `TTL_exceeded ->
          (* TODO should report ICMP error message to src *)
          Logs.warn (fun f -> f "TTL exceeded");
          None
    end
        | Error `TTL_exceeded ->
          (* TODO should report ICMP error message to src *)
          Logs.warn (fun f -> f "TTL exceeded");
          None
      in
      match packet with
      | None -> Lwt.return_unit
      | Some packet ->
        match Nat.payload_to_buf packet with
        | Error () -> Lwt.return_unit
        | Ok (payload, proto, ip_hdr) ->
    (* send over stack *)
    S.IP.write (S.ip s) (Ipaddr.V4 ip_hdr.Ipv4_packet.dst) proto (fun _buf -> 0) [ payload ] >|= function
    | Ok () -> ()
    | Error e -> Logs.warn (fun m -> m "error %a when sending data received over tunnel"
                               S.IP.pp_error e)

  let start _ _ _ _ net eth arp ipv6 block ipv4 ipv4_gateway ipv4_only ipv6_only nat_table_size =
    read_config block >>= function
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "error while reading config %s" msg);
        failwith "config file error"
    | Ok config ->
        let table =
          let icmp_size = nat_table_size / 100 in
          let tcp_size = (nat_table_size - icmp_size) / 2 in
          Logs.info (fun m -> m "Using NAT with %u ICMP, %u TCP, and %u UDP entries"
                        icmp_size tcp_size tcp_size);
          Mirage_nat_lru.empty ~tcp_size ~udp_size:tcp_size ~icmp_size
        in
        Ipv4.connect ~no_init:ipv6_only ~cidr:ipv4 ?gateway:ipv4_gateway eth arp table config >>= fun ipv4 ->
        IPV4V6.connect ~ipv4_only ~ipv6_only ipv4 ipv6 >>= fun ip ->
        ICMP.connect ipv4 >>= fun icmp ->
        UDP.connect ip >>= fun udp ->
        TCP.connect ip >>= fun tcp ->
        S.connect net eth arp ip icmp udp tcp >>= fun stack ->
        let payloadv4_from_tunnel = payloadv4_from_tunnel config table stack in
        let t = O.connect ~payloadv4_from_tunnel config stack in
        Ipv4.inject_write (O.write t);
        let task, _u = Lwt.task () in
        task
end
