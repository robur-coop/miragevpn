(* synopsis: openvpn-connected stack that sends OpenVPN pings. *)

(* similar to the lwt-client, but via mirage *)

(* this does not implement the design-data-flow, but hardcodes usage of the
   "internal stack" (i.e. no forwarding and second ethernet interface!) *)

open Lwt.Infix

module Main (R : Mirage_random.C) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) (FS: Mirage_kv_lwt.RO) = struct

  module O = Openvpn_mirage.Make(R)(M)(P)(T)(S)

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
      let open Rresult.R.Infix in
      let string_of_file _ = Error (`Msg "not supported") in
      Openvpn_config.parse ~string_of_file data >>= fun config ->
      Openvpn_config.is_valid_client_config config >>| fun () ->
      config

  let start _ _ _ _ s data _ =
    (let open Lwt_result.Infix in
     read_config data >>= fun config ->
     O.connect config s) >>= function
    | Ok (t, reader) ->
      Logs.info (fun m -> m "tunnel established");
      reader t
    | Error e ->
      Logs.err (fun m -> m "error %a" O.pp_error e);
      Lwt.return_unit

  (*
      (* if there's payload, parse: if ipv4 and icmp echo request, reply! *)
      Lwt_list.iter_s (fun pkt ->
            match Ipv4_packet.Unmarshal.of_cstruct pkt with
            | Ok (iphdr, payload) when
                iphdr.Ipv4_packet.proto = Ipv4_packet.Marshal.protocol_to_int `ICMP &&
                Ipaddr.V4.compare iphdr.Ipv4_packet.dst ip_cfg.Openvpn.ip = 0 ->
              begin match Icmpv4_packet.Unmarshal.of_cstruct payload with
                | Ok (icmphdr, payload) when
                    icmphdr.Icmpv4_packet.code = 0 && icmphdr.Icmpv4_packet.ty = Icmpv4_wire.Echo_request ->
                  Logs.info (fun m -> m "received ICMP echo request from %a, replying" Ipaddr.V4.pp iphdr.Ipv4_packet.src);
                  let icmp = { Icmpv4_packet.code = 0x00 ; ty = Icmpv4_wire.Echo_reply ; subheader = icmphdr.Icmpv4_packet.subheader } in
                  let ip = { Ipv4_packet.src = ip_cfg.Openvpn.ip ; dst = iphdr.Ipv4_packet.src ;
                             id = 0 ; off = 0 ; ttl = 42 ; proto = iphdr.Ipv4_packet.proto ;
                             options = Cstruct.empty }
                  in
                  let icmp_buf = Icmpv4_packet.Marshal.make_cstruct ~payload icmp in
                  let ip_buf = Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len icmp_buf + Cstruct.len payload) ip in
                  let buf = Cstruct.concat [ ip_buf ; icmp_buf ; payload ] in
                  begin match Openvpn.outgoing !ovpn (ts ()) buf with
                    | Error `Not_ready -> assert false
                    | Ok (ovpn', outs) ->
                      ovpn := ovpn' ;
                      send_multiple flow outs >|= fun _ -> ()
                  end
                | Ok (icmp, _) ->
                  Logs.warn (fun m -> m "received non echo-request ICMP frame %a" Icmpv4_packet.pp icmp);
                  Lwt.return_unit
                | Error e ->
                  Logs.warn (fun m -> m "parse error while parsing icmp %s" e);
                  Lwt.return_unit
              end
            | Ok (ip, _) -> Logs.warn (fun m -> m "received non-ICMP IPv4 frame %a" Ipv4_packet.pp ip); Lwt.return_unit
            | Error e -> Logs.warn (fun m -> m "parse error while parsing ip frame %s" e); Lwt.return_unit)
      app *)
end
