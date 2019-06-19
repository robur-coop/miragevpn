(* synopsis: openvpn-connected host that sends ICMP echo requests to
   a remote host, by default nqsb.io 198.167.222.201, over the established
   connection. *)

(* similar to the lwt-client, but via mirage *)

(* this does not implement the design-data-flow, but hardcodes usage of the
   "internal stack" (i.e. no forwarding and second ethernet interface!) *)

open Lwt.Infix

module Main (R : Mirage_random.C) (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (S : Mirage_stack_lwt.V4) (FS: Mirage_kv_lwt.RO) = struct

  module DNS = Dns_mirage_client.Make(S)
  module TCP = S.TCPV4

  let read_config data =
    FS.get data (Mirage_kv.Key.v "openvpn.config") >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:FS.pp_error (Error e)
    | Ok data ->
      let open Rresult.R.Infix in
      let string_of_file _ = Error (`Msg "not supported") in
      Openvpn_config.parse ~string_of_file data >>= fun config ->
      Openvpn_config.is_valid_client_config config >>| fun () ->
      config

  let now () = Ptime.v (P.now_d_ps ())

  let ts () = M.elapsed_ns ()

  let send_multiple flow outs =
    Lwt_list.fold_left_s (fun acc x -> match acc with
        | Ok () -> TCP.write flow x
        | Error e -> Lwt.return (Error e))
      (Ok ()) outs >|= function
    | Error e -> Rresult.R.error_to_msg ~pp_error:TCP.pp_write_error (Error e)
    | Ok () -> Ok ()

  let start _ _ _ s data _ =
    (let open Lwt_result.Infix in
     read_config data >>= fun config ->
     (Lwt_result.lift Rresult.R.(of_option ~none:(fun () -> error_msg "no remote")
                                   Openvpn_config.(find Remote config)) >>= function
      | (`IP (Ipaddr.V4 ip), port) :: _ -> Lwt.return (Ok (ip, port))
      | (`Domain name, port) :: _ ->
        begin
          let res = DNS.create s in
          DNS.gethostbyname res name >|= fun ip ->
          (ip,port)
        end
      | (`IP (Ipaddr.V6 _), _) :: _ -> Lwt.return (Error (`Msg "V6 not supported"))
      | [] -> Lwt.return (Error (`Msg "no remote"))) >>= fun remote ->
     Logs.info (fun m -> m "connecting to %a" Fmt.(pair ~sep:(unit ":") Ipaddr.V4.pp int) remote);
     Lwt_result.lift (Openvpn.client config (now ()) (ts ()) R.generate ()) >>= fun (state, out) ->
     let ovpn = ref state in
     let open Lwt.Infix in
     TCP.create_connection (S.tcpv4 s) remote >>= function
     | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_error (Error e))
     | Ok flow -> TCP.write flow out >>= function
       | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_write_error (Error e))
       | Ok () ->
         let rec ping () =
           let ovpn', out = Openvpn.timer !ovpn (ts ()) in
           ovpn := ovpn' ;
           send_multiple flow out >>= fun _ ->
           OS.Time.sleep_ns (Duration.of_sec 1) >>=
           ping
         in
         Lwt.async ping ;
         let rec loop : unit -> (unit, [> `Msg of string ]) result Lwt.t = fun () ->
           TCP.read flow >>= function
           | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_error (Error e))
           | Ok `Eof -> Lwt.return (Error (`Msg "end of file from server"))
           | Ok (`Data b) ->
             match Openvpn.(incoming !ovpn (now ()) (ts ()) b) with
             | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:Openvpn.pp_error (Error e))
             | Ok (ovpn', outs, app) ->
               ovpn := ovpn' ;
               let open Lwt_result.Infix in
               send_multiple flow outs >>= fun () ->
               let open Lwt.Infix in
               match Openvpn.ready !ovpn with
               | None -> loop ()
               | Some ip_cfg ->
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
                   app >>= loop
         in
         loop ()) >|= function
    | Ok () -> ()
    | Error (`Msg msg) -> Logs.err (fun m -> m "error %s" msg)
end
