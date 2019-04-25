(* synopsis: openvpn-connected host that sends ICMP echo requests to
   a remote host, by default nqsb.io 198.167.222.201, over the established
   connection. *)

(* similar to the lwt-client, but via mirage *)

(* this does not implement the design-data-flow, but hardcodes usage of the
   "internal stack" (i.e. no forwarding and second ethernet interface!) *)

open Lwt.Infix

module Main (R : Mirage_random.C) (P : Mirage_clock.PCLOCK) (S : Mirage_stack_lwt.V4) (FS: Mirage_kv_lwt.RO) = struct

  module DNS = Udns_mirage_client.Make(S)
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

  let start _ _ s data _ =
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
     Lwt_result.lift (Openvpn.client config (now ()) R.generate ()) >>= fun (state, out) ->
     let ovpn = ref state in
     let open Lwt.Infix in
     TCP.create_connection (S.tcpv4 s) remote >>= function
     | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_error (Error e))
     | Ok flow -> TCP.write flow out >>= function
       | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_write_error (Error e))
       | Ok () ->
         let seq = ref 0 in
         let rec loop () =
           (TCP.read flow >>= function
             | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_error (Error e))
             | Ok `Eof -> Lwt.return (Error (`Msg "end of file from server"))
             | Ok (`Data b) ->
               Logs.info (fun m -> m "received data %d %a" (Cstruct.len b) Cstruct.hexdump_pp b);
               match Openvpn.(Rresult.R.error_to_msg ~pp_error (incoming !ovpn (now ()) b)) with
               | Error e -> Lwt.return (Error e)
               | Ok (ovpn', outs, app) ->
                 ovpn := ovpn' ;
                 List.iter (fun data ->
                     Logs.info (fun m -> m "received OpenVPN payload:@.%a"
                                   Cstruct.hexdump_pp data))
                   app ;
                 Lwt_list.fold_left_s (fun acc x -> match acc with
                   | Ok () -> TCP.write flow x
                   | Error e -> Lwt.return (Error e))
                   (Ok ()) outs >>= function
                 | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_write_error (Error e))
                 | Ok () ->
                   match Openvpn.ready !ovpn with
                   | Some ip_config ->
                     Logs.info (fun m -> m "openvpn is ready, sending a ping");
                     let payload = R.generate 10 in
                     let ping =
                       { Icmpv4_packet.code = 0 ; ty = Icmpv4_wire.Echo_request ;
                         subheader = Id_and_seq (0, !seq) }
                     in
                     Logs.info (fun m -> m "sending ping %a" Icmpv4_packet.pp ping);
                     let icmp_buf = Icmpv4_packet.Marshal.make_cstruct ~payload ping in
                     incr seq;
                     let ip =
                         { Ipv4_packet.src = ip_config.Openvpn.ip ; dst = Ipaddr.V4.of_string_exn "198.167.222.201" ;
                           id = 0 ; off = 0 ; ttl = 34 ; proto = 1 ; options = Cstruct.empty }
                     in
                     Logs.info (fun m -> m "ip header %a" Ipv4_packet.pp ip);
                     let ip_buf = Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len icmp_buf) ip in
                     let buf = Cstruct.append ip_buf icmp_buf in
                     (Lwt_result.lift (Openvpn.outgoing !ovpn buf) >>= function
                       | Error `Not_ready -> Lwt.return (Error (`Msg "not ready yet"))
                       | Ok (ovpn', outs) ->
                         ovpn := ovpn';
                         Lwt_list.fold_left_s (fun acc x -> match acc with
                             | Ok () -> TCP.write flow x
                             | Error e -> Lwt.return (Error e))
                           (Ok ()) outs >>= function
                         | Error e -> Lwt.return (Rresult.R.error_to_msg ~pp_error:TCP.pp_write_error (Error e))
                         | Ok () -> Lwt.return (Ok ()))
                   | None -> Lwt.return (Ok ())) >>= function
           | Error e -> Lwt.return (Error e)
           | Ok () -> loop ()
         in
         loop ()) >>= function
    | Ok () -> Lwt.return_unit | Error (`Msg m) -> Lwt.fail_with m

end
