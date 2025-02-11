open Lwt.Syntax

(* NOTE: copied from mirage/miragevpn_mirage.ml Server functor - please
   carefully contribute back changes there *)
type t = {
  config : Miragevpn.Config.t;
  server : Miragevpn.server;
  ip : Ipaddr.V4.t * Ipaddr.V4.Prefix.t;
  connections : (Ipaddr.V4.t, Lwt_unix.file_descr * Miragevpn.t ref) Hashtbl.t;
  test : bool;
}

let pp_dst ppf (dst, port) = Fmt.pf ppf "%a:%u" Ipaddr.pp dst port

let write t dst cs =
  let open Lwt.Infix in
  match Hashtbl.find_opt t.connections dst with
  | None ->
      Logs.err (fun m -> m "destination %a not found in map" Ipaddr.V4.pp dst);
      Lwt.return_unit
  | Some (fd, state) -> (
      match Miragevpn.outgoing !state cs with
      | Error `Not_ready ->
          Logs.err (fun m ->
              m "error not_ready while writing to %a" Ipaddr.V4.pp dst);
          Lwt.return_unit
      | Ok (state', enc) -> (
          state := state';
          Common.write_to_fd fd enc >|= function
          | Error (`Msg msg) ->
              Logs.err (fun m ->
                  m "%a tcp write failed %s" Ipaddr.V4.pp dst msg);
              Hashtbl.remove t.connections dst
          | Ok () -> ()))

let _received_ping = ref 0

let handle_payload t dst source_ip data =
  match Ipv4_packet.Unmarshal.of_cstruct (Cstruct.of_string data) with
  | Error e ->
      Logs.warn (fun m ->
          m "%a received payload (error %s) %a" pp_dst dst e
            (Ohex.pp_hexdump ()) data);
      Lwt.return_unit
  | Ok (ip, _) when Ipaddr.V4.compare ip.Ipv4_packet.src source_ip <> 0 ->
      Logs.warn (fun m ->
          m "%a received payload where source ip %a doesn't match expected %a"
            pp_dst dst Ipaddr.V4.pp ip.Ipv4_packet.src Ipaddr.V4.pp source_ip);
      Lwt.return_unit
  | Ok (ip, _)
    when Ipaddr.V4.(
           compare (Prefix.broadcast (snd t.ip)) ip.Ipv4_packet.dst = 0)
         || Ipaddr.V4.(compare broadcast ip.Ipv4_packet.dst = 0)
         || Ipaddr.V4.is_multicast ip.Ipv4_packet.dst ->
      Logs.warn (fun m ->
          m "%a received multicast or broadcast packet, ignoring %a" pp_dst dst
            Ipv4_packet.pp ip);
      Lwt.return_unit
  | Ok (ip, payload)
    when ip.Ipv4_packet.proto = Ipv4_packet.Marshal.protocol_to_int `ICMP
         && Ipaddr.V4.compare ip.Ipv4_packet.dst (fst t.ip) = 0 -> (
      match Icmpv4_packet.Unmarshal.of_cstruct payload with
      | Ok (({ ty = Icmpv4_wire.Echo_request; _ } as icmp), payload) ->
          (* XXX(reynir): also check code = 0?! *)
          incr _received_ping;
          let* () =
            let reply = { icmp with Icmpv4_packet.ty = Icmpv4_wire.Echo_reply }
            and ip' = { ip with src = ip.dst; dst = ip.src } in
            let data =
              Cstruct.append
                (Icmpv4_packet.Marshal.make_cstruct ~payload reply)
                payload
            in
            let hdr =
              Ipv4_packet.Marshal.make_cstruct
                ~payload_len:(Cstruct.length data) ip'
            in
            write t ip.src (Cstruct.to_string (Cstruct.append hdr data))
          in
          if t.test && !_received_ping > 2 then (
            Logs.app (fun m ->
                m "Received echo request from %a" Ipaddr.V4.pp source_ip);
            let client_fd, client = Hashtbl.find t.connections source_ip in
            match Miragevpn.send_control_message !client "HALT" with
            | Error `Not_ready ->
                Logs.warn (fun m -> m "Failed to send HALT to client");
                exit 0
            | Ok (client', datas) ->
                Logs.app (fun m -> m "Sending HALT to client");
                client := client';
                let* () =
                  Lwt_list.iter_s
                    (fun data ->
                      let+ _ = Common.write_to_fd client_fd data in
                      ())
                    datas
                in
                exit 0)
          else Lwt.return_unit
      | Ok (icmp, _payload) ->
          Logs.warn (fun m ->
              m "ignoring icmp frame from %a: %a" Ipaddr.V4.pp ip.src
                Icmpv4_packet.pp icmp);
          Lwt.return_unit
      | Error e ->
          Logs.warn (fun m ->
              m "ignoring icmp frame from %a, decoding error %s" Ipaddr.V4.pp
                ip.src e);
          Lwt.return_unit)
  | Ok (ip, _)
    when Miragevpn.Config.mem Client_to_client t.config
         && Ipaddr.V4.Prefix.mem ip.Ipv4_packet.dst (snd t.ip) ->
      (* local routing *)
      let dst = ip.Ipv4_packet.dst in
      if Hashtbl.mem t.connections dst then write t dst data
      else
        let reply =
          Icmpv4_packet.
            {
              ty = Icmpv4_wire.Destination_unreachable;
              code = 1;
              subheader = Unused;
            }
        and ip' = { ip with src = fst t.ip; dst = ip.src } in
        let payload =
          Cstruct.of_string data ~len:(min 28 (String.length data))
        in
        let data =
          Cstruct.append
            (Icmpv4_packet.Marshal.make_cstruct ~payload reply)
            payload
        in
        let hdr =
          Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.length data)
            ip'
        in
        write t ip.src (Cstruct.to_string (Cstruct.append hdr data))
  | Ok (ip, _) ->
      Logs.warn (fun m -> m "ignoring ipv4 frame %a" Ipv4_packet.pp ip);
      Lwt.return_unit

let rec timer server () =
  let open Lwt.Infix in
  (* foreach connection, call handle `Tick and follow instructions! *)
  Hashtbl.fold
    (fun k (fd, t) acc ->
      acc >>= fun acc ->
      match Miragevpn.handle !t `Tick with
      | Error e ->
          Logs.err (fun m -> m "error in timer %a" Miragevpn.pp_error e);
          Lwt.return (k :: acc)
      | Ok (_t', _out, _payloads, Some `Exit) ->
          (* TODO anything to do with "_out" or "_payloads"? *)
          Logs.warn (fun m -> m "exiting %a" Ipaddr.V4.pp k);
          Lwt.return (k :: acc)
      | Ok (t', out, payloads, act) -> (
          (* TODO anything to do with "_act"? (apart from exit) *)
          Option.iter
            (fun a ->
              Logs.warn (fun m ->
                  m "in timer, ignoring action %a" Miragevpn.pp_action a))
            act;
          t := t';
          let dst =
            match Lwt_unix.getsockname fd with
            | Lwt_unix.ADDR_UNIX _ -> assert false
            | Lwt_unix.ADDR_INET (ip, port) ->
                (Ipaddr_unix.of_inet_addr ip, port)
          in
          Lwt_list.iter_p (handle_payload server dst k) payloads >>= fun () ->
          Lwt_list.fold_left_s
            (fun r o ->
              match r with
              | Error _ as e -> Lwt.return e
              | Ok () -> (
                  Common.write_to_fd fd o >|= function
                  | Error (`Msg msg) ->
                      Logs.err (fun m ->
                          m "%a TCP write failed %s" Ipaddr.V4.pp k msg);
                      Error ()
                  | Ok () -> Ok ()))
            (Ok ()) out
          >|= function
          | Error () -> k :: acc
          | Ok () -> acc))
    server.connections (Lwt.return [])
  >>= fun to_remove ->
  List.iter (Hashtbl.remove server.connections) to_remove;
  Lwt_unix.sleep 1. >>= fun () -> timer server ()

let handle_action dst add rm ip action =
  match action with
  | `Established ({ Miragevpn.cidr; _ }, _, _) ->
      Logs.info (fun m ->
          m "%a insert ip %a, registering flow" pp_dst dst Ipaddr.V4.Prefix.pp
            cidr);
      let ip = Ipaddr.V4.Prefix.address cidr in
      add ip;
      (Some ip, `Continue)
  | `Exit ->
      rm ();
      Logs.info (fun m -> m "%a exiting" pp_dst dst);
      (None, `Stop)
  | a ->
      Logs.warn (fun m ->
          m "%a ignoring action %a" pp_dst dst Miragevpn.pp_action a);
      (ip, `Continue)

let callback t fd =
  let open Lwt.Infix in
  let dst =
    match Lwt_unix.getsockname fd with
    | Lwt_unix.ADDR_UNIX _ -> assert false
    | Lwt_unix.ADDR_INET (ip, port) -> (Ipaddr_unix.of_inet_addr ip, port)
  in
  let rm = function
    | None -> ()
    | Some ip ->
        Logs.info (fun m ->
            m "%a removing ip %a from connections" pp_dst dst Ipaddr.V4.pp ip);
        Hashtbl.remove t.connections ip
  and add client_state ip =
    Hashtbl.replace t.connections ip (fd, client_state)
  in
  let rec read ?ip client_state =
    Common.read_from_fd fd >>= function
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "%a error %s while reading" pp_dst dst msg);
        rm ip;
        Common.safe_close fd
    | Ok data -> (
        match Miragevpn.handle !client_state (`Data data) with
        | Error msg ->
            Logs.err (fun m ->
                m "%a internal miragevpn error %a" pp_dst dst Miragevpn.pp_error
                  msg);
            rm ip;
            Common.safe_close fd
        | Ok (s', out, payloads, action) ->
            client_state := s';
            handle ?ip client_state out payloads action)
  and handle ?ip client_state out payloads action =
    let ip, continue_or_stop =
      match action with
      | None -> (ip, `Continue)
      | Some action ->
          handle_action dst (add client_state) (fun () -> rm ip) ip action
    in
    (* Do not handle payloads from client that have not yet been
       assigned an ip address *)
    (match ip with
    | None ->
        if payloads <> [] then
          Logs.warn (fun m ->
              m "%a ignoring %u premature payloads" pp_dst dst
                (List.length payloads));
        Lwt.return_unit
    | Some ip -> Lwt_list.iter_p (handle_payload t dst ip) payloads)
    >>= fun () ->
    Lwt_list.fold_left_s
      (fun r o ->
        match r with
        | Error _ as e -> Lwt.return e
        | Ok () -> (
            Common.write_to_fd fd o >|= function
            | Error (`Msg msg) ->
                Logs.err (fun m -> m "%a TCP write failed %s" pp_dst dst msg);
                Error ()
            | Ok () -> Ok ()))
      (Ok ()) out
    >>= function
    | Error () ->
        rm ip;
        Common.safe_close fd
    | Ok () -> (
        match continue_or_stop with
        | `Stop -> Common.safe_close fd
        | `Continue -> read ?ip client_state)
  in
  Common.read_from_fd fd >>= function
  | Error (`Msg msg) ->
      Logs.warn (fun m ->
          m "error reading first packet from %a: %s" pp_dst dst msg);
      Common.safe_close fd
  | Ok data -> (
      match Miragevpn.new_connection t.server data with
      | Error e ->
          Logs.warn (fun m ->
              m "couldn't initiate the connection %a" Miragevpn.pp_error e);
          Common.safe_close fd
      | Ok (t, out, payloads, action) ->
          let client_state = ref t in
          handle client_state out payloads action)

let connect config test =
  let open Lwt.Infix in
  let connections = Hashtbl.create 7 in
  let is_not_taken ip = not (Hashtbl.mem connections ip) in
  match Miragevpn.server ~really_no_authentication:true ~is_not_taken config with
  | Error (`Msg msg) ->
      Logs.err (fun m -> m "server construction failed %s" msg);
      assert false
  | Ok (server, ip, port) ->
      Logs.info (fun m ->
          m "miragevpn server listening on port %d, using %a/%d" port
            Ipaddr.V4.pp (fst ip)
            (Ipaddr.V4.Prefix.bits (snd ip)));
      let server = { config; server; ip; connections; test } in
      let fd = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
      Lwt_unix.(setsockopt fd SO_REUSEADDR true);
      Lwt_unix.(setsockopt fd IPV6_ONLY false);
      let addr =
        Lwt_unix.ADDR_INET
          (Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified, port)
      in
      Lwt_unix.bind fd addr >>= fun () ->
      Lwt_unix.listen fd 10;
      Lwt.async (timer server);
      let rec accept () =
        Lwt_unix.accept fd >>= fun (cfd, _) ->
        Lwt.async (fun () -> callback server cfd);
        accept ()
      in
      accept ()

let parse_config filename =
  Lwt.return
  @@
  let dir, filename = Filename.(dirname filename, basename filename) in
  let string_of_file = Common.string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> Miragevpn.Config.parse_server ~string_of_file str
  | Error _ as e -> e

let jump _ filename test =
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    (let* config = parse_config filename in
     match config with
     | Error (`Msg s) -> Lwt.return (Error (`Msg ("config parser: " ^ s)))
     | Ok config -> connect config test)

open Cmdliner

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let test =
  let doc = "Testing mode: exit with exit code 0 upon receiving echo request" in
  Arg.(value & flag & info [ "test" ] ~doc)

let cmd =
  let term = Term.(term_result (const jump $ Common.setup_log $ config $ test))
  and info = Cmd.info "miragevpn_server_notun" ~version:"%%VERSION_NUM%%" in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
