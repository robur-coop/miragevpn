open Lwt.Syntax
module IPM = Map.Make (Ipaddr.V4)

type t = {
  server : Miragevpn.server;
  ip : Ipaddr.V4.t * Ipaddr.V4.Prefix.t;
  mutable connections : (Lwt_unix.file_descr * Miragevpn.t ref) IPM.t;
}

let pp_dst ppf (dst, port) = Fmt.pf ppf "%a:%u" Ipaddr.V4.pp dst port

let write t dst cs =
  let open Lwt.Infix in
  match IPM.find_opt dst t.connections with
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
          (* TODO fragmentation!? *)
          state := state';
          Common.write_to_fd fd enc >|= function
          | Error (`Msg msg) ->
              Logs.err (fun m ->
                  m "%a tcp write failed %s" Ipaddr.V4.pp dst msg);
              t.connections <- IPM.remove dst t.connections
          | Ok () -> ()))

let handle_payload t dst data =
  match Ipv4_packet.Unmarshal.of_cstruct data with
  | Error e ->
      Logs.warn (fun m ->
          m "%a received payload (error %s) %a" Ipaddr.V4.pp dst e
            Cstruct.hexdump_pp data);
      Lwt.return_unit
  | Ok (ip, payload)
    when ip.Ipv4_packet.proto = Ipv4_packet.Marshal.protocol_to_int `ICMP
         && Ipaddr.V4.compare ip.Ipv4_packet.dst (fst t.ip) = 0 -> (
      match Icmpv4_packet.Unmarshal.of_cstruct payload with
      | Ok (({ ty = Icmpv4_wire.Echo_request; _ } as icmp), payload) ->
          (* XXX(reynir): also check code = 0?! *)
          let reply = { icmp with Icmpv4_packet.ty = Icmpv4_wire.Echo_reply }
          and ip' = { ip with src = ip.dst; dst = ip.src } in
          let data =
            Cstruct.append
              (Icmpv4_packet.Marshal.make_cstruct ~payload reply)
              payload
          in
          let hdr =
            Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.length data)
              ip'
          in
          write t ip.src (Cstruct.append hdr data)
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
  | Ok (ip, _) ->
      Logs.warn (fun m -> m "ignoring ipv4 frame %a" Ipv4_packet.pp ip);
      Lwt.return_unit

let rec timer server () =
  let open Lwt.Infix in
  (* foreach connection, call handle `Tick and follow instructions! *)
  IPM.fold
    (fun k (fd, t) acc ->
      acc >>= fun acc ->
      match Miragevpn.handle !t `Tick with
      | Error e ->
          Logs.err (fun m -> m "error in timer %a" Miragevpn.pp_error e);
          Lwt.return acc
      | Ok (_t', _out, _payloads, Some `Exit) ->
          (* TODO anything to do with "_out" or "_payloads"? *)
          Logs.warn (fun m -> m "exiting %a" Ipaddr.V4.pp k);
          Lwt.return acc
      | Ok (t', out, payloads, act) -> (
          (* TODO anything to do with "_act"? (apart from exit) *)
          Option.iter
            (fun a ->
              Logs.warn (fun m ->
                  m "in timer, ignoring action %a" Miragevpn.pp_action a))
            act;
          t := t';
          Lwt_list.iter_p (handle_payload server k) payloads >>= fun () ->
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
          | Error () -> acc
          | Ok () -> IPM.add k (fd, t) acc))
    server.connections (Lwt.return IPM.empty)
  >>= fun connections ->
  server.connections <- connections;
  Lwt_unix.sleep 1. >>= fun () -> timer server ()

let handle_action dst add rm ip action =
  match action with
  | `Established ({ Miragevpn.cidr; _ }, _) ->
      Logs.info (fun m ->
          m "%a insert ip %a, registering flow" pp_dst dst Ipaddr.V4.Prefix.pp
            cidr);
      let ip = Ipaddr.V4.Prefix.address cidr in
      add ip;
      `Continue (Some ip)
  | `Exit ->
      rm ();
      Logs.info (fun m -> m "%a exiting" pp_dst dst);
      `Stop
  | a ->
      Logs.warn (fun m ->
          m "%a ignoring action %a" pp_dst dst Miragevpn.pp_action a);
      `Continue ip

let callback t fd =
  let open Lwt.Infix in
  let is_not_taken ip = not (IPM.mem ip t.connections) in
  let client_state = ref (Miragevpn.new_connection t.server) in
  let dst =
    match Lwt_unix.getsockname fd with
    | Lwt_unix.ADDR_UNIX _ -> assert false
    | Lwt_unix.ADDR_INET (ip, port) -> (
        match Ipaddr_unix.V4.of_inet_addr ip with
        | Some ip -> (ip, port)
        | None -> assert false)
  in
  Logs.info (fun m -> m "%a new connection" pp_dst dst);
  let rec read ?ip fd =
    let rm () =
      match ip with
      | None -> ()
      | Some ip ->
          Logs.info (fun m ->
              m "%a removing ip %a from connections" pp_dst dst Ipaddr.V4.pp ip);
          t.connections <- IPM.remove ip t.connections
    and add ip = t.connections <- IPM.add ip (fd, client_state) t.connections in
    Common.read_from_fd fd >>= function
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "%a error %s while reading" pp_dst dst msg);
        rm ();
        Lwt.return_unit
    | Ok cs -> (
        match Miragevpn.handle !client_state ~is_not_taken (`Data cs) with
        | Error msg ->
            Logs.err (fun m ->
                m "%a internal miragevpn error %a" pp_dst dst Miragevpn.pp_error
                  msg);
            rm ();
            Lwt.return_unit
        | Ok (s', out, payloads, action) -> (
            client_state := s';
            let ip =
              Option.fold ~none:(`Continue ip)
                ~some:(handle_action dst add rm ip)
                action
            in
            Lwt_list.iter_p (handle_payload t (fst dst)) payloads >>= fun () ->
            Lwt_list.fold_left_s
              (fun r o ->
                match r with
                | Error _ as e -> Lwt.return e
                | Ok () -> (
                    Common.write_to_fd fd o >|= function
                    | Error (`Msg msg) ->
                        Logs.err (fun m ->
                            m "%a TCP write failed %s" Ipaddr.V4.pp (fst dst)
                              msg);
                        Error ()
                    | Ok () -> Ok ()))
              (Ok ()) out
            >>= function
            | Error () ->
                rm ();
                Lwt.return_unit
            | Ok () -> (
                match ip with
                | `Stop -> Lwt.return_unit
                | `Continue ip -> read ?ip fd)))
  in
  read fd

let connect config =
  let open Lwt.Infix in
  let ts () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())
  and now = Ptime_clock.now
  and rng = Mirage_crypto_rng.generate in
  match Miragevpn.server config ts now rng with
  | Error (`Msg msg) ->
      Logs.err (fun m -> m "server construction failed %s" msg);
      assert false
  | Ok (server, ip, port) ->
      Logs.info (fun m ->
          m "miragevpn server listening on port %d, using %a/%d" port
            Ipaddr.V4.pp (fst ip)
            (Ipaddr.V4.Prefix.bits (snd ip)));
      let server = { server; ip; connections = IPM.empty } in
      let fd = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
      Lwt_unix.(setsockopt fd SO_REUSEADDR true);
      Lwt_unix.(setsockopt fd IPV6_ONLY false);
      let addr =
        Lwt_unix.ADDR_INET
          (Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified, port)
      in
      Lwt_unix.bind fd addr >|= fun () ->
      Lwt_unix.listen fd 10;
      Lwt.async (fun () ->
          Lwt_unix.accept fd >>= fun (cfd, _) -> callback server cfd);
      Lwt.async (timer server);
      server

let parse_config filename =
  Lwt.return
  @@
  let dir, filename = Filename.(dirname filename, basename filename) in
  let string_of_file = Common.string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> Miragevpn.Config.parse_server ~string_of_file str
  | Error _ as e -> e

let jump _ filename =
  let open Lwt.Infix in
  Mirage_crypto_rng_lwt.initialize (module Mirage_crypto_rng.Fortuna);
  Lwt_main.run
    (let* config = parse_config filename in
     match config with
     | Error (`Msg s) -> Lwt.return (Error (`Msg ("config parser: " ^ s)))
     | Ok config ->
         connect config >>= fun _server ->
         let task, _u = Lwt.task () in
         task)

open Cmdliner

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let cmd =
  let term = Term.(term_result (const jump $ Common.setup_log $ config))
  and info = Cmd.info "miragevpn_server_notun" ~version:"%%VERSION_NUM%%" in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
