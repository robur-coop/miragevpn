open Lwt.Infix

let open_tun config {Openvpn.ip ; gateway ; prefix } : (Lwt_unix.file_descr,[> `Msg of string]) Lwt_result.t =
  let open Lwt_result.Infix in
  let netmask =
    (* openvpn solves this problem by modifying the routing table: *)
    if Ipaddr.V4.Prefix.mem gateway prefix
    then Ipaddr.V4.Prefix.of_addr ip
    else prefix in
  begin match Openvpn.Config.find Dev config with
    | None | Some `Tun None -> Ok None
    | Some `Tun (Some n) -> Ok (Some ("tun" ^ string_of_int n))
    | Some `Null -> Error (`Msg "TODO what is this")
    | Some `Tap _ -> Error (`Msg "using a TAP interface is not supported")
  end |> Lwt_result.lift >>= fun devname ->
  try begin
    let fd , dev = Tuntap.opentun ?devname () in
    (* pray to god we don't get raced re: tun dev teardown+creation here;
       TODO should patch Tuntap to operate on fd instead of dev name:*)
    Tuntap.set_ipv4 ~netmask dev ip ;
    Logs.debug (fun m -> m "allocated TUN interface %s" dev);
    Lwt_result.return (Lwt_unix.of_unix_file_descr fd)
  end with
  | Failure msg ->
    Lwt_result.fail
      (Rresult.R.msgf "%s: Failed to allocate TUN interface: %s"
         (match devname with None -> "dynamic" | Some dev -> dev) msg)

let rec write_to_fd fd data =
  if Cstruct.len data = 0 then
    Lwt_result.return ()
  else
    Lwt.catch (fun () ->
        Lwt_cstruct.write fd data >|= Cstruct.shift data >>= write_to_fd fd)
      (fun e ->
         Lwt_result.lift
           (Rresult.R.error_msgf "write error %s" (Printexc.to_string e)))

let write_multiple_to_fd fd bufs =
  Lwt_list.fold_left_s (fun r buf ->
      match r with
      | Ok () -> write_to_fd fd buf
      | Error e -> Lwt.return (Error e))
    (Ok ()) bufs

let read_from_fd fd =
  Lwt_result.catch (
      let buf = Bytes.create 2048 in
      Lwt_unix.read fd buf 0 2048 >>= fun count ->
      if count = 0 then
        Lwt.fail_with "end of file from server"
      else
        let cs = Cstruct.of_bytes ~len:count buf in
        Logs.debug (fun m -> m "read %d bytes" count) ;
        Lwt.return cs)
  |> Lwt_result.map_err (fun e ->
      Rresult.R.msgf "read error %s" (Printexc.to_string e))

let now () = Ptime_clock.now ()

let ts () = Mtime_clock.now_ns ()

let read_file filename =
  Lwt_unix.stat filename >>= fun stats ->
  let buf = Bytes.create stats.Lwt_unix.st_size in
  Lwt_unix.openfile filename [O_RDONLY] 0 >>= fun fd ->
  let rec read_full ?(off = 0) size =
    if size - off = 0 then
      Lwt.return_unit
    else
      Lwt_unix.read fd buf off (size - off) >>= fun read ->
      read_full ~off:(off + read) size
  in
  read_full stats.Lwt_unix.st_size >>= fun () ->
  Lwt_unix.close fd >|= fun () ->
  Bytes.unsafe_to_string buf

let jump _ filename =
  Printexc.record_backtrace true;
  Lwt_main.run (
    Nocrypto_entropy_lwt.initialize () >>= fun () ->
    read_file filename >>= fun str ->
    match
      let string_of_file fn = Ok (Lwt_main.run (read_file fn)) in
      Openvpn.Config.parse_client ~string_of_file str
    with
    | Error `Msg s -> Lwt.fail_with ("config parser: " ^ s)
    | Ok config ->
      let resolve = function
        | (`IP ip, port) :: _ -> Lwt.return (ip, port)
        | (`Domain name, port) :: _ ->
          begin
            let res = Dns_client_lwt.create () in
            Dns_client_lwt.gethostbyname res name >>= function
            | Error `Msg x ->
              Logs.err (fun m -> m "gethostbyname for %a returned an error: %s"
                           Domain_name.pp name x) ;
              Lwt.fail_with "resolver error"
            | Ok ip -> Lwt.return (Ipaddr.V4 ip,port)
          end
        | [] -> Lwt.fail_with "no remote"
      in
      begin match Openvpn.client config (now ()) (ts ()) Nocrypto.Rng.generate () with
      | Error (`Msg msg) -> Lwt.fail_with ("couldn't init client: " ^ msg)
      | Ok (state, remote, out) ->
        resolve remote >>= fun (ip, port) ->
        Logs.info (fun m -> m "connecting to %a:%d" Ipaddr.pp ip port) ;
        let s = ref state
        and dom =
          Ipaddr.(Lwt_unix.(match ip with V4 _ -> PF_INET | V6 _ -> PF_INET6))
        and ip = Ipaddr_unix.to_inet_addr ip
        in
        let fd = Lwt_unix.(socket dom SOCK_STREAM 0) in
        Lwt_unix.(connect fd (ADDR_INET (ip, port))) >>= fun () ->


        (* TODO here we should learn MTU from unix.getsockopt fd IP_MTU
           ... which Unix doesn't expose. *)

        let open Lwt_result in
        write_to_fd fd out >>= fun () ->
        let _ =
          Lwt_engine.on_timer 1. true (fun _ ->
              let s', out = Openvpn.timer !s (ts ()) in
              s := s' ;
              Lwt.async (fun () -> write_multiple_to_fd fd out))
        in
        let read_and_handle () =
          read_from_fd fd >>= fun b ->
          match
            Openvpn.(Rresult.R.error_to_msg ~pp_error
                       (incoming !s (now ()) (ts ()) b))
          with
          | Error e -> fail e
          | Ok (s', outs, app) ->
            s := s' ;
            write_multiple_to_fd fd outs >|= fun () ->
            app
        in
        let rec establish () =
          read_and_handle () >>= function
          | incoming_data ->
            match Openvpn.ready !s with
            | Some ip_config ->
              open_tun config ip_config >|= fun tun_fd -> tun_fd, incoming_data
            | None ->
              if incoming_data <> [] then
                Logs.err (fun m ->
                    m "Got incoming %d data before connection ready:@,%a"
                      (List.length incoming_data)
                      Fmt.(list ~sep:(unit"@,")
                             Cstruct.hexdump_pp) incoming_data);
              establish ()
        in
        establish () >>= fun (tun_fd, app_data) ->
        let rec process_incoming app_data =
          ( let open Lwt.Infix in
            Lwt_list.for_all_p (fun pkt ->
                (* not using write_to_fd here because partial writes to
                   a tun interface are semantically different from
                   single write()s: *)
                Lwt_cstruct.write tun_fd pkt >|= function
                | written when written = Cstruct.len pkt -> true
                | _ -> false
              ) app_data >>= function
              | true -> Lwt_result.return ()
              | false -> Lwt_result.fail (`Msg "partial write to tun interface")
          ) >>= fun () ->
          let open Lwt_result.Infix in
          read_and_handle () >>= process_incoming
        in
        let rec process_outgoing tun_fd ()=
          let buf = Cstruct.create 1500 in
          Lwt_cstruct.read tun_fd buf |> Lwt_result.ok
          >|= Cstruct.sub buf 0 >>= fun buf ->
          match Openvpn.outgoing !s (ts()) buf with
          | Error `Not_ready -> failwith ""
          | Ok (s', outs) ->
            s := s';
            write_multiple_to_fd fd outs
            >>= process_outgoing tun_fd
        in
        Lwt.pick [ process_incoming app_data
                 ; process_outgoing tun_fd () ]
      end
  ) (* <- Lwt_main.run *)

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let cmd =
  Term.(term_result (const jump $ setup_log $ config)),
  Term.info "openvpn_client" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
