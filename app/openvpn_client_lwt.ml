open Lwt.Infix

let open_tun config {Openvpn.ip ; gateway ; _ }
  : (Openvpn.Config.t * Lwt_unix.file_descr, [> `Msg of string]) Lwt_result.t =
  (* This returns a Config with updated MTU, and a file descriptor for
     the TUN interface *)
  let open Lwt_result.Infix in
  begin match Openvpn.Config.find Dev config with
    | None | Some (`Tun, None) -> Ok None
    | Some (`Tun, Some name) -> Ok (Some name)
    | Some (`Tap, name) ->
      Rresult.R.error_msgf
        "using a TAP interface (for %S) is not supported"
        (match name with Some n -> n | None -> "dynamic device")
  end |> Lwt_result.lift >>= fun devname ->
  try begin
    let fd , dev = Tuntap.opentun ?devname () in
    (* pray to god we don't get raced re: tun dev teardown+creation here;
       TODO should patch Tuntap to operate on fd instead of dev name:*)
    Logs.debug (fun m -> m "opened TUN interface %s" dev);
    Tuntap.set_up_and_running dev;
    Logs.debug (fun m -> m "set TUN interface up and running");
    (* TODO set the mtu of the device *)
    let config = match Openvpn.Config.find Tun_mtu config with
      | Some _mtu -> (*Tuntap.set_mtu dev mtu TODO ; *) config
      | None -> Openvpn.Config.add Tun_mtu (Tuntap.get_mtu dev) config in
    begin
      (* TODO factor the uname -s out into a separate library *)
      let local, remote = Ipaddr.V4.to_string ip, Ipaddr.V4.to_string gateway in
      match
        let cmd = "uname -s" in
        let process = Unix.open_process_in cmd in
        let output = input_line process in
        let _ = Unix.close_process_in process in
        output
      with
      (* TODO handle errors appropriately (use bos) *)
      | "Linux" ->
        Unix.system (Format.sprintf "ip addr add dev %s %s remote %s"
                       dev local remote) |> ignore
      | "FreeBSD" ->
        Unix.system (Format.sprintf "ifconfig %s %s %s" dev local remote) |> ignore
      | s ->
        Logs.err (fun m -> m "unknown system %s, no tun setup %s (local %s remote %s)."
                     s dev local remote)
    end;
    (* TODO add stuff to routing table if desired/demanded by server *)
    (* TODO use tuntap API once it does the right thing Tuntap.set_ipv4 ~netmask dev ip ;*)
    Logs.debug (fun m -> m "allocated TUN interface %s" dev);
    Lwt_result.return (config, Lwt_unix.of_unix_file_descr fd)
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
           (Rresult.R.error_msgf "TCP write error %s" (Printexc.to_string e)))

let write_multiple_to_fd fd bufs =
  Lwt_list.fold_left_s (fun r buf ->
      if r then
        write_to_fd fd buf >|= function
        | Ok () -> true
        | Error `Msg msg ->
          Logs.err (fun m -> m "TCP error %s while writing" msg);
          false
      else
        Lwt.return r)
    true bufs

let write_udp sa fd data =
  Lwt.catch (fun () ->
      let len = Cstruct.len data in
      Lwt_unix.sendto fd (Cstruct.to_bytes data) 0 len [] sa >|= fun sent ->
      if sent <> len then
        Logs.warn (fun m -> m "UDP short write (length %d, written %d)" len sent);
      Ok ())
    (fun e ->
       Lwt_result.lift
         (Rresult.R.error_msgf "UDP write error %s" (Printexc.to_string e)))

let write_multiple_udp sa fd bufs =
  Lwt_list.fold_left_s (fun r buf ->
      if r then
        write_udp sa fd buf >|= function
        | Ok () -> true
        | Error `Msg msg ->
          Logs.err (fun m -> m "error %s while writing" msg);
          false
      else
        Lwt.return r)
    true bufs

let transmit data = function
  | Some `Tcp fd -> write_multiple_to_fd fd data
  | Some `Udp (sa, fd) -> write_multiple_udp sa fd data
  | None -> Lwt.return false

let read_from_fd fd =
  Lwt_result.catch (
    let bufsize = 2048 in
    let buf = Bytes.create bufsize in
    Lwt_unix.read fd buf 0 bufsize >>= fun count ->
    if count = 0 then
      Lwt.fail_with "end of file from server"
    else
      let cs = Cstruct.of_bytes ~len:count buf in
      Logs.debug (fun m -> m "read %d bytes" count) ;
      Lwt.return cs)
  |> Lwt_result.map_err (fun e -> `Msg (Printexc.to_string e))

let rec reader_tcp mvar fd =
  read_from_fd fd >>= function
  | Error `Msg msg ->
    Logs.err (fun m -> m "read error from remote %s" msg);
    Lwt_mvar.put mvar `Connection_failed
  | Ok data ->
    Lwt_mvar.put mvar (`Data data) >>= fun () ->
    reader_tcp mvar fd

let read_udp =
  let bufsize = 65535 in
  let buf = Bytes.create bufsize in
  fun (sa, fd) ->
    Lwt_result.catch (
      Lwt_unix.recvfrom fd buf 0 bufsize [] >>= fun (count, sa') ->
      if sa = sa' then
        let cs = Cstruct.of_bytes ~len:count buf in
        Logs.debug (fun m -> m "read %d bytes" count) ;
        Lwt.return (Some cs)
      else
        let pp_sockaddr ppf = function
          | Unix.ADDR_UNIX s -> Fmt.pf ppf "unix %s" s
          | Unix.ADDR_INET (ip, port) ->
            Fmt.pf ppf "%s:%d" (Unix.string_of_inet_addr ip) port
        in
        Logs.warn (fun m -> m "ignoring unsolicited data from %a (expected %a)"
                      pp_sockaddr sa' pp_sockaddr sa);
        Lwt.return None)
  |> Lwt_result.map_err (fun e -> `Msg (Printexc.to_string e))

let rec reader_udp mvar r =
  read_udp r >>= function
  | Error `Msg msg ->
    Logs.err (fun m -> m "read error from remote %s" msg);
    Lwt_mvar.put mvar `Connection_failed
  | Ok Some data ->
    Lwt_mvar.put mvar (`Data data) >>= fun () ->
    reader_udp mvar r
  | Ok None -> reader_udp mvar r

let ts () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())

let now () = Ptime_clock.now ()

let resolve (name, ip_version) =
  let res = Dns_client_lwt.create ~clock:ts () in
  match ip_version with
  | `Ipv4 | `Any ->
    begin
      Dns_client_lwt.gethostbyname res name >|= function
      | Error `Msg x ->
        Logs.warn (fun m -> m "gethostbyname for %a return an error: %s"
                      Domain_name.pp name x);
        None
      | Ok ip -> Some (Ipaddr.V4 ip)
    end
  | `Ipv6 ->
    begin
      Dns_client_lwt.gethostbyname6 res name >|= function
      | Error `Msg x ->
        Logs.warn (fun m -> m "gethostbyname for %a return an error: %s"
                      Domain_name.pp name x);
        None
      | Ok ip -> Some (Ipaddr.V6 ip)
    end

let connect_tcp ip port =
  let dom =
    Ipaddr.(Lwt_unix.(match ip with V4 _ -> PF_INET | V6 _ -> PF_INET6))
  and unix_ip = Ipaddr_unix.to_inet_addr ip
  in
  let fd = Lwt_unix.(socket dom SOCK_STREAM 0) in
  Lwt.catch (fun () ->
      Lwt_unix.(connect fd (ADDR_INET (unix_ip, port))) >|= fun () ->
      Logs.app (fun m -> m "connected to %a:%d" Ipaddr.pp ip port);
      Some fd)
    (fun e ->
       Logs.err (fun m -> m "error %s while connecting to %a:%d"
                    (Printexc.to_string e) Ipaddr.pp ip port);
       Lwt.return None)
  (* TODO 2019-11-23 hannes is not sure whether this comment is still relevant.
     TODO here we should learn the MTU in order to set Link_mtu.
     We can use ioctl SIOCIFMTU bound in Tuntap.get_mtu
     if we learn the network interface name with
     SIOCGIFNAME
     #include <net/if.h>
     SIOCGIFINDEX ifr_ifindex ifr_ifru.ifru_ivalue
     ./sys/sockio.h:#define	SIOCGIFINDEX
     SIOCSIFMETRIC
     > #ifdef __FreeBSD__
     >         ifr.ifr_index = i;
     > #else
     >         ifr.ifr_ifindex = i;
     > #endif
     > The "'SIOCGIFNAME' was not declared in this scope" is hopefully solved by:
     > #ifdef SIOCGIFNAME
     >         if (::ioctl (s, SIOCGIFNAME, &ifr) < 0)
     > #else
     >         if (!if_indextoname(ifr.ifr_index, ifr.ifr_name))
     > #endif
     TODO this will be fixed in upcoming PR to mirage-tuntap.
  *)

let connect_udp ip port =
  let dom =
    Ipaddr.(Lwt_unix.(match ip with V4 _ -> PF_INET | V6 _ -> PF_INET6))
  and unix_ip = Ipaddr_unix.to_inet_addr ip
  and src_port = Randomconv.int16 Mirage_crypto_rng.generate
  in
  let fd = Lwt_unix.(socket dom SOCK_DGRAM 0) in
  let any =
    Ipaddr.(Unix.(match ip with V4 _ -> inet_addr_any | V6 _ -> inet6_addr_any))
  in
  Lwt_unix.(bind fd (ADDR_INET (any, src_port))) >|= fun () ->
  Unix.ADDR_INET (unix_ip, port), fd

type conn = {
  mutable o_client : Openvpn.t ;
  mutable peer : ([ `Udp of Lwt_unix.sockaddr * Lwt_unix.file_descr | `Tcp of Lwt_unix.file_descr ]) option ;
  mutable est_switch : Lwt_switch.t ;
  data_mvar : Cstruct.t list Lwt_mvar.t ;
  est_mvar : (Openvpn.ip_config * int) Lwt_mvar.t ;
  event_mvar : Openvpn.event Lwt_mvar.t ;
}

let safe_close fd =
  Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

let handle_action conn = function
  | `Resolve data ->
    Lwt_switch.turn_off conn.est_switch >>= fun () ->
    resolve data >>= fun r ->
    let ev = match r with None -> `Resolve_failed | Some x -> `Resolved x in
    Lwt_mvar.put conn.event_mvar ev
  | `Connect (ip, port, `Udp) ->
    Lwt_switch.turn_off conn.est_switch >>= fun () ->
    conn.est_switch <- Lwt_switch.create ();
    Logs.app (fun m -> m "connecting udp %a" Ipaddr.pp ip);
    connect_udp ip port >>= fun r ->
    conn.peer <- Some (`Udp r);
    Lwt.async (fun () -> reader_udp conn.event_mvar r);
    Lwt_mvar.put conn.event_mvar `Connected
  | `Connect (ip, port, `Tcp) ->
    Lwt_switch.turn_off conn.est_switch >>= fun () ->
    let sw = Lwt_switch.create () in
    conn.est_switch <- sw;
    Logs.app (fun m -> m "connecting tcp %a" Ipaddr.pp ip);
    connect_tcp ip port >>= fun r ->
    if Lwt_switch.is_on sw then
      let ev = match r with
        | None -> `Connection_failed
        | Some fd ->
          conn.peer <- Some (`Tcp fd);
          Lwt.async (fun () -> reader_tcp conn.event_mvar fd);
          `Connected
      in
      Lwt_mvar.put conn.event_mvar ev
    else begin
      Logs.warn (fun m -> m "connection cancelled by switch");
      match r with None -> Lwt.return_unit | Some x -> safe_close x
    end
  | `Disconnect ->
    begin match conn.peer with
      | None ->
        Logs.err (fun m -> m "cannot disconnect: no open connection");
        Lwt.return_unit
      | Some `Tcp fd | Some `Udp (_, fd) ->
        Logs.warn (fun m -> m "disconnecting!");
        conn.peer <- None;
        safe_close fd
    end
  | `Exit -> Lwt.fail_with "exit called"
  | `Payload data -> Lwt_mvar.put conn.data_mvar data
  | `Established (ip, mtu) ->
    Logs.app (fun m -> m "established %a" Openvpn.pp_ip_config ip);
    Lwt_mvar.put conn.est_mvar (ip, mtu)

let rec event conn =
  Logs.info (fun m -> m "processing event");
  Lwt_mvar.take conn.event_mvar >>= fun ev ->
  Logs.info (fun m -> m "now for real processing event %a" Openvpn.pp_event ev);
  match Openvpn.handle conn.o_client ev with
  | Error e ->
    Logs.err (fun m -> m "openvpn handle failed %a" Openvpn.pp_error e);
    Lwt.return_unit
  | Ok (t', outs, action) ->
    conn.o_client <- t';
    Logs.info (fun m -> m "handling action %a"
                  Fmt.(option ~none:(unit "none") Openvpn.pp_action) action);
    (match outs with
     | [] -> ()
     | _ ->
       Lwt.async (fun () ->
           (transmit outs conn.peer >>= function
             | true -> Lwt.return_unit
             | false -> Lwt_mvar.put conn.event_mvar `Connection_failed)));
    (match action with
     | None -> ()
     | Some a -> Lwt.async (fun () -> handle_action conn a));
    event conn

let send_recv conn config ip_config _mtu =
  open_tun config ip_config (* TODO mtu *) >>= function
  | Error `Msg msg -> Lwt.fail_with ("error opening tun " ^ msg)
  | Ok (_, tun_fd) ->
    let rec process_incoming () =
      Lwt_mvar.take conn.data_mvar >>= fun app_data ->
      Lwt_list.for_all_p (fun pkt ->
          (* not using write_to_fd here because partial writes to a tun
             interface are semantically different from single write()s: *)
          Lwt_cstruct.write tun_fd pkt >|= function
          | written when written = Cstruct.len pkt -> true
          | _ -> false
        ) app_data >>= function
      | true -> process_incoming ()
      | false -> Lwt_result.fail (`Msg "partial write to tun interface")
    in
    let rec process_outgoing tun_fd =
      let open Lwt_result.Infix in
      let buf = Cstruct.create 1500 in
      Lwt_cstruct.read tun_fd buf |> Lwt_result.ok
      >|= Cstruct.sub buf 0 >>= fun buf ->
      match Openvpn.outgoing conn.o_client buf with
      | Error `Not_ready -> Lwt.fail_with "tunnel not ready, dropping data"
      | Ok (s', out) ->
        conn.o_client <- s';
        let open Lwt.Infix in
        transmit [out] conn.peer >>= fun sent ->
        if sent then
          process_outgoing tun_fd
        else
          Lwt.fail_with "couldn't send"
    in
    Lwt.pick [ process_incoming () ; process_outgoing tun_fd ]

let establish_tunnel config =
  match Openvpn.client config ts now Mirage_crypto_rng.generate with
  | Error `Msg msg ->
    Logs.err (fun m -> m "client construction failed %s" msg);
    Lwt.fail_with msg
  | Ok (o_client, action) ->
    let data_mvar = Lwt_mvar.create_empty ()
    and est_mvar = Lwt_mvar.create_empty ()
    and event_mvar = Lwt_mvar.create_empty ()
    in
    let conn = { o_client ; peer = None ; est_switch = Lwt_switch.create () ;
                 data_mvar ; est_mvar ; event_mvar }
    in
    (* handle initial action *)
    Lwt.async (fun () -> event conn);
    let _event =
      Lwt_engine.on_timer 1. true (fun _ ->
          Lwt.async (fun () -> Lwt_mvar.put event_mvar `Tick))
    in
    Lwt.async (fun () -> handle_action conn action);
    Logs.info (fun m -> m "waiting for established");
    Lwt_mvar.take est_mvar >>= fun (ip_config, mtu) ->
    Logs.info (fun m -> m "now established %a (mtu %d)"
                  Openvpn.pp_ip_config ip_config mtu);
    send_recv conn config ip_config mtu

let string_of_file ~dir filename =
  let file =
    if Filename.is_relative filename then
      Filename.concat dir filename
    else
      filename
  in
  try
    let fh = open_in file in
    let content = really_input_string fh (in_channel_length fh) in
    close_in_noerr fh ;
    Ok content
  with _ -> Rresult.R.error_msgf "Error reading file %S" file

let parse_config filename =
  Lwt.return @@
  let dir, filename = Filename.(dirname filename, basename filename) in
  let string_of_file = string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> Openvpn.Config.parse_client ~string_of_file str
  | Error _ as e -> e

let jump _ filename =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.initialize ();
  Lwt_main.run (
    parse_config filename >>= function
    | Error `Msg s -> Lwt.fail_with ("config parser: " ^ s)
    | Ok config -> establish_tunnel config
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
