open Lwt.Infix

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let pp_route ppf (net, gw, metric) =
  Fmt.pf ppf "%a via %a metric %u" Ipaddr.V4.Prefix.pp net Ipaddr.V4.pp gw
    metric

type supported = FreeBSD | Linux

let platform =
  let cmd = Bos.Cmd.(v "uname" % "-s") in
  lazy
    (match Bos.OS.Cmd.(run_out cmd |> out_string |> success) with
    | Ok s when s = "FreeBSD" -> FreeBSD
    | Ok s when s = "Linux" -> Linux
    | Ok s -> invalid_arg (Printf.sprintf "OS %s not supported" s)
    | Error (`Msg m) -> invalid_arg m)

let connected_ip = ref Ipaddr.V4.any

let shares_subnet dst =
  let dst = Ipaddr.V4.to_string dst in
  match Lazy.force platform with
  | Linux -> (
      let cmd = Bos.Cmd.(v "ip" % "route" % "get" % dst) in
      match Bos.OS.Cmd.(run_out cmd |> out_string |> success) with
      | Ok routes -> (
          match String.split_on_char ' ' routes with
          | _ :: "via" :: _ip :: _ -> false
          | _ -> true)
      | Error (`Msg m) -> invalid_arg ("couldn't find default route " ^ m))
  | FreeBSD -> (
      let cmd = Bos.Cmd.(v "route" % "-n" % "show" % dst) in
      match Bos.OS.Cmd.(run_out cmd |> out_lines |> success) with
      | Ok lines ->
          not
            (List.exists
               (fun l -> String.starts_with ~prefix:"gateway:" (String.trim l))
               lines)
      | Error (`Msg m) -> invalid_arg ("couldn't find default route " ^ m))

let default_route () =
  match Lazy.force platform with
  | Linux -> (
      let cmd = Bos.Cmd.(v "ip" % "route" % "show" % "default") in
      match Bos.OS.Cmd.(run_out cmd |> out_string |> success) with
      | Ok ip -> (
          match String.split_on_char ' ' ip with
          | "default" :: "via" :: ip :: _ -> Some ip
          | _ -> None)
      | Error (`Msg m) -> invalid_arg ("couldn't find default route " ^ m))
  | FreeBSD -> (
      let cmd = Bos.Cmd.(v "route" % "-n" % "show" % "default") in
      match Bos.OS.Cmd.(run_out cmd |> out_lines |> success) with
      | Ok lines -> (
          match
            List.find_opt
              (fun l -> String.starts_with ~prefix:"gateway:" (String.trim l))
              lines
          with
          | Some gw ->
              Option.map String.trim
                (List.nth_opt (String.split_on_char ':' gw) 1)
          | None -> None)
      | Error (`Msg m) -> invalid_arg ("couldn't find default route " ^ m))

let open_tun config { Miragevpn.cidr; gateway } routes :
    (Miragevpn.Config.t * Lwt_unix.file_descr, [> `Msg of string ]) result =
  (* This returns a Config with updated MTU, and a file descriptor for
     the TUN interface *)
  let ( let* ) = Result.bind in
  let* devname =
    match Miragevpn.Config.find Dev config with
    | None | Some (`Tun, None) -> Ok None
    | Some (`Tun, Some name) -> Ok (Some name)
    | Some (`Tap, name) ->
        error_msgf "using a TAP interface (for %S) is not supported"
          (match name with Some n -> n | None -> "dynamic device")
  in
  let* fd, dev =
    try Ok (Tuntap.opentun ?devname ())
    with Failure msg ->
      error_msgf "%s: Failed to allocate TUN interface: %s"
        (match devname with None -> "dynamic" | Some dev -> dev)
        msg
  in
  let* () =
    (* pray to god we don't get raced re: tun dev teardown+creation here;
       TODO should patch Tuntap to operate on fd instead of dev name:*)
    Logs.debug (fun m -> m "opened TUN interface %s" dev);
    Tuntap.set_up_and_running dev;
    Logs.debug (fun m -> m "set TUN interface up and running");
    let local = Ipaddr.V4.Prefix.to_string cidr
    and remote = Ipaddr.V4.to_string gateway in
    let cmd =
      match Lazy.force platform with
      | Linux -> Bos.Cmd.(v "ip" % "addr" % "add" % "dev" % dev % local)
      | FreeBSD -> Bos.Cmd.(v "ifconfig" % dev % local % remote)
    in
    Bos.OS.Cmd.run cmd
  in
  (* TODO set the mtu of the device *)
  let config =
    match Miragevpn.Config.find Tun_mtu config with
    | Some _mtu -> (*Tuntap.set_mtu dev mtu TODO ; *) config
    | None -> Miragevpn.Config.add Tun_mtu (Tuntap.get_mtu dev) config
  in
  Logs.info (fun m ->
      m "Setting up routes: @[<v>%a@]" Fmt.(list pp_route) routes);
  let* on_exit =
    match
      List.fold_left
        (fun acc (net, gw, _metric) ->
          let* cmds_on_exit = acc in
          let net = Ipaddr.V4.Prefix.to_string net
          and gw = Ipaddr.V4.to_string gw in
          let cmd_add, cmd_del =
            match Lazy.force platform with
            | Linux ->
                ( Bos.Cmd.(v "ip" % "route" % "add" % net % "via" % gw),
                  Bos.Cmd.(v "ip" % "route" % "del" % net) )
            | FreeBSD ->
                ( Bos.Cmd.(v "route" % "add" % net % gw),
                  Bos.Cmd.(v "route" % "delete" % net) )
          in
          match Bos.OS.Cmd.run cmd_add with
          | Ok () -> Ok (cmd_del :: cmds_on_exit)
          | Error (`Msg m) -> Error (`Msg m, cmds_on_exit))
        (Ok []) routes
    with
    | Ok cmds -> Ok cmds
    | Error (`Msg m, on_exit) ->
        List.iter (fun cmd -> Bos.OS.Cmd.run cmd |> ignore) on_exit;
        Error (`Msg m)
  in
  at_exit (fun () ->
      List.iter (fun cmd -> Bos.OS.Cmd.run cmd |> ignore) on_exit);
  (* TODO use tuntap API once it does the right thing Tuntap.set_ipv4 ~netmask dev ip ;*)
  Logs.debug (fun m -> m "allocated TUN interface %s" dev);
  Ok (config, Lwt_unix.of_unix_file_descr fd)

let write_multiple_to_fd fd bufs =
  Lwt_list.fold_left_s
    (fun r buf ->
      if r then (
        Common.write_to_fd fd buf >|= function
        | Ok () -> true
        | Error (`Msg msg) ->
            Logs.err (fun m -> m "TCP error %s while writing" msg);
            false)
      else Lwt.return r)
    true bufs

let write_multiple_udp fd bufs =
  Lwt_list.fold_left_s
    (fun r buf ->
      if r then (
        Common.write_udp fd buf >|= function
        | Ok () -> true
        | Error (`Msg msg) ->
            Logs.err (fun m -> m "error %s while writing" msg);
            false)
      else Lwt.return r)
    true bufs

let transmit data = function
  | Some (`Tcp fd) -> write_multiple_to_fd fd data
  | Some (`Udp fd) -> write_multiple_udp fd data
  | None -> Lwt.return false

let rec reader_tcp mvar fd =
  Common.read_from_fd fd >>= function
  | Error (`Msg msg) ->
      Common.safe_close fd >>= fun () ->
      Logs.err (fun m -> m "read error from remote %s" msg);
      Lwt_mvar.put mvar `Connection_failed
  | Ok data -> Lwt_mvar.put mvar (`Data data) >>= fun () -> reader_tcp mvar fd

let rec reader_udp mvar r =
  Common.read_udp r >>= function
  | Error (`Msg msg) ->
      Common.safe_close r >>= fun () ->
      Logs.err (fun m -> m "read error from remote %s" msg);
      Lwt_mvar.put mvar `Connection_failed
  | Ok (Some data) ->
      Lwt_mvar.put mvar (`Data data) >>= fun () -> reader_udp mvar r
  | Ok None -> reader_udp mvar r

let resolve (name, ip_version) =
  let happy_eyeballs = Happy_eyeballs_lwt.create () in
  let res = Dns_client_lwt.create happy_eyeballs in
  match ip_version with
  | `Ipv4 | `Any -> (
      Dns_client_lwt.gethostbyname res name >|= function
      | Error (`Msg x) ->
          Logs.warn (fun m ->
              m "gethostbyname for %a return an error: %s" Domain_name.pp name x);
          None
      | Ok ip -> Some (Ipaddr.V4 ip))
  | `Ipv6 -> (
      Dns_client_lwt.gethostbyname6 res name >|= function
      | Error (`Msg x) ->
          Logs.warn (fun m ->
              m "gethostbyname for %a return an error: %s" Domain_name.pp name x);
          None
      | Ok ip -> Some (Ipaddr.V6 ip))

let connect_tcp ip port =
  let dom =
    Ipaddr.(Lwt_unix.(match ip with V4 _ -> PF_INET | V6 _ -> PF_INET6))
  and unix_ip = Ipaddr_unix.to_inet_addr ip in
  let fd = Lwt_unix.(socket dom SOCK_STREAM 0) in
  Lwt.catch
    (fun () ->
      Lwt_unix.(connect fd (ADDR_INET (unix_ip, port))) >|= fun () ->
      Logs.app (fun m -> m "connected to %a:%d" Ipaddr.pp ip port);
      Some fd)
    (fun e ->
      Common.safe_close fd >|= fun () ->
      Logs.err (fun m ->
          m "error %s while connecting to %a:%d" (Printexc.to_string e)
            Ipaddr.pp ip port);
      None)
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
  and unix_ip = Ipaddr_unix.to_inet_addr ip in
  let fd = Lwt_unix.(socket dom SOCK_DGRAM 0) in
  Lwt_unix.(connect fd (ADDR_INET (unix_ip, port))) >|= fun () -> fd

type conn = {
  mutable o_client : Miragevpn.t;
  mutable peer :
    [ `Udp of Lwt_unix.file_descr | `Tcp of Lwt_unix.file_descr ] option;
  mutable est_switch : Lwt_switch.t;
  data_mvar : string list Lwt_mvar.t;
  est_mvar :
    (Miragevpn.ip_config * int * Miragevpn.route_info, unit) result Lwt_mvar.t;
  event_mvar : Miragevpn.event Lwt_mvar.t;
}

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
      connect_udp ip port >>= fun fd ->
      conn.peer <- Some (`Udp fd);
      Lwt.async (fun () -> reader_udp conn.event_mvar fd);
      (match ip with
      | Ipaddr.V4 ip -> connected_ip := ip
      | Ipaddr.V6 _ -> Logs.warn (fun m -> m "ahhhh, v6"));
      Lwt_mvar.put conn.event_mvar `Connected
  | `Connect (ip, port, `Tcp) ->
      Lwt_switch.turn_off conn.est_switch >>= fun () ->
      let sw = Lwt_switch.create () in
      conn.est_switch <- sw;
      Logs.app (fun m -> m "connecting tcp %a" Ipaddr.pp ip);
      connect_tcp ip port >>= fun r ->
      if Lwt_switch.is_on sw then
        let ev =
          match r with
          | None -> `Connection_failed
          | Some fd ->
              conn.peer <- Some (`Tcp fd);
              Lwt.async (fun () -> reader_tcp conn.event_mvar fd);
              (match ip with
              | Ipaddr.V4 ip -> connected_ip := ip
              | Ipaddr.V6 _ -> Logs.warn (fun m -> m "aaaah"));
              `Connected
        in
        Lwt_mvar.put conn.event_mvar ev
      else (
        Logs.warn (fun m -> m "connection cancelled by switch");
        match r with None -> Lwt.return_unit | Some x -> Common.safe_close x)
  | `Exit -> (* FIXME *) failwith "exit called"
  | (`Cc_exit | `Cc_halt _ | `Cc_restart _) as exit_msg ->
      (* FIXME *)
      Format.kasprintf failwith "%a received" Miragevpn.pp_action exit_msg
  | `Established (ip, mtu, route_info) ->
      Logs.app (fun m -> m "established %a" Miragevpn.pp_ip_config ip);
      Lwt_mvar.put conn.est_mvar (Ok (ip, mtu, route_info))

let rec event conn =
  Lwt_mvar.take conn.event_mvar >>= fun ev ->
  Logs.debug (fun m ->
      m "now for real processing event %a" Miragevpn.pp_event ev);
  match Miragevpn.handle conn.o_client ev with
  | Error e ->
      Logs.err (fun m -> m "miragevpn handle failed: %a" Miragevpn.pp_error e);
      Lwt_mvar.put conn.est_mvar (Error ()) >>= fun () -> Lwt.return_unit
  | Ok (t', outs, payloads, action) ->
      conn.o_client <- t';
      (match outs with
      | [] -> Lwt.return_unit
      | _ -> (
          transmit outs conn.peer >>= function
          | true -> Lwt.return_unit
          | false -> Lwt_mvar.put conn.event_mvar `Connection_failed))
      >>= fun () ->
      Option.iter
        (fun a ->
          Logs.debug (fun m -> m "handling action %a" Miragevpn.pp_action a);
          Lwt.async (fun () -> handle_action conn a))
        action;
      (match payloads with
      | [] -> Lwt.return_unit
      | _ -> Lwt_mvar.put conn.data_mvar payloads)
      >>= fun () -> event conn

let send_recv conn config ip_config _mtu routes =
  match open_tun config ip_config (* TODO mtu *) routes with
  | Error (`Msg msg) -> failwith ("error opening tun " ^ msg)
  | Ok (_, tun_fd) ->
      let rec process_incoming () =
        Lwt_mvar.take conn.data_mvar >>= fun pkts ->
        (* not using write_to_fd here because partial writes to a tun
           interface are semantically different from single write()s: *)
        Lwt_list.iter_p
          (fun pkt ->
            (* on FreeBSD, the tun read is prepended with a 4 byte protocol (AF_INET) *)
            let pkt =
              match Lazy.force platform with
              | FreeBSD -> "\000\000\000\002" ^ pkt
              | Linux -> pkt
            in
            Lwt_unix.write_string tun_fd pkt 0 (String.length pkt) >|= ignore)
          pkts
        >>= fun () -> process_incoming ()
      in
      let rec process_outgoing tun_fd =
        let open Lwt_result.Infix in
        let buf = Bytes.create 1500 in
        (* on FreeBSD, the tun read is prepended with a 4 byte protocol (AF_INET) *)
        ( Lwt_unix.read tun_fd buf 0 (Bytes.length buf) |> Lwt_result.ok
        >|= fun len ->
          let start, len =
            match Lazy.force platform with
            | Linux -> (0, len)
            | FreeBSD -> (4, len - 4)
          in
          Bytes.sub_string buf start len )
        >>= fun buf ->
        match Miragevpn.outgoing conn.o_client buf with
        | Error `Not_ready -> failwith "tunnel not ready, dropping data"
        | Ok (s', out) ->
            conn.o_client <- s';
            let open Lwt.Infix in
            transmit [ out ] conn.peer >>= fun sent ->
            if sent then process_outgoing tun_fd else failwith "couldn't send"
      in
      Lwt.pick [ process_incoming (); process_outgoing tun_fd ]

let establish_tunnel config pkcs12_password =
  match Miragevpn.client ?pkcs12_password config with
  | Error (`Msg msg) ->
      Logs.err (fun m -> m "client construction failed %s" msg);
      failwith msg
  | Ok (o_client, action) -> (
      let data_mvar = Lwt_mvar.create_empty ()
      and est_mvar = Lwt_mvar.create_empty ()
      and event_mvar = Lwt_mvar.create_empty () in
      let conn =
        {
          o_client;
          peer = None;
          est_switch = Lwt_switch.create ();
          data_mvar;
          est_mvar;
          event_mvar;
        }
      in
      (* handle initial action *)
      Lwt.async (fun () -> event conn);
      let _event =
        Lwt_engine.on_timer 1. true (fun _ ->
            Lwt.async (fun () -> Lwt_mvar.put event_mvar `Tick))
      in
      Lwt.async (fun () -> handle_action conn action);
      Logs.info (fun m -> m "waiting for established");
      Lwt_mvar.take est_mvar >>= function
      | Error () -> Lwt.return_error (`Msg "Impossible to establish a channel")
      | Ok (ip_config, mtu, route_info) ->
          Lwt.async (fun () ->
              let rec take_mvar () =
                Lwt_mvar.take est_mvar >>= function
                | Error () ->
                    Logs.err (fun m -> m "est_mvar errored");
                    exit 2
                | Ok (ip_config', _, _) ->
                    if
                      Ipaddr.V4.Prefix.compare ip_config.cidr ip_config'.cidr
                      = 0
                      && Ipaddr.V4.compare ip_config.gateway ip_config'.gateway
                         = 0
                    then take_mvar ()
                    else (
                      Logs.warn (fun m ->
                          m
                            "IP changed: was %a (gateway %a), now %a (gateway \
                             %a)"
                            Ipaddr.V4.Prefix.pp ip_config.cidr Ipaddr.V4.pp
                            ip_config.gateway Ipaddr.V4.Prefix.pp
                            ip_config'.cidr Ipaddr.V4.pp ip_config'.gateway);
                      exit 2)
              in
              take_mvar ());
          Logs.info (fun m ->
              m "now established %a (mtu %d)" Miragevpn.pp_ip_config ip_config
                mtu);
          let routes =
            let remote_host = Some !connected_ip
            and net_gateway =
              Option.bind (default_route ()) (fun gw ->
                  Result.to_option (Ipaddr.V4.of_string gw))
            and shares_subnet = shares_subnet !connected_ip in
            Miragevpn.routes ~shares_subnet ~remote_host ~net_gateway route_info
          in
          send_recv conn config ip_config mtu routes)

let parse_config filename =
  Lwt.return
  @@
  let dir, filename = Filename.(dirname filename, basename filename) in
  let string_of_file = Common.string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> Miragevpn.Config.parse_client ~string_of_file str
  | Error _ as e -> e

let jump _ filename pkcs12 =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    (parse_config filename >>= function
     | Error (`Msg s) -> failwith ("config parser: " ^ s)
     | Ok config -> establish_tunnel config pkcs12)

open Cmdliner

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let pkcs12 =
  let doc = "PKCS12 password" in
  Arg.(
    value
    & opt (some string) None
    & info [ "pkcs12-password" ] ~doc ~docv:"PKCS12-PASSWORD")

let cmd =
  let term =
    Term.(term_result (const jump $ Common.setup_log $ config $ pkcs12))
  and info = Cmd.info "miragevpn_client" ~version:"%%VERSION_NUM%%" in
  Cmd.v info term

let () =
  try
    Sys.catch_break true;
    exit (Cmd.eval cmd)
  with Sys.Break -> exit 1
