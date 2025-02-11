open Lwt.Syntax

type established = {
  ip_config : Miragevpn.ip_config;
  mtu : int;
  ping : [ `Ping ] Lwt.t;
  seq_no : int;
}

let ticker () =
  let+ () = Lwt_unix.sleep 1. in
  `Tick

let resolve (name, ip_version) =
  let happy_eyeballs = Happy_eyeballs_lwt.create () in
  let res = Dns_client_lwt.create happy_eyeballs in
  match ip_version with
  | `Ipv4 | `Any -> (
      let+ r = Dns_client_lwt.gethostbyname res name in
      match r with
      | Error (`Msg x) ->
          Logs.warn (fun m ->
              m "gethostbyname for %a return an error: %s" Domain_name.pp name x);
          `Resolve_failed
      | Ok ip -> `Resolved (Ipaddr.V4 ip))
  | `Ipv6 -> (
      let+ r = Dns_client_lwt.gethostbyname6 res name in
      match r with
      | Error (`Msg x) ->
          Logs.warn (fun m ->
              m "gethostbyname for %a return an error: %s" Domain_name.pp name x);
          `Resolve_failed
      | Ok ip -> `Resolved (Ipaddr.V6 ip))

type action =
  [ Miragevpn.action | `Suspend | `Transmit of string | `Payload of string ]

let pp_action ppf = function
  | #Miragevpn.action as action -> Miragevpn.pp_action ppf action
  | `Suspend -> Fmt.pf ppf "suspend"
  | `Transmit data -> Fmt.pf ppf "transmit %u bytes" (String.length data)
  | `Payload data -> Fmt.pf ppf "payload %u bytes" (String.length data)

let event k (tick : [ `Tick ] Lwt.t) client actions ev =
  Logs.debug (fun m -> m "event %a" Miragevpn.pp_event ev);
  let tick = match ev with `Tick -> ticker () | _ -> tick in
  match Miragevpn.handle client ev with
  | Error e ->
      Logs.err (fun m -> m "miragevpn handle failed %a" Miragevpn.pp_error e);
      exit 4
  | Ok (client, outs, payloads, new_action) ->
      let new_actions =
        List.map (fun p -> `Payload p) payloads
        @ List.map (fun out -> `Transmit out) outs
        @ (Option.to_list new_action :> action list)
      in
      k tick client (actions @ new_actions)

let mk_ifconfig (ip_config, mtu, _routes) =
  { ip_config; mtu; ping = Lwt.return `Ping; seq_no = 0 }

let ping_payload =
  Cstruct.of_string "never gonna give you up\nnever gonna let you down\nlalala!"

let send_ping ({ ip_config; seq_no; mtu = _; ping = _ } as ifconfig) =
  let ping =
    {
      Icmpv4_packet.code = 0;
      ty = Icmpv4_wire.Echo_request;
      subheader = Icmpv4_packet.Id_and_seq (1024, seq_no);
    }
  in
  let ifconfig = { ifconfig with seq_no = succ seq_no } in
  let payload = ping_payload in
  let icmpv4_hdr = Icmpv4_packet.Marshal.make_cstruct ~payload ping in
  let ipv4_hdr =
    let src = Ipaddr.V4.Prefix.address ip_config.cidr in
    let dst = ip_config.gateway in
    let off = 0x4000 in
    {
      Ipv4_packet.src;
      dst;
      id = 0;
      off;
      ttl = 38;
      proto = Ipv4_packet.Marshal.protocol_to_int `ICMP;
      options = Cstruct.empty;
    }
  in
  let ipv4_hdr =
    Ipv4_packet.Marshal.make_cstruct
      ~payload_len:(Cstruct.lenv [ icmpv4_hdr; payload ])
      ipv4_hdr
  in
  ( ifconfig,
    Cstruct.to_string (Cstruct.concat [ ipv4_hdr; icmpv4_hdr; payload ]) )

let pong { ip_config; _ } buf =
  let buf = Cstruct.of_string buf in
  let ( let* ) = Result.bind and ( let+ ) = Fun.flip Result.map in
  let* ipv4_hdr, off = Ipv4_packet.Unmarshal.header_of_cstruct buf in
  let buf = Cstruct.shift buf off in
  let* () =
    if
      Ipaddr.V4.compare ipv4_hdr.dst (Ipaddr.V4.Prefix.address ip_config.cidr)
      = 0
    then Ok ()
    else
      Fmt.kstr Result.error "Unknown IPv4 recipient %a" Ipaddr.V4.pp
        ipv4_hdr.dst
  in
  let* protocol =
    Ipv4_packet.Unmarshal.int_to_protocol ipv4_hdr.proto
    |> Option.to_result ~none:"Unknown ipv4 protocol"
  in
  let* () =
    match protocol with `ICMP -> Ok () | _ -> Error "Non-ICMP IPv4 packet"
  in
  let* icmpv4_hdr, buf = Icmpv4_packet.Unmarshal.of_cstruct buf in
  let* () =
    match icmpv4_hdr.ty with
    | Icmpv4_wire.Echo_reply -> Ok ()
    | ty ->
        Fmt.kstr Result.error "ICMP type %a"
          (Fmt.of_to_string Icmpv4_wire.ty_to_string)
          ty
  in
  let* () =
    if icmpv4_hdr.code = 0 then Ok ()
    else Fmt.kstr Result.error "ICMP code %d" icmpv4_hdr.code
  in
  let+ id, seq_no =
    match icmpv4_hdr.subheader with
    | Id_and_seq (id, seq_no) -> Ok (id, seq_no)
    | _ ->
        Fmt.kstr Result.error "Unexpected ICMPv4 subheader %a" Icmpv4_packet.pp
          icmpv4_hdr
  in
  Logs.debug (fun m ->
      m "Received ICMPv4 payload %d bytes" (Cstruct.length buf));
  (id, seq_no)

let _received_pong = ref 0

let rec established_action test proto fd incoming ifconfig tick client actions =
  let action, actions =
    match actions with
    | action :: actions -> ((action :> action), actions)
    | [] -> (`Suspend, actions)
  in
  Logs.debug (fun m -> m "established_action %a" pp_action action);
  match action with
  | `Suspend -> (
      let* ev =
        Lwt.choose
          [
            (tick :> [ Miragevpn.event | `Ping ] Lwt.t);
            (ifconfig.ping :> [ Miragevpn.event | `Ping ] Lwt.t);
            (incoming :> [ Miragevpn.event | `Ping ] Lwt.t);
          ]
      in
      match ev with
      | `Data _ as ev ->
          let incoming = Common.receive proto fd in
          event
            (established_action test proto fd incoming ifconfig)
            tick client actions ev
      | `Connection_failed as ev ->
          event (connecting_action test) tick client actions ev
      | #Miragevpn.event as ev ->
          event
            (established_action test proto fd incoming ifconfig)
            tick client actions ev
      | `Ping -> (
          Logs.app (fun m -> m "Sending ping icmp_seq=%d..." ifconfig.seq_no);
          let ping =
            let+ () = Lwt_unix.sleep 1. in
            `Ping
          in
          let ifconfig = { ifconfig with ping } in
          let ifconfig, data = send_ping ifconfig in
          match Miragevpn.outgoing client data with
          | Ok (client, data) ->
              established_action test proto fd incoming ifconfig tick client
                (`Transmit data :: actions)
          | Error `Not_ready ->
              Logs.warn (fun m ->
                  m
                    "Trying to ping when miragevpn state machine is not ready; \
                     this should never happen");
              established_action test proto fd incoming ifconfig tick client
                actions))
  | `Payload data ->
      (match pong ifconfig data with
      | Ok (_id, seq_no) ->
          Logs.app (fun m -> m "Received pong icmp_seq=%d" seq_no);
          incr _received_pong;
          if test && !_received_pong > 2 then exit 0
      | Error msg -> Logs.app (fun m -> m "Received unexpected data: %s" msg));
      established_action test proto fd incoming ifconfig tick client actions
  | `Exit -> Lwt_result.fail (`Msg "Exiting due to Miragevpn engine exit")
  | `Transmit data ->
      let* r = Common.transmit proto fd data in
      (match r with
      | Ok () -> ()
      | Error (`Msg e) ->
          Logs.err (fun m -> m "transmit error: %s" e);
          exit 3);
      established_action test proto fd incoming ifconfig tick client actions
  | `Established _ ->
      Logs.err (fun m -> m "Unexpected action %a" pp_action action);
      assert false
  | (`Cc_exit | `Cc_halt _ | `Cc_restart _) as action ->
      Logs.warn (fun m -> m "Exiting due to received %a" pp_action action);
      let+ () = Common.safe_close fd in
      exit 0
  | (`Connect _ | `Resolve _) as action ->
      let* () = Common.safe_close fd in
      connecting_action test tick client (action :: actions)

and connected_action test proto fd incoming tick client actions =
  let action, actions =
    match actions with
    | action :: actions -> ((action :> action), actions)
    | [] -> (`Suspend, actions)
  in
  Logs.debug (fun m -> m "connected_action %a" pp_action action);
  match action with
  | `Suspend ->
      let* ev =
        Lwt.choose
          [
            (tick :> [ `Tick | `Data of string | `Connection_failed ] Lwt.t);
            incoming;
          ]
      in
      let k =
        match ev with
        | `Data _ -> connected_action test proto fd (Common.receive proto fd)
        | `Connection_failed -> connecting_action test
        | _ -> connected_action test proto fd incoming
      in
      event k tick client actions (ev :> Miragevpn.event)
  | `Established ((ip, _, _) as ifconfig) ->
      Logs.info (fun m ->
          m "Connection established! %a" Miragevpn.pp_ip_config ip);
      let ifconfig = mk_ifconfig ifconfig in
      established_action test proto fd incoming ifconfig tick client actions
  | `Exit -> Lwt_result.fail (`Msg "Exiting due to Miragevpn engine exit")
  | `Transmit data ->
      let* r = Common.transmit proto fd data in
      (match r with
      | Ok () -> ()
      | Error (`Msg e) ->
          Logs.err (fun m -> m "transmit error: %s" e);
          exit 3);
      connected_action test proto fd incoming tick client actions
  | `Payload _ ->
      Logs.err (fun m -> m "Unexpected action %a" pp_action action);
      assert false
  | (`Cc_exit | `Cc_halt _ | `Cc_restart _) as action ->
      (* TODO: restart and exit should result in reconnect *)
      Logs.warn (fun m -> m "Exiting due to received %a" pp_action action);
      let+ () = Common.safe_close fd in
      exit 0
  | (`Connect _ | `Resolve _) as action ->
      let* () = Common.safe_close fd in
      connecting_action test tick client (action :: actions)

and connecting_action test tick client actions =
  let action, actions =
    match actions with
    | action :: actions -> (action, actions)
    | [] -> (`Suspend, actions)
  in
  Logs.debug (fun m -> m "connecting_action %a" pp_action action);
  match action with
  | `Suspend ->
      let* `Tick = tick in
      event (connecting_action test) tick client actions `Tick
  | `Resolve data ->
      let* ev = resolve data in
      event (connecting_action test) tick client actions ev
  | `Connect (addr, port, proto) ->
      let dom =
        Ipaddr.(Lwt_unix.(match addr with V4 _ -> PF_INET | V6 _ -> PF_INET6))
      and unix_ip = Ipaddr_unix.to_inet_addr addr in
      let sock_typ =
        match proto with `Tcp -> Unix.SOCK_STREAM | `Udp -> Unix.SOCK_DGRAM
      in
      let fd = Lwt_unix.socket dom sock_typ 0 in
      let connect =
        Lwt.catch
          (fun () ->
            let+ () = Lwt_unix.connect fd (ADDR_INET (unix_ip, port)) in
            Logs.app (fun m -> m "Connected to %a:%d" Ipaddr.pp addr port);
            let incoming = Common.receive proto fd in
            (`Connected, connected_action test proto fd incoming))
          (fun e ->
            Logs.err (fun m ->
                m "error %s while connecting to %a:%d" (Printexc.to_string e)
                  Ipaddr.pp addr port);
            let+ () = Common.safe_close fd in
            (`Connection_failed, connecting_action test))
      in
      let* ev, k = connect in
      event k tick client actions ev
  | `Exit -> Lwt_result.fail (`Msg "Exiting due to Miragevpn engine exit")
  | (`Cc_exit | `Cc_halt _ | `Cc_restart _) as action ->
      Logs.warn (fun m -> m "Exiting due to received %a" pp_action action);
      exit 0
  | `Established _ | `Payload _ | `Transmit _ ->
      Logs.err (fun m -> m "Unexpected action %a" pp_action action);
      assert false

let establish_tunnel config pkcs12_password test =
  match Miragevpn.client ?pkcs12_password config with
  | Error (`Msg msg) ->
      Logs.err (fun m -> m "client construction failed: %s" msg);
      exit 3
  | Ok (client, action) ->
      let tick =
        let+ () = Lwt_unix.sleep 1. in
        `Tick
      in
      connecting_action test tick client [ (action :> action) ]

let parse_config filename =
  Lwt.return
  @@
  let dir, filename = Filename.(dirname filename, basename filename) in
  let string_of_file = Common.string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> Miragevpn.Config.parse_client ~string_of_file str
  | Error _ as e -> e

let jump _ filename pkcs12 test =
  Mirage_crypto_rng_unix.use_default ();
  Lwt_main.run
    (let* config = parse_config filename in
     match config with
     | Error (`Msg s) -> failwith ("config parser: " ^ s)
     | Ok config -> establish_tunnel config pkcs12 test)

open Cmdliner

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let test =
  let doc = "Testing mode: exit with exit code 0 upon receiving echo reply" in
  Arg.(value & flag & info [ "test" ] ~doc)

let pkcs12 =
  let doc = "PKCS12 password" in
  Arg.(
    value
    & opt (some string) None
    & info [ "pkcs12-password" ] ~doc ~docv:"PKCS12-PASSWORD")

let cmd =
  let term =
    Term.(term_result (const jump $ Common.setup_log $ config $ pkcs12 $ test))
  and info = Cmd.info "miragevpn_client" ~version:"%%VERSION_NUM%%" in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
