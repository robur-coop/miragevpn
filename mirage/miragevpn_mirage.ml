(* An OpenVPN layer for MirageOS. Given a stackv4 and a configuration, it
   connects to the OpenVPN gateway in tun mode. Once the tunnel is established,
   an IPv4 stack is returned. *)

(* This effectful OpenVPN client layer is mostly reactive - only when some
   event occured, such as receiving data from the tunnel, a read failure
   (which immediately closes the connection), or a timer `Tick (once every
   second), or an user wants to transmit data (write) over the tunnel, work
   will be done.

   The asynchronous task library Lwt is in use here, which provides cooperative
   tasks -- not preemptive tasks! This means that only at yield points
   (Lwt.bind (>>=) and Lwt.map (>|=)) other tasks can be scheduled. Everything
   between two yield points will happen atomically!

   Speaking of tasks, there are three tasks involved:
   - reader -- which is reading from a given TCP flow (started once
               TCP.create_connection successfully established a connection)
   - timer -- which sleeps for a second, produces a `Tick, in a loop
   - event -- which waits for events (generated by reader and timer), calling
              Miragevpn.handle for each event, and executing potential actions
              asynchronously (via Lwt.async handle_action)

   Synchronisation is achieved by Lwt_mvar.t variables, there are two:
   * data_mvar which gets put when payload has been received over the
               tunnel (it is taken by process_data)
   * est_mvar which gets put once the tunnel is established. connect takes
              that before returning (subsequent put mutate t)
   * event_mvar which gets put by timer/reader/handle_action whenever an
                event occured, the event task above waits for it *)

(* TODO to avoid deadlocks, better be sure that
   (a) until connect returns there ain't any data_mvar put happening -- since
       only the task returned by connect (process_data) calls Lwt_mvar.take --
       to-be-called by the client of this stack *)

open Lwt.Infix

let src = Logs.Src.create "miragevpn.mirage" ~doc:"MirageVPN MirageOS layer"

module Log = (val Logs.src_log src : Logs.LOG)

(* NB for the internal/VPN thingy, a stack is needed that is not backed by an
   ethernet interface or similar, but only virtual (i.e. using 10.8.0.1,
   send/recv operations local only) *)
module Server (S : Tcpip.Stack.V4V6) = struct
  module TCP = S.TCP

  type t = {
    config : Miragevpn.Config.t;
    server : Miragevpn.server;
    ip : Ipaddr.V4.t * Ipaddr.V4.Prefix.t;
    connections : (Ipaddr.V4.t, TCP.flow * Miragevpn.t ref) Hashtbl.t;
    payloadv4_from_tunnel : Ipv4_packet.t -> Cstruct.t -> unit Lwt.t;
  }

  let pp_dst ppf (dst, port) = Fmt.pf ppf "%a:%u" Ipaddr.pp dst port

  let write t dst cs =
    match Hashtbl.find_opt t.connections dst with
    | None ->
        Log.err (fun m -> m "destination %a not found in map" Ipaddr.V4.pp dst);
        Lwt.return_unit
    | Some (flow, state) -> (
        match Miragevpn.outgoing !state (Cstruct.to_string cs) with
        | Error `Not_ready ->
            Log.err (fun m ->
                m "error not_ready while writing to %a" Ipaddr.V4.pp dst);
            Lwt.return_unit
        | Ok (state', enc) -> (
            (* TODO fragmentation!? *)
            state := state';
            TCP.writev flow [ Cstruct.of_string enc ] >|= function
            | Error e ->
                Log.err (fun m ->
                    m "%a tcp write failed %a" Ipaddr.V4.pp dst
                      TCP.pp_write_error e);
                Hashtbl.remove t.connections dst
            | Ok () -> ()))

  let handle_payload t dst source_ip data =
    let data_cs = Cstruct.of_string data in
    match Ipv4_packet.Unmarshal.of_cstruct data_cs with
    | Error e ->
        Log.warn (fun m ->
            m "%a received payload (error %s) %a" pp_dst dst e
              (Ohex.pp_hexdump ()) data);
        Lwt.return_unit
    | Ok (ip, _) when Ipaddr.V4.compare ip.Ipv4_packet.src source_ip <> 0 ->
        Log.warn (fun m ->
            m "%a received payload where source ip %a doesn't match expected %a"
              pp_dst dst Ipaddr.V4.pp ip.Ipv4_packet.src Ipaddr.V4.pp source_ip);
        Lwt.return_unit
    | Ok (ip, _)
      when Ipaddr.V4.(
             compare (Prefix.broadcast (snd t.ip)) ip.Ipv4_packet.dst = 0)
           || Ipaddr.V4.(compare broadcast ip.Ipv4_packet.dst = 0)
           || Ipaddr.V4.is_multicast ip.Ipv4_packet.dst ->
        Log.warn (fun m ->
            m "%a received multicast or broadcast packet, ignoring %a" pp_dst
              dst Ipv4_packet.pp ip);
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
              Ipv4_packet.Marshal.make_cstruct
                ~payload_len:(Cstruct.length data) ip'
            in
            write t ip.src (Cstruct.append hdr data)
        | Ok (icmp, _payload) ->
            Log.warn (fun m ->
                m "ignoring icmp frame from %a: %a" Ipaddr.V4.pp ip.src
                  Icmpv4_packet.pp icmp);
            Lwt.return_unit
        | Error e ->
            Log.warn (fun m ->
                m "ignoring icmp frame from %a, decoding error %s" Ipaddr.V4.pp
                  ip.src e);
            Lwt.return_unit)
    | Ok (ip, _)
      when Miragevpn.Config.mem Client_to_client t.config
           && Ipaddr.V4.Prefix.mem ip.Ipv4_packet.dst (snd t.ip) ->
        (* local routing *)
        let dst = ip.Ipv4_packet.dst in
        if Hashtbl.mem t.connections dst then write t dst data_cs
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
          write t ip.src (Cstruct.append hdr data)
    | Ok (ip, ip_payload) -> t.payloadv4_from_tunnel ip ip_payload

  let handle_action dst add rm ip action =
    match action with
    | `Established ({ Miragevpn.cidr; _ }, _, _) ->
        Log.info (fun m ->
            m "%a insert ip %a, registering flow" pp_dst dst Ipaddr.V4.Prefix.pp
              cidr);
        let ip = Ipaddr.V4.Prefix.address cidr in
        add ip;
        (Some ip, `Continue)
    | `Exit ->
        rm ();
        Log.info (fun m -> m "%a exiting" pp_dst dst);
        (None, `Stop)
    | `Cc_exit ->
        (* server does not produce [`Cc_halt] or [`Cc_restart] actions *)
        rm ();
        Log.info (fun m ->
            m "%a exiting due to explicit exit notification" pp_dst dst);
        (None, `Stop)
    | a ->
        Log.warn (fun m ->
            m "%a ignoring action %a" pp_dst dst Miragevpn.pp_action a);
        (ip, `Continue)

  let callback t flow =
    let dst = TCP.dst flow in
    let rm = function
      | None -> ()
      | Some ip ->
          Log.info (fun m ->
              m "%a removing ip %a from connections" pp_dst dst Ipaddr.V4.pp ip);
          Hashtbl.remove t.connections ip
    and add client_state ip =
      Hashtbl.replace t.connections ip (flow, client_state)
    in
    let rec read ?ip client_state =
      TCP.read flow >>= function
      | Error e ->
          Log.err (fun m ->
              m "%a error %a while reading" pp_dst dst TCP.pp_error e);
          rm ip;
          TCP.close flow
      | Ok `Eof ->
          Log.warn (fun m -> m "%a eof" pp_dst dst);
          rm ip;
          TCP.close flow
      | Ok (`Data cs) -> (
          match
            Miragevpn.handle !client_state (`Data (Cstruct.to_string cs))
          with
          | Error msg ->
              Log.err (fun m ->
                  m "%a internal miragevpn error %a" pp_dst dst
                    Miragevpn.pp_error msg);
              rm ip;
              TCP.close flow
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
      TCP.writev flow (List.map Cstruct.of_string out) >>= function
      | Error e ->
          Log.err (fun m ->
              m "%a tcp write failed %a" pp_dst dst TCP.pp_write_error e);
          rm ip;
          TCP.close flow
      | Ok () -> (
          match continue_or_stop with
          | `Stop -> TCP.close flow
          | `Continue -> read ?ip client_state)
    in
    TCP.read flow >>= function
    | Error e ->
        Log.err (fun m ->
            m "%a error %a while reading" pp_dst dst TCP.pp_error e);
        TCP.close flow
    | Ok `Eof ->
        Log.warn (fun m -> m "%a eof" pp_dst dst);
        TCP.close flow
    | Ok (`Data data) -> (
        match Miragevpn.new_connection t.server (Cstruct.to_string data) with
        | Error e ->
            Logs.warn (fun m ->
                m "couldn't initiate the connection %a" Miragevpn.pp_error e);
            TCP.close flow
        | Ok (cs, out, payloads, action) ->
            let client_state = ref cs in
            Log.info (fun m -> m "%a new connection" pp_dst dst);
            handle client_state out payloads action)

  let rec timer server () =
    (* foreach connection, call handle `Tick and follow instructions! *)
    Hashtbl.fold
      (fun k (flow, t) acc ->
        acc >>= fun acc ->
        match Miragevpn.handle !t `Tick with
        | Error e ->
            Log.err (fun m -> m "error in timer %a" Miragevpn.pp_error e);
            Lwt.return (k :: acc)
        | Ok (_t', _out, _payloads, Some `Exit) ->
            (* TODO anything to do with "_out" or "_payloads"? *)
            Log.warn (fun m -> m "exiting %a" Ipaddr.V4.pp k);
            Lwt.return (k :: acc)
        | Ok (t', out, payloads, act) -> (
            (* TODO anything to do with "_act"? (apart from exit) *)
            Option.iter
              (fun a ->
                Log.warn (fun m ->
                    m "in timer, ignoring action %a" Miragevpn.pp_action a))
              act;
            t := t';
            Lwt_list.iter_p (handle_payload server (TCP.dst flow) k) payloads
            >>= fun () ->
            TCP.writev flow (List.map Cstruct.of_string out) >|= function
            | Error e ->
                Log.err (fun m ->
                    m "%a TCP write failed %a" Ipaddr.V4.pp k TCP.pp_write_error
                      e);
                k :: acc
            | Ok () -> acc))
      server.connections (Lwt.return [])
    >>= fun to_remove ->
    List.iter (Hashtbl.remove server.connections) to_remove;
    Mirage_sleep.ns (Duration.of_sec 1) >>= fun () -> timer server ()

  let connect ?really_no_authentication ?payloadv4_from_tunnel config stack =
    let connections = Hashtbl.create 7 in
    let is_not_taken ip = not (Hashtbl.mem connections ip) in
    match Miragevpn.server ?really_no_authentication ~is_not_taken config with
    | Error (`Msg msg) ->
        Log.err (fun m -> m "server construction failed %s" msg);
        exit 64
    | Ok (server, ip, port) ->
        Log.info (fun m ->
            m "miragevpn server listening on port %d, using %a/%d" port
              Ipaddr.V4.pp (fst ip)
              (Ipaddr.V4.Prefix.bits (snd ip)));
        let payloadv4_from_tunnel =
          Option.value
            ~default:(fun ip _ ->
              Log.info (fun m ->
                  m "ignoring IPv4 packet from tunnel %a" Ipv4_packet.pp ip);
              Lwt.return_unit)
            payloadv4_from_tunnel
        in
        let server =
          { config; server; ip; connections; payloadv4_from_tunnel }
        in
        S.TCP.listen (S.tcp stack) ~port (callback server);
        Lwt.async (timer server);
        server
end

module Client_router (S : Tcpip.Stack.V4V6) = struct
  module H = Happy_eyeballs_mirage.Make (S)
  module DNS = Dns_client_mirage.Make (S) (H)
  module TCP = S.TCP
  module UDP = S.UDP

  type conn = {
    mutable o_client : Miragevpn.t;
    mutable peer :
      [ `Udp of UDP.t * (int * Ipaddr.t * int) | `Tcp of TCP.flow ] option;
    mutable est_switch : Lwt_switch.t;
    data_mvar : Cstruct.t list Lwt_mvar.t;
    est_mvar : (Miragevpn.ip_config * int * Miragevpn.route_info) Lwt_mvar.t;
    event_mvar : Miragevpn.event Lwt_mvar.t;
  }

  type t = {
    conn : conn;
    mutable ip_config : Miragevpn.ip_config;
    mutable mtu : int;
  }

  let get_ip t = Ipaddr.V4.Prefix.address t.ip_config.Miragevpn.cidr
  let configured_ips t = [ t.ip_config.Miragevpn.cidr ]
  let mtu t = t.mtu

  let transmit_tcp flow data =
    let ip, port = TCP.dst flow in
    Log.debug (fun m ->
        m "sending %d bytes to %a:%d" (Cstruct.lenv data) Ipaddr.pp ip port);
    TCP.writev flow data >>= function
    | Ok () -> Lwt.return true
    | Error e ->
        TCP.close flow >|= fun () ->
        Log.err (fun m -> m "tcp write failed %a" TCP.pp_write_error e);
        false

  let transmit_udp udp (src_port, dst, dst_port) data =
    match data with
    | [] -> Lwt.return true
    | xs ->
        Lwt_list.fold_left_s
          (fun acc pkt ->
            UDP.write ~src_port ~dst ~dst_port udp pkt >|= function
            | Ok () -> acc
            | Error e ->
                Log.err (fun m -> m "udp write failed %a" UDP.pp_error e);
                false)
          true xs

  let transmit where data =
    let data = List.map Cstruct.of_string data in
    match (data, where) with
    | [], _ -> Lwt.return true
    | _, Some (`Tcp flow) -> transmit_tcp flow data
    | _, Some (`Udp (udp, peer)) -> transmit_udp udp peer data
    | _, None ->
        Log.err (fun m -> m "transmit, but no peer");
        Lwt.return false

  let write t data =
    match Miragevpn.outgoing t.conn.o_client (Cstruct.to_string data) with
    | Error `Not_ready ->
        Log.warn (fun m -> m "tunnel not ready, dropping data!");
        Lwt.return false
    | Ok (c', out) ->
        t.conn.o_client <- c';
        transmit t.conn.peer [ out ]

  let read t = Lwt_mvar.take t.conn.data_mvar

  let resolve_hostname s name =
    let happy_eyeballs = H.create s in
    let res = DNS.create (s, happy_eyeballs) in
    DNS.gethostbyname res name >|= function
    | Ok ip -> Some (Ipaddr.V4 ip)
    | Error (`Msg msg) ->
        Log.err (fun m -> m "failed to resolve %a: %s" Domain_name.pp name msg);
        None

  let read_flow flow =
    TCP.read flow >|= fun r ->
    match r with
    | Ok (`Data b) -> `Data (Cstruct.to_string b)
    | Ok `Eof ->
        Log.err (fun m -> m "eof while reading");
        `Connection_failed
    | Error e ->
        Log.err (fun m -> m "tcp read error %a" TCP.pp_error e);
        `Connection_failed

  let rec reader c flow =
    let ip, port = TCP.dst flow in
    Log.debug (fun m -> m "reading flow %a:%d" Ipaddr.pp ip port);
    read_flow flow >>= fun r ->
    let n =
      match r with
      | `Connection_failed -> 0
      | `Data r -> String.length r
      | _ -> assert false
    in
    Log.debug (fun m -> m "read flow %a:%d (%d bytes)" Ipaddr.pp ip port n);
    Lwt_mvar.put c r >>= fun () ->
    match r with
    | `Data _ -> reader c flow
    | _ ->
        Log.err (fun m -> m "connection failed, terminating reader");
        Lwt.return_unit

  let udp_read_cb port c (our_port, peer_ip, their_port) ~src ~dst:_ ~src_port
      data =
    if
      port = our_port && src_port = their_port && Ipaddr.compare peer_ip src = 0
    then (
      Log.debug (fun m ->
          m "read %a:%d (%d bytes)" Ipaddr.pp src src_port (Cstruct.length data));
      Lwt_mvar.put c (`Data (Cstruct.to_string data)))
    else (
      Log.info (fun m ->
          m
            "ignoring unsolicited data from %a:%d (expected %a:%d, our %d dst \
             %d)"
            Ipaddr.pp src src_port Ipaddr.pp peer_ip their_port our_port port);
      Lwt.return_unit)

  let connect_tcp s (ip, port) =
    TCP.create_connection (S.tcp s) (ip, port) >|= function
    | Ok flow ->
        Log.info (fun m ->
            m "connection to %a:%d established" Ipaddr.pp ip port);
        Some flow
    | Error tcp_err ->
        Log.err (fun m ->
            m "failed to connect to %a:%d: %a" Ipaddr.pp ip port TCP.pp_error
              tcp_err);
        None

  let handle_action s conn = function
    | `Resolve (name, _ip_version) ->
        Lwt_switch.turn_off conn.est_switch >>= fun () ->
        resolve_hostname s name >>= fun r ->
        let ev =
          match r with None -> `Resolve_failed | Some x -> `Resolved x
        in
        Lwt_mvar.put conn.event_mvar ev
    | `Connect (ip, port, `Udp) ->
        (* we don't use the switch, but an earlier connection attempt may have used TCP *)
        Lwt_switch.turn_off conn.est_switch >>= fun () ->
        conn.est_switch <- Lwt_switch.create ();
        (* TODO we may wish to filter certain ports (< 1024) *)
        let our_port = Randomconv.int16 Mirage_crypto_rng.generate in
        let peer = (our_port, ip, port) in
        conn.peer <- Some (`Udp (S.udp s, peer));
        S.UDP.listen (S.udp s) ~port:our_port
          (udp_read_cb our_port conn.event_mvar peer);
        (* TODO for UDP, we atm can't figure out connection failures
           (timeout should work, but ICMP refused/.. won't be delivered here) *)
        Lwt_mvar.put conn.event_mvar `Connected
    | `Connect (ip, port, `Tcp) ->
        Lwt_switch.turn_off conn.est_switch >>= fun () ->
        let sw = Lwt_switch.create () in
        conn.est_switch <- sw;
        connect_tcp s (ip, port) >>= fun r ->
        if Lwt_switch.is_on sw then
          let ev =
            match r with
            | None -> `Connection_failed
            | Some flow ->
                conn.peer <- Some (`Tcp flow);
                Lwt.async (fun () -> reader conn.event_mvar flow);
                Log.info (fun m ->
                    m "successfully established connection to %a:%d" Ipaddr.pp
                      ip port);
                `Connected
          in
          Lwt_mvar.put conn.event_mvar ev
        else (
          Log.warn (fun m -> m "ignoring connection (cancelled by switch)");
          match r with None -> Lwt.return_unit | Some f -> TCP.close f)
    | `Exit -> (* FIXME *) failwith "exit called"
    | (`Cc_exit | `Cc_restart _ | `Cc_halt _) as exit_msg ->
        (* FIXME *)
        Format.kasprintf failwith "%a received" Miragevpn.pp_action exit_msg
    | `Established (ip, mtu, route_info) ->
        Log.debug (fun m -> m "action = established");
        Lwt_mvar.put conn.est_mvar (ip, mtu, route_info)

  let rec event s conn =
    Lwt_mvar.take conn.event_mvar >>= fun ev ->
    Log.debug (fun m ->
        m "now for real processing event %a" Miragevpn.pp_event ev);
    match Miragevpn.handle conn.o_client ev with
    | Error e ->
        Log.err (fun m -> m "miragevpn handle failed %a" Miragevpn.pp_error e);
        handle_action s conn `Exit
    | Ok (t', outs, payloads, action) ->
        conn.o_client <- t';
        (match payloads with
        | [] -> Lwt.return_unit
        | _ -> Lwt_mvar.put conn.data_mvar (List.map Cstruct.of_string payloads))
        >>= fun () ->
        (match outs with
        | [] -> Lwt.return_unit
        | _ -> (
            transmit conn.peer outs >>= function
            | true -> Lwt.return_unit
            | false -> Lwt_mvar.put conn.event_mvar `Connection_failed))
        >>= fun () ->
        Option.iter
          (fun a ->
            Log.debug (fun m -> m "handling action %a" Miragevpn.pp_action a);
            Lwt.async (fun () -> handle_action s conn a))
          action;
        event s conn

  let connect config s =
    match Miragevpn.client config with
    | Error (`Msg msg) ->
        Log.err (fun m -> m "client construction failed %s" msg);
        Lwt.return (Error (`Msg msg))
    | Ok (o_client, action) ->
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
        Lwt.async (fun () -> event s conn);
        let rec tick () =
          Mirage_sleep.ns (Duration.of_sec 1) >>= fun () ->
          Lwt_mvar.put event_mvar `Tick >>= fun () -> tick ()
        in
        Lwt.async tick;
        Lwt.async (fun () -> handle_action s conn action);
        Log.debug (fun m -> m "waiting for established");
        Lwt_mvar.take est_mvar >|= fun (ip_config, mtu, _route_info) ->
        (* TODO: routes *)
        Log.debug (fun m ->
            m "now established %a (mtu %d)" Miragevpn.pp_ip_config ip_config mtu);
        let t = { conn; ip_config; mtu } in
        let rec established () =
          (* TODO: signal to upper layer!? *)
          Lwt_mvar.take est_mvar >>= fun (ip_config', mtu', _route_info) ->
          let ip_changed =
            let i c = Ipaddr.V4.Prefix.address c.Miragevpn.cidr in
            Ipaddr.V4.compare (i ip_config) (i ip_config') <> 0
          in
          Log.debug (fun m ->
              m "tunnel re-established (ip changed? %B) %a (mtu %d)" ip_changed
                Miragevpn.pp_ip_config ip_config' mtu');
          if ip_changed then t.ip_config <- ip_config';
          (* not sure about mtu changes, but better to update this in any case *)
          t.mtu <- mtu';
          established ()
        in
        Lwt.async established;
        Log.info (fun m -> m "returning from connect");
        Ok t
end

module Client_stack (S : Tcpip.Stack.V4V6) = struct
  module O = Client_router (S)

  type t = { ovpn : O.t; mutable frags : Fragments.Cache.t }

  (* boilerplate i don't understand *)
  type ipaddr = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t

  let pp_ipaddr = Ipaddr.V4.pp

  type error =
    [ Tcpip.Ip.error
    | `Msg of string
    | `Would_fragment
    | `Openvpn of Miragevpn.error ]

  let pp_error ppf = function
    | #Tcpip.Ip.error as e -> Tcpip.Ip.pp_error ppf e
    | `Msg m -> Fmt.pf ppf "message %s" m
    | `Openvpn e -> Miragevpn.pp_error ppf e

  let disconnect _ =
    Log.warn (fun m -> m "disconnect called, should I do something?");
    Lwt.return_unit

  let get_ip t = O.get_ip t.ovpn
  let mtu t ~dst:_ = O.mtu t.ovpn

  type prefix = Ipaddr.V4.Prefix.t

  let pp_prefix = Ipaddr.V4.Prefix.pp
  let configured_ips t = O.configured_ips t.ovpn

  let encode hdr data =
    let payload_len = Cstruct.length data
    and hdr_buf = Cstruct.create Ipv4_wire.sizeof_ipv4 in
    match Ipv4_packet.Marshal.into_cstruct ~payload_len hdr hdr_buf with
    | Error msg ->
        Log.err (fun m -> m "failure while assembling ip frame: %s" msg);
        assert false
    | Ok () -> Cstruct.append hdr_buf data

  let write t ?(fragment = true) ?(ttl = 38) ?src dst proto ?(size = 0) headerf
      bufs =
    (* everything must be unfragmented! the Miragevpn.outgoing function prepends *)
    (* whatever we get here we may need to split up *)
    Log.debug (fun m -> m "write size %d bufs len %d" size (Cstruct.lenv bufs));
    (* no options here, always 20 bytes IPv4 header size! *)
    (* first figure out the actual payload a user wants *)
    let u_hdr =
      if size > 0 then
        let b = Cstruct.create size in
        let l = headerf b in
        Cstruct.sub b 0 l
      else Cstruct.empty
    in
    let payload = Cstruct.concat (u_hdr :: bufs) in
    let pay_len = Cstruct.length payload in
    let hdr =
      let src = match src with None -> get_ip t | Some x -> x in
      let off = if fragment then 0x0000 else 0x4000 in
      Ipv4_packet.
        {
          options = Cstruct.empty;
          src;
          dst;
          ttl;
          off;
          id = 0;
          proto = Ipv4_packet.Marshal.protocol_to_int proto;
        }
    in
    (* now we take chunks of (mtu - hdr_len) one at a time *)
    let mtu = mtu t ~dst in
    let ip_payload_len = mtu - Ipv4_wire.sizeof_ipv4 in
    if ((not fragment) && ip_payload_len < pay_len) || ip_payload_len <= 0 then
      Lwt.return (Error `Would_fragment)
    else
      let outs =
        if pay_len <= ip_payload_len then
          (* simple case, marshal and go ahead *)
          let out = encode hdr payload in
          [ out ]
        else
          (* fragment payload: set ip ID and more_fragments in header *)
          (* need to ensure that our v4 payload is 8byte-bounded *)
          let ip_payload_len' = ip_payload_len - (ip_payload_len mod 8) in
          let hdr =
            {
              hdr with
              id = Randomconv.int16 Mirage_crypto_rng.generate;
              off = 0x2000;
            }
          in
          let pay, rest = Cstruct.split payload ip_payload_len' in
          let first = encode hdr pay in
          let outs = Fragments.fragment ~mtu hdr rest in
          first :: outs
      in
      Lwt_list.fold_left_s
        (fun acc data ->
          match acc with
          | Error e -> Lwt.return (Error e)
          | Ok () ->
              O.write t.ovpn data >|= fun r ->
              if r then Ok () else Error (`Msg "write failed"))
        (Ok ()) outs

  let input t ~tcp ~udp ~default buf =
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error s ->
        Log.err (fun m ->
            m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
        Lwt.return_unit
    | Ok (packet, payload) -> (
        Log.debug (fun m ->
            m "received IPv4 frame: %a (payload %d bytes)" Ipv4_packet.pp packet
              (Cstruct.length payload));
        let f', r =
          Fragments.process t.frags (Mirage_mtime.elapsed_ns ()) packet payload
        in
        t.frags <- f';
        match r with
        | None -> Lwt.return_unit
        | Some (pkt, payload) -> (
            let src, dst = (pkt.src, pkt.dst) in
            match Ipv4_packet.Unmarshal.int_to_protocol pkt.proto with
            | Some `TCP -> tcp ~src ~dst payload
            | Some `UDP -> udp ~src ~dst payload
            | Some `ICMP | None -> default ~proto:pkt.proto ~src ~dst payload))

  let rec process_data ~tcp ~udp ~default t =
    Log.debug (fun m -> m "processing data");
    O.read t.ovpn >>= fun datas ->
    Log.debug (fun m ->
        m "now for real processing data (len %d)" (Cstruct.lenv datas));
    Lwt_list.iter_p (input t ~tcp ~udp ~default) datas >>= fun () ->
    process_data ~tcp ~udp ~default t

  let connect cfg s =
    O.connect cfg s >|= function
    | Error e -> Error e
    | Ok ovpn ->
        let frags = Fragments.Cache.empty (1024 * 256) in
        Ok ({ ovpn; frags }, process_data)

  let pseudoheader t ?src dst proto len =
    let src = match src with Some x -> x | None -> get_ip t in
    Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto len

  let src t ~dst:_ = get_ip t
  let get_ip t = [ get_ip t ]
end
