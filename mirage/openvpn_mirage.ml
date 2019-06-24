(* An OpenVPN layer for MirageOS. Given a stackv4 and a configuration, it
   connects to the OpenVPN gateway in tun mode. Once the tunnel is established,
   an IPv4 stack is returned.
*)

open Lwt.Infix

let src = Logs.Src.create "openvpn.mirage" ~doc:"OpenVPN MirageOS layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.C) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (T : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) = struct
  (* boilerplate i don't understand *)
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t
  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

  type error = [ Mirage_protocols.Ip.error
               | `Msg of string
               | `Would_fragment
               | `Openvpn of Openvpn.error ]
  let pp_error ppf = function
    | #Mirage_protocols.Ip.error as e -> Mirage_protocols.Ip.pp_error ppf e
    | `Msg m -> Fmt.pf ppf "message %s" m
    | `Would_fragment -> Fmt.string ppf "would fragment, but fragmentation is disabled"
    | `Openvpn e -> Openvpn.pp_error ppf e

  module DNS = Dns_mirage_client.Make(S)
  module TCP = S.TCPV4

  type t = {
    mutable client : [ `Active of Openvpn.t | `Error of error ] ;
    config : Openvpn_config.t ;
    ip_config : Openvpn.ip_config ;
    flow : TCP.flow ;
    mutable linger : Cstruct.t list ;
  }

  let get_ip t = t.ip_config.Openvpn.ip

  let lift_err ~pp_error v =
    v >|= Rresult.R.error_to_msg ~pp_error

  let send_multiple flow datas =
    lift_err ~pp_error:TCP.pp_write_error
      (Lwt_list.fold_left_s (fun r data ->
           match r with
           | Ok () ->
             Log.debug (fun m -> m "writing %d bytes %a" (Cstruct.len data)
                           Cstruct.hexdump_pp data);
             TCP.write flow data
           | Error e -> Lwt.return (Error e))
          (Ok ()) datas)

  let write t ?(fragment = true) ?(ttl = 38) ?src dst proto ?(size = 0) headerf bufs =
    (* plan: if we're active, assemble the packet, encrypt, and output *)
    (* TODO: mostly copied from static_ipv4 *)
    (* TODO: no fragmentation (yet) *)
    match t.client with
    | `Error e -> Lwt.return (Error e)
    | `Active c ->
      (* no options here, always 20 bytes! *)
      let hdr_len = Ipv4_wire.sizeof_ipv4 in
      let hdr =
        let src = match src with None -> get_ip t | Some x -> x in
        let off = if fragment then 0x0000 else 0x4000 in
        Ipv4_packet.{
          options = Cstruct.empty ;
          src ; dst ;
          ttl ; off ; id = 0 ;
          proto = Ipv4_packet.Marshal.protocol_to_int proto }
      in
      let hdr_buf = Cstruct.create hdr_len in
      let payload =
        if size > 0 then begin
          let b = Cstruct.create size in
          let header_len = headerf b in
          if header_len > size then begin
            Log.err (fun m -> m "headers returned length exceeding size") ;
            invalid_arg "headerf exceeds size"
          end ;
          Cstruct.concat (b :: bufs)
        end else
          Cstruct.concat bufs
      in
      let payload_len = Cstruct.len payload in
      match Ipv4_packet.Marshal.into_cstruct ~payload_len hdr hdr_buf with
      | Error msg ->
        Log.err (fun m -> m "failure while assembling ip frame: %s" msg) ;
        invalid_arg msg
      | Ok () ->
        Ipv4_common.set_checksum hdr_buf;
        match Openvpn.outgoing c (M.elapsed_ns ()) (Cstruct.append hdr_buf payload) with
        | Ok (c', outs) ->
          begin
            t.client <- `Active c';
            send_multiple t.flow outs >|= function
            | Ok () -> Ok ()
            | Error e -> t.client <- `Error e ; Error e
          end
        | Error `Not_ready -> assert false

  let read_react client flow =
    let open Lwt_result.Infix in
    lift_err ~pp_error:TCP.pp_error (TCP.read flow) >>= function
    | `Eof -> Lwt.return (Error (`Msg "received eof"))
    | `Data b ->
      Log.debug (fun m -> m "read %d bytes %a" (Cstruct.len b) Cstruct.hexdump_pp b);
      match client () with
      | Error e -> Log.err (fun m -> m "read_react error state %a" pp_error e) ; Lwt.return (Error e)
      | Ok client ->
        lift_err ~pp_error:Openvpn.pp_error
          (Lwt_result.lift
             (Openvpn.incoming client (Ptime.v (P.now_d_ps ())) (M.elapsed_ns ()) b))

  let input _t ~tcp ~udp ~default buf =
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error s ->
      Log.err (fun m -> m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
      Lwt.return_unit
    | Ok (packet, payload) ->
      Log.info (fun m -> m "received IPv4 frame: %a (payload %d bytes)"
                   Ipv4_packet.pp packet (Cstruct.len payload));
      let src, dst = packet.src, packet.dst in
      match Ipv4_packet.Unmarshal.int_to_protocol packet.proto with
      | Some `TCP -> tcp ~src ~dst payload
      | Some `UDP -> udp ~src ~dst payload
      | Some `ICMP | None -> default ~proto:packet.proto ~src ~dst payload

  let rec read_and_process ~tcp ~udp ~default t =
    begin match t.linger with
      | a::xs -> t.linger <- xs ; Lwt.return (Ok (Some a))
      | [] ->
        read_react (fun () -> match t.client with `Active c -> Ok c | `Error e -> Error e) t.flow >>= function
        | Error e -> t.client <- `Error e ; Lwt.return (Error e)
        | Ok (client', outs, app) ->
          t.client <- `Active client' ;
          let pkt, linger = match app with a :: xs -> Some a, xs | [] -> None, [] in
          t.linger <- linger ;
          (send_multiple t.flow outs >|= function
            | Error e -> t.client <- `Error e
            | Ok () -> ()) >|= fun () ->
          Ok pkt
    end >>= function
    | Error e ->
      Logs.err (fun m -> m "error %a while reading from remote" pp_error e);
      Lwt.return_unit
    | Ok None ->
      Log.info (fun m -> m "read and process but no app data");
      read_and_process ~tcp ~udp ~default t
    | Ok (Some pkt) ->
      input t ~tcp ~udp ~default pkt >>= fun () ->
      read_and_process ~tcp ~udp ~default t

  let rec establish_tunnel client flow =
    let open Lwt_result.Infix in
    read_react (fun _ -> Ok client) flow >>= fun (client', outs, app) ->
    send_multiple flow outs >>= fun () ->
    match Openvpn.ready client' with
    | None -> establish_tunnel client' flow
    | Some ip_config -> Lwt.return (Ok (client', ip_config, app))

  let rec ping t =
    match t.client with
    | `Active client ->
      let client', out = Openvpn.timer client (M.elapsed_ns ()) in
      t.client <- `Active client';
      (match out with [] -> () | _ -> Log.info (fun m -> m "sending ping"));
      send_multiple t.flow out >>= fun _ ->
      T.sleep_ns (Duration.of_sec 1) >>= fun () ->
      ping t
    | _ ->
      Log.err (fun m -> m "stopping ping, not active anymore");
      Lwt.return_unit

  let connect config s =
    let open Lwt_result.Infix in
    Lwt_result.lift (Openvpn.client config (Ptime.v (P.now_d_ps ())) (M.elapsed_ns ()) R.generate ())
    >>= fun (client, remote, data) ->
    (match remote with
     | (`IP (Ipaddr.V4 ip), port) :: _ -> Lwt.return (Ok (ip, port))
     | (`Domain name, port) :: _ ->
       let res = DNS.create s in
       DNS.gethostbyname res name >|= fun ip ->
       (ip, port)
     | _ -> Lwt.return (Error (`Msg "bad openvpn config, no suitable remote"))) >>= fun remote ->
    lift_err ~pp_error:TCP.pp_error (TCP.create_connection (S.tcpv4 s) remote) >>= fun flow ->
    lift_err ~pp_error:TCP.pp_write_error (TCP.write flow data) >>= fun () ->
    establish_tunnel client flow >|= fun (client', ip_config, linger) ->
    let t = { flow ; client = `Active client' ; config ; ip_config ; linger } in
    Lwt.async (fun () -> ping t);
    t, read_and_process

  let disconnect _ =
    Log.warn (fun m -> m "disconnect called, should I do something?");
    Lwt.return_unit

  let set_ip _ _ =
    Log.warn (fun m -> m "set ip not supported by OpenVPN");
    Lwt.return_unit

  let pseudoheader t ?src dst proto len =
    let src = match src with
      | Some x -> x
      | None -> get_ip t
    in
    Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto len

  let src t ~dst:_ = get_ip t

  let mtu _t =
    (* TODO get from OpenVPN configuration *)
    1500

  let get_ip t = [ get_ip t ]
end
