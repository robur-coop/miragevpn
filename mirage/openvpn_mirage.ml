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
    ip_config : Openvpn.ip_config ;
    flow : TCP.flow ;
    mutable linger : Cstruct.t list ;
    mutable frags : Fragments.Cache.t ;
  }

  let now () = Ptime.v (P.now_d_ps ())
  let ts () = M.elapsed_ns ()

  let get_ip t = t.ip_config.Openvpn.ip

  let mtu t = match t.client with
    | `Active t -> Openvpn.mtu t
    | `Error _ -> assert false

  let lift_err ~pp_error v = v >|= Rresult.R.error_to_msg ~pp_error

  let send_multiple flow datas =
    lift_err ~pp_error:TCP.pp_write_error (TCP.writev flow datas)

  let encode_encrypt c hdr data =
    let payload_len = Cstruct.len data
    and hdr_buf = Cstruct.create Ipv4_wire.sizeof_ipv4
    in
    match Ipv4_packet.Marshal.into_cstruct ~payload_len hdr hdr_buf with
    | Error msg ->
      Log.err (fun m -> m "failure while assembling ip frame: %s" msg) ;
      assert false
    | Ok () ->
      Ipv4_common.set_checksum hdr_buf;
      match Openvpn.outgoing c (ts ()) (Cstruct.append hdr_buf data) with
      | Error `Not_ready -> assert false
      | Ok (c', out) -> c', out

  let write t ?(fragment = true) ?(ttl = 38) ?src dst proto ?(size = 0) headerf bufs =
    (* everything must be unfragmented! the Openvpn.outgoing function prepends *)
    (* whatever we get here we may need to split up *)
    Log.debug (fun m -> m "write size %d bufs len %d"
                  size (Cstruct.lenv bufs));
    match t.client with
    | `Error e -> Lwt.return (Error e)
    | `Active c ->
      (* no options here, always 20 bytes IPv4 header size! *)
      (* first figure out the actual payload a user wants *)
      let u_hdr =
        if size > 0 then
          let b = Cstruct.create size in
          let l = headerf b in
          Cstruct.sub b 0 l
        else
          Cstruct.empty
      in
      let payload = Cstruct.concat (u_hdr :: bufs) in
      let pay_len = Cstruct.len payload in
      let hdr =
        let src = match src with None -> get_ip t | Some x -> x in
        let off = if fragment then 0x0000 else 0x4000 in
        Ipv4_packet.{
          options = Cstruct.empty ;
          src ; dst ;
          ttl ; off ; id = 0 ;
          proto = Ipv4_packet.Marshal.protocol_to_int proto }
      in
      (* now we take chunks of (mtu - hdr_len) one at a time *)
      let ip_payload_len = mtu t - Ipv4_wire.sizeof_ipv4 in
      assert (ip_payload_len > 0);
      if not fragment && ip_payload_len < pay_len then
        invalid_arg "don't fragment set, but too much payload!"
      else
        let c', outs =
          if pay_len <= ip_payload_len then
            (* simple case, marshal and go ahead *)
            let c', out = encode_encrypt c hdr payload in
            c', [ out ]
          else
            (* complex case: loop, set more_fragments and offset *)
            (* set an ip ID *)
            (* we also need to ensure that our v4 payload is 8byte-bounded *)
            (*  ~~> since we're at max, we may need to reduce mtu again... *)
            let ip_payload_len' = ip_payload_len - (ip_payload_len mod 8) in
            let frags = (pay_len + pred ip_payload_len') / ip_payload_len' in
            (* do not set more_fragments in last one *)
            let hdr = { hdr with id = Randomconv.int16 R.generate } in
            let c', outs =
              List.fold_left (fun (c, outs) idx ->
                  let start = idx * ip_payload_len' in
                  let off =
                    (if idx = pred frags then 0 else 0x2000) (* more frags *) +
                    (start / 8)
                  in
                  let hdr' = { hdr with off } in
                  let data =
                    let len = min ip_payload_len' (Cstruct.len payload - start) in
                    Cstruct.sub payload start len
                  in
                  let c', out = encode_encrypt c hdr' data in
                  (c', out :: outs))
                (c, []) (List.init frags (fun i -> i))
            in
            c', List.rev outs
        in
        t.client <- `Active c';
        send_multiple t.flow outs >|= function
        | Error e -> t.client <- `Error e ; Error e
        | Ok () -> Ok ()

  let read_react client flow =
    let open Lwt_result.Infix in
    lift_err ~pp_error:TCP.pp_error (TCP.read flow) >>= function
    | `Eof -> Lwt.return (Error (`Msg "received eof"))
    | `Data b ->
      Log.debug (fun m -> m "read %d bytes" (*" %a"*) (Cstruct.len b) (* Cstruct.hexdump_pp b *));
      match client () with
      | Error e ->
        Log.err (fun m -> m "read_react error state %a" pp_error e);
        Lwt.return (Error e)
      | Ok client ->
        lift_err ~pp_error:Openvpn.pp_error
          (Lwt_result.lift (Openvpn.incoming client (now ()) (ts ()) b))

  let input t ~tcp ~udp ~default buf =
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error s ->
      Log.err (fun m -> m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
      Lwt.return_unit
    | Ok (packet, payload) ->
      Log.info (fun m -> m "received IPv4 frame: %a (payload %d bytes)"
                   Ipv4_packet.pp packet (Cstruct.len payload));
      let frags, r = Fragments.process t.frags (ts ()) packet payload in
      t.frags <- frags;
      match r with
      | None -> Lwt.return_unit
      | Some (pkt, payload) ->
        let src, dst = pkt.src, pkt.dst in
        match Ipv4_packet.Unmarshal.int_to_protocol pkt.proto with
        | Some `TCP -> tcp ~src ~dst payload
        | Some `UDP -> udp ~src ~dst payload
        | Some `ICMP | None -> default ~proto:pkt.proto ~src ~dst payload

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
      let client', out = Openvpn.timer client (now ()) (ts ()) in
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
    Lwt_result.lift (Openvpn.client config (now ()) (ts ()) R.generate ())
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
    let frags = Fragments.Cache.empty (1024 * 256) in
    let t = { flow ; client = `Active client' ; ip_config ; linger ; frags } in
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

  let get_ip t = [ get_ip t ]
end
