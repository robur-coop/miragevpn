type my_key_material = {
  pre_master : Cstruct.t; (* only in client -> server, 48 bytes *)
  random1 : Cstruct.t; (* 32 bytes *)
  random2 : Cstruct.t; (* 32 bytes *)
}

module IM = Map.Make (Int32)

type transport = {
  my_sequence_number : int32;
      (* this starts from 0l, indicates the next to-be-send *)
  their_sequence_number : int32;
      (* the first should be 0l, indicates the next to-be-received *)
  last_acked_sequence_number : int32;
  out_packets : (int64 * (int * Packet.control)) IM.t;
}

let pp_transport ppf t =
  Fmt.pf ppf "my packet %lu@ their packet %lu@ (acked %lu)@ out %d"
    t.my_sequence_number t.their_sequence_number t.last_acked_sequence_number
    (IM.cardinal t.out_packets)

let init_transport =
  {
    my_sequence_number = 0l;
    their_sequence_number = 0l;
    last_acked_sequence_number = 0l;
    out_packets = IM.empty;
  }

type key_variant =
  | AES_CBC of {
      my_key : Mirage_crypto.Cipher_block.AES.CBC.key;
      my_hmac : Cstruct.t;
      their_key : Mirage_crypto.Cipher_block.AES.CBC.key;
      their_hmac : Cstruct.t;
    }
  | AES_GCM of {
      my_key : Mirage_crypto.Cipher_block.AES.GCM.key;
      my_implicit_iv : Cstruct.t;
      their_key : Mirage_crypto.Cipher_block.AES.GCM.key;
      their_implicit_iv : Cstruct.t;
    }
  | CHACHA20_POLY1305 of {
      my_key : Mirage_crypto.Chacha20.key;
      my_implicit_iv : Cstruct.t;
      their_key : Mirage_crypto.Chacha20.key;
      their_implicit_iv : Cstruct.t;
    }

type keys = {
  my_replay_id : int32;
  their_replay_id : int32;
  keys : key_variant;
}

let pp_keys ppf t =
  Fmt.pf ppf "%s keys: my id %lu, their id %lu"
    (match t.keys with
    | AES_CBC _ -> "AES-CBC"
    | AES_GCM _ -> "AES-GCM"
    | CHACHA20_POLY1305 _ -> "CHACHA20-POLY1305")
    t.my_replay_id t.their_replay_id

type channel_state =
  | Expect_reset
  | TLS_handshake of Tls.Engine.state
  | TLS_established of Tls.Engine.state * my_key_material
  | Push_request_sent of Tls.Engine.state * my_key_material * Packet.tls_data
  | Established of keys

let pp_channel_state ppf = function
  | Expect_reset -> Fmt.string ppf "expecting reset"
  | TLS_handshake _ -> Fmt.string ppf "TLS handshake in process"
  | TLS_established _ -> Fmt.string ppf "TLS handshake established"
  | Push_request_sent _ -> Fmt.string ppf "push request sent"
  | Established _ -> Fmt.string ppf "established"

type channel = {
  keyid : int;
  channel_st : channel_state;
  transport : transport;
  started : int64;
  bytes : int;
  packets : int;
}

let received_packet ch data =
  { ch with packets = succ ch.packets; bytes = Cstruct.length data + ch.bytes }

let pp_channel ppf c =
  Fmt.pf ppf "channel %d %a@ started %Lu bytes %d packets %d@ transport %a"
    c.keyid pp_channel_state c.channel_st c.started c.bytes c.packets
    pp_transport c.transport

let new_channel ?(state = Expect_reset) keyid started =
  {
    keyid;
    channel_st = state;
    transport = init_transport;
    started;
    bytes = 0;
    packets = 0;
  }

let keys_opt ch =
  match ch.channel_st with Established keys -> Some keys | _ -> None

let set_keys ch keys =
  let channel_st =
    match ch.channel_st with Established _ -> Established keys | x -> x
  in
  { ch with channel_st }

type ip_config = { cidr : Ipaddr.V4.Prefix.t; gateway : Ipaddr.V4.t }

let pp_ip_config ppf { cidr; gateway } =
  Fmt.pf ppf "ip %a gateway %a" Ipaddr.V4.Prefix.pp cidr Ipaddr.V4.pp gateway

type event =
  [ `Resolved of Ipaddr.t
  | `Resolve_failed
  | `Connected
  | `Connection_failed
  | `Tick
  | `Data of Cstruct.t ]

let pp_event ppf = function
  | `Resolved r -> Fmt.pf ppf "resolved %a" Ipaddr.pp r
  | `Resolve_failed -> Fmt.string ppf "resolve failed"
  | `Connected -> Fmt.string ppf "connected"
  | `Connection_failed -> Fmt.string ppf "connection failed"
  | `Tick -> Fmt.string ppf "tick"
  | `Data cs -> Fmt.pf ppf "data %d bytes" (Cstruct.length cs)

type initial_action =
  [ `Resolve of [ `host ] Domain_name.t * [ `Ipv4 | `Ipv6 | `Any ]
  | `Connect of Ipaddr.t * int * [ `Tcp | `Udp ] ]

type action =
  [ initial_action
  | `Disconnect
  | `Exit
  | `Established of ip_config * int
  | `Payload of Cstruct.t ]

let pp_ip_version ppf = function
  | `Ipv4 -> Fmt.string ppf "ipv4"
  | `Ipv6 -> Fmt.string ppf "ipv6"
  | `Any -> Fmt.string ppf "any"

let pp_proto ppf = function
  | `Tcp -> Fmt.string ppf "tcp"
  | `Udp -> Fmt.string ppf "udp"

let pp_action ppf = function
  | `Resolve (host, ip_version) ->
      Fmt.pf ppf "resolve %a (%a)" Domain_name.pp host pp_ip_version ip_version
  | `Connect (ip, port, proto) ->
      Fmt.pf ppf "connect %a %a:%d" pp_proto proto Ipaddr.pp ip port
  | `Disconnect -> Fmt.string ppf "disconect"
  | `Exit -> Fmt.string ppf "exit"
  | `Established (ip, mtu) ->
      Fmt.pf ppf "established %a, mtu %d" pp_ip_config ip mtu
  | `Payload x -> Fmt.pf ppf "payload (%d bytes)" (Cstruct.length x)

let ip_from_config config =
  match Config.(get Ifconfig config, get Route_gateway config) with
  | (V4 address, V4 netmask), `Ip (V4 gateway) ->
      let cidr = Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address in
      { cidr; gateway }
  | _ -> assert false

let server_ip config =
  let cidr = Config.get Server config in
  let network = Ipaddr.V4.Prefix.network cidr
  and ip = Ipaddr.V4.Prefix.address cidr in
  if not (Ipaddr.V4.compare ip network = 0) then (ip, cidr)
  else
    (* take first IP in subnet (unless server a.b.c.d/netmask) with a.b.c.d not being the network address *)
    let ip' = Ipaddr.V4.Prefix.first cidr in
    (ip', cidr)

let next_free_ip config is_not_taken =
  let cidr = Config.get Server config in
  let network = Ipaddr.V4.Prefix.network cidr in
  let server_ip = fst (server_ip config) in
  (* could be smarter than a linear search *)
  let rec isit ip =
    if Ipaddr.V4.Prefix.mem ip cidr then
      if
        (not (Ipaddr.V4.compare ip server_ip = 0))
        && (not (Ipaddr.V4.compare ip network = 0))
        && is_not_taken ip
      then
        let cidr' = Ipaddr.V4.Prefix.make (Ipaddr.V4.Prefix.bits cidr) ip in
        Ok (ip, cidr')
      else
        match Ipaddr.V4.succ ip with Ok ip' -> isit ip' | Error e -> Error e
    else Error (`Msg "all ips are taken")
  in
  isit (Ipaddr.V4.Prefix.first cidr)

type session = {
  my_session_id : int64;
  my_replay_id : int32; (* this starts from 1l, indicates the next to-be-send *)
  their_session_id : int64;
  their_replay_id : int32;
      (* the first should be 1l, indicates the next to-be-received *)
  compress : bool;
  protocol : [ `Tcp | `Udp ];
}

let init_session ~my_session_id ?(their_session_id = 0L) ?(compress = false)
    ?(protocol = `Tcp) () =
  {
    my_session_id;
    my_replay_id = 1l;
    their_session_id;
    their_replay_id = 1l;
    compress;
    protocol;
  }

let pp_session ppf t =
  Fmt.pf ppf
    "compression %B@ protocol %a@ my session %016LX@ replay %lu@ their session \
     %016LX@ replay %lu"
    t.compress pp_proto t.protocol t.my_session_id t.my_replay_id
    t.their_session_id t.their_replay_id

type client_state =
  | Resolving of
      int * int64 * int (* index [into remote], timestamp, retry count *)
  | Connecting of int * int64 * int (* index [into remote], ts, retry count *)
  | Handshaking of int * int64 (* index into [remote], ts *)
  | Ready
  | Rekeying of channel

let pp_client_state ppf = function
  | Resolving (_idx, _ts, _) -> Fmt.string ppf "resolving"
  | Connecting (_idx, _ts, retry) -> Fmt.pf ppf "connecting (retry %d)" retry
  | Handshaking (_idx, _ts) -> Fmt.string ppf "handshaking"
  | Ready -> Fmt.string ppf "ready"
  | Rekeying c -> Fmt.pf ppf "rekeying %a" pp_channel c

type server_state =
  | Server_handshaking
  | Server_ready
  | Server_rekeying of channel

let pp_server_state ppf = function
  | Server_handshaking -> Fmt.string ppf "server handshaking"
  | Server_ready -> Fmt.string ppf "server ready"
  | Server_rekeying c -> Fmt.pf ppf "server rekeying %a" pp_channel c

type tls_auth = {
  hmac_algorithm : Mirage_crypto.Hash.hash;
  my_hmac : Cstruct.t;
  their_hmac : Cstruct.t;
}

type tls_crypt_key = Mirage_crypto.Cipher_block.AES.CTR.key

type tls_crypt = {
  my : Tls_crypt.Key.t;
  their : Tls_crypt.Key.t;
}

type state =
  | Client_tls_auth of { tls_auth : tls_auth; state : client_state }
  | Client_tls_crypt of {
      tls_crypt : tls_crypt * Tls_crypt.Wrapped_key.t option;
      state : client_state;
    }
  | Client_static of { keys : keys; state : client_state }
  | Server_tls_auth of { tls_auth : tls_auth; state : server_state }

let pp_state ppf = function
  | Client_tls_auth { state; _ } ->
      Fmt.pf ppf "client tls-auth %a" pp_client_state state
  | Client_tls_crypt { state; tls_crypt = _, None } ->
      Fmt.pf ppf "client tls-crypt %a" pp_client_state state
  | Client_tls_crypt { state; tls_crypt = _, Some _ } ->
      Fmt.pf ppf "client tls-crypt-v2 %a" pp_client_state state
  | Client_static { state; _ } ->
      Fmt.pf ppf "client static %a" pp_client_state state
  | Server_tls_auth { state; _ } -> pp_server_state ppf state

type t = {
  config : Config.t;
  linger : Cstruct.t;
  rng : int -> Cstruct.t;
  ts : unit -> int64;
  now : unit -> Ptime.t;
  state : state;
  session : session;
  channel : channel;
  lame_duck : (channel * int64) option;
  last_received : int64;
  last_sent : int64;
}

let pp ppf t =
  let lame_duck =
    match t.lame_duck with None -> None | Some (ch, _) -> Some ch
  in
  Fmt.pf ppf
    "linger %d@ state %a@ session %a@ active %a@ lame duck %a@ last-rcvd %Lu@ \
     last-sent %Lu"
    (Cstruct.length t.linger) pp_state t.state pp_session t.session pp_channel
    t.channel
    Fmt.(option ~none:(any "no") pp_channel)
    lame_duck t.last_received t.last_sent

let compress s = s.session.compress

let data_mtu config session =
  (* we assume to have a tun interface and the server send us a tun-mtu *)
  let tun_mtu =
    match Config.find Tun_mtu config with
    | None -> 1500 (* TODO "client_merge_server_config" should do this! *)
    | Some x -> x
  and compress = session.compress in
  match Config.get Cipher config with
  | `AES_256_CBC ->
      let static_key_mode = Config.mem Secret config in
      let ts = if static_key_mode then 4 (* timestamp *) else 0 in
      let block_size = Mirage_crypto.Cipher_block.AES.CBC.block_size in
      let hmac = Config.get Auth config |> Mirage_crypto.Hash.digest_size in
      let not_yet_padded_payload =
        Packet.id_len + ts + if compress then 1 else 0
      in
      let hdrs =
        block_size (* IV *) + hmac
        + (if static_key_mode then 0 else 1)
        (* key /op *) + if session.protocol = `Tcp then 2 else 0
      in
      let data = tun_mtu - hdrs in
      (* data is pad ( not_yet_padded_payload + x ) - i.e. we're looking for the
         closest bs-1 number, and subtract not_yet_padded_payload *)
      let pad =
        let res = data mod block_size in
        if res = pred block_size then 0 else succ res
      in
      let r = data - pad - not_yet_padded_payload in
      assert (r > 0);
      r
  | `AES_128_GCM | `AES_256_GCM | `CHACHA20_POLY1305 ->
      let tag_size = Mirage_crypto.Cipher_block.AES.GCM.tag_size in
      assert (Mirage_crypto.Chacha20.tag_size = tag_size);
      let hdr =
        Packet.id_len + tag_size + 1
        (* key / op *) + (if compress then 1 else 0)
        + if session.protocol = `Tcp then 2 else 0
      in
      tun_mtu - hdr

let control_mtu config state session =
  (* we assume to have a tun interface and the server send us a tun-mtu *)
  let tun_mtu =
    match Config.find Tun_mtu config with
    | None -> 1500 (* TODO "client_merge_server_config" should do this! *)
    | Some x -> x
  in
  let mac_len =
    match state with
    | Client_static _ -> assert false
    | Client_tls_auth _ | Server_tls_auth _ ->
        (* here, the hash is used from auth *)
        Config.get Auth config |> Mirage_crypto.Hash.digest_size
    | Client_tls_crypt _ ->
        (* AES_CTR and SHA256 *)
        Mirage_crypto.Hash.SHA256.digest_size
  in
  let pre = 1 (* key / op *) + if session.protocol = `Tcp then 2 else 0 in
  let hdr = Packet.hdr_len mac_len in
  tun_mtu - pre - hdr

let channel_of_keyid keyid s =
  if s.channel.keyid = keyid then
    Some (s.channel, fun s channel -> { s with channel })
  else
    match s.lame_duck with
    | Some (ch, ts) when ch.keyid = keyid ->
        Some (ch, fun s ch -> { s with lame_duck = Some (ch, ts) })
    | _ -> (
        match s.state with
        | Client_tls_auth { state = Rekeying channel; tls_auth }
          when channel.keyid = keyid ->
            let set s ch =
              let state = Client_tls_auth { tls_auth; state = Rekeying ch } in
              { s with state }
            in
            Some (channel, set)
        | Client_tls_crypt { state = Rekeying channel; tls_crypt }
          when channel.keyid = keyid ->
            let set s ch =
              let state = Client_tls_crypt { tls_crypt; state = Rekeying ch } in
              { s with state }
            in
            Some (channel, set)
        | Server_tls_auth { state = Server_rekeying channel; tls_auth }
          when channel.keyid = keyid ->
            let set s ch =
              let state =
                Server_tls_auth { state = Server_rekeying ch; tls_auth }
              in
              { s with state }
            in
            Some (channel, set)
        | _ -> None)

let transition_to_established t =
  match t.state with
  | Client_tls_auth { state = Handshaking _; tls_auth } ->
      let compress =
        match Config.find Comp_lzo t.config with
        | None -> false
        | Some () -> true
      in
      let session = { t.session with compress }
      and mtu = data_mtu t.config t.session in
      Ok
        ( { t with state = Client_tls_auth { state = Ready; tls_auth }; session },
          Some mtu )
  | Client_tls_crypt { state = Handshaking _; tls_crypt } ->
      let compress =
        match Config.find Comp_lzo t.config with
        | None -> false
        | Some () -> true
      in
      let session = { t.session with compress }
      and mtu = data_mtu t.config t.session in
      Ok
        ( {
            t with
            state = Client_tls_crypt { state = Ready; tls_crypt };
            session;
          },
          Some mtu )
  | Client_tls_auth { state = Rekeying _; tls_auth } ->
      (* TODO: may cipher (i.e. mtu) or compress change between rekeys? *)
      let lame_duck = Some (t.channel, t.ts ()) in
      Ok
        ( {
            t with
            state = Client_tls_auth { state = Ready; tls_auth };
            lame_duck;
          },
          None )
  | Client_tls_crypt { state = Rekeying _; tls_crypt } ->
      (* TODO: may cipher (i.e. mtu) or compress change between rekeys? *)
      let lame_duck = Some (t.channel, t.ts ()) in
      Ok
        ( {
            t with
            state = Client_tls_crypt { state = Ready; tls_crypt };
            lame_duck;
          },
          None )
  | Server_tls_auth { state = Server_handshaking; tls_auth } ->
      let mtu = data_mtu t.config t.session in
      Ok
        ( { t with state = Server_tls_auth { state = Server_ready; tls_auth } },
          Some mtu )
  | Server_tls_auth { state = Server_rekeying _; tls_auth } ->
      (* TODO: may cipher (i.e. mtu) or compress (or IP?) change between rekeys? *)
      let lame_duck = Some (t.channel, t.ts ()) in
      Ok
        ( {
            t with
            state = Server_tls_auth { state = Server_ready; tls_auth };
            lame_duck;
          },
          None )
  | (Client_tls_auth _ | Client_tls_crypt _ | Server_tls_auth _) as state ->
      Error
        (`Msg
          (Fmt.str "couldn't transition to established, state %a" pp_state state))
  | Client_static _ -> assert false

type server = {
  server_config : Config.t;
  server_rng : int -> Cstruct.t;
  server_ts : unit -> int64;
  server_now : unit -> Ptime.t;
  tls_auth : tls_auth;
}

let pp_server ppf _s = Fmt.pf ppf "server"
