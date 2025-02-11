type my_key_material = {
  pre_master : string; (* only in client -> server, 48 bytes *)
  random1 : string; (* 32 bytes *)
  random2 : string; (* 32 bytes *)
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

let[@coverage off] pp_transport ppf t =
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
      my_key : Mirage_crypto.AES.CBC.key;
      my_hmac : string;
      their_key : Mirage_crypto.AES.CBC.key;
      their_hmac : string;
    }
  | AES_GCM of {
      my_key : Mirage_crypto.AES.GCM.key;
      my_implicit_iv : string;
      their_key : Mirage_crypto.AES.GCM.key;
      their_implicit_iv : string;
    }
  | CHACHA20_POLY1305 of {
      my_key : Mirage_crypto.Chacha20.key;
      my_implicit_iv : string;
      their_key : Mirage_crypto.Chacha20.key;
      their_implicit_iv : string;
    }

type keys = {
  my_replay_id : int32;
  their_replay_id : int32;
  keys : key_variant;
}

let[@coverage off] pp_keys ppf t =
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
  | Established of Tls.Engine.state * keys

let[@coverage off] pp_channel_state ppf = function
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
  { ch with packets = succ ch.packets; bytes = String.length data + ch.bytes }

let[@coverage off] pp_channel ppf c =
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
  match ch.channel_st with Established (_tls, keys) -> Some keys | _ -> None

let set_keys ch keys =
  let channel_st =
    match ch.channel_st with
    | Established (tls, _) -> Established (tls, keys)
    | x -> x
  in
  { ch with channel_st }

type route_info = Config.t

type event =
  [ `Resolved of Ipaddr.t
  | `Resolve_failed
  | `Connected
  | `Connection_failed
  | `Tick
  | `Data of string ]

let[@coverage off] pp_event ppf = function
  | `Resolved r -> Fmt.pf ppf "resolved %a" Ipaddr.pp r
  | `Resolve_failed -> Fmt.string ppf "resolve failed"
  | `Connected -> Fmt.string ppf "connected"
  | `Connection_failed -> Fmt.string ppf "connection failed"
  | `Tick -> Fmt.string ppf "tick"
  | `Data cs -> Fmt.pf ppf "data %d bytes" (String.length cs)

type initial_action =
  [ `Resolve of [ `host ] Domain_name.t * [ `Ipv4 | `Ipv6 | `Any ]
  | `Connect of Ipaddr.t * int * [ `Tcp | `Udp ] ]

type cc_message = Cc_message.cc_message
type ip_config = { cidr : Ipaddr.V4.Prefix.t; gateway : Ipaddr.V4.t }

type action =
  [ initial_action
  | `Exit
  | `Established of ip_config * int * route_info
  | cc_message ]

let[@coverage off] pp_ip_version ppf = function
  | `Ipv4 -> Fmt.string ppf "ipv4"
  | `Ipv6 -> Fmt.string ppf "ipv6"
  | `Any -> Fmt.string ppf "any"

let[@coverage off] pp_proto ppf = function
  | `Tcp -> Fmt.string ppf "tcp"
  | `Udp -> Fmt.string ppf "udp"

let[@coverage off] pp_ip_config ppf { cidr; gateway } =
  Fmt.pf ppf "ip %a gateway %a" Ipaddr.V4.Prefix.pp cidr Ipaddr.V4.pp gateway

let[@coverage off] pp_action ppf = function
  | `Resolve (host, ip_version) ->
      Fmt.pf ppf "resolve %a (%a)" Domain_name.pp host pp_ip_version ip_version
  | `Connect (ip, port, proto) ->
      Fmt.pf ppf "connect %a %a:%d" pp_proto proto Ipaddr.pp ip port
  | `Exit -> Fmt.string ppf "exit"
  | `Established (ip, mtu, _route_info) ->
      Fmt.pf ppf "established %a, mtu %d" pp_ip_config ip mtu
  | (`Cc_exit | `Cc_restart _ | `Cc_halt _) as msg ->
      Fmt.pf ppf "control channel message %a" Cc_message.pp msg

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

let[@coverage off] pp_session ppf t =
  Fmt.pf ppf
    "compression %B@ protocol %a@ my session %016LX@ replay %lu@ their session \
     %016LX@ replay %lu"
    t.compress pp_proto t.protocol t.my_session_id t.my_replay_id
    t.their_session_id t.their_replay_id

type client_state =
  | Resolving of
      int * int64 * int (* index into [remote], timestamp, retry count *)
  | Connecting of int * int64 * int (* index into [remote], ts, retry count *)
  | Handshaking of int * int64 (* index into [remote], ts *)
  | Ready
  | Rekeying of channel

let[@coverage off] pp_client_state ppf = function
  | Resolving (_idx, _ts, _) -> Fmt.string ppf "resolving"
  | Connecting (_idx, _ts, retry) -> Fmt.pf ppf "connecting (retry %d)" retry
  | Handshaking (_idx, _ts) -> Fmt.string ppf "handshaking"
  | Ready -> Fmt.string ppf "ready"
  | Rekeying c -> Fmt.pf ppf "rekeying %a" pp_channel c

type server_state =
  | Server_handshaking
  | Server_ready
  | Server_rekeying of channel

let[@coverage off] pp_server_state ppf = function
  | Server_handshaking -> Fmt.string ppf "server handshaking"
  | Server_ready -> Fmt.string ppf "server ready"
  | Server_rekeying c -> Fmt.pf ppf "server rekeying %a" pp_channel c

type tls_auth = {
  hmac_algorithm : Digestif.hash';
  my_hmac : string;
  their_hmac : string;
}

type tls_crypt = { my : Tls_crypt.Key.t; their : Tls_crypt.Key.t }

type control_tls =
  [ `Tls_auth of tls_auth
  | `Tls_crypt of tls_crypt * Tls_crypt.Wrapped_key.t option ]

type control_crypto = [ control_tls | `Static of keys ]

let[@coverage off] pp_control_crypto ppf = function
  | `Tls_auth _ -> Fmt.string ppf "tls-auth"
  | `Tls_crypt (_, None) -> Fmt.string ppf "tls-crypt"
  | `Tls_crypt (_, Some _) -> Fmt.string ppf "tls-crypt-v2"
  | `Static _ -> Fmt.string ppf "static"

type state = Client of client_state | Server of server_state

let[@coverage off] pp_state ppf = function
  | Client state -> Fmt.pf ppf "client %a" pp_client_state state
  | Server state -> Fmt.pf ppf "server %a" pp_server_state state

type t = {
  config : Config.t;
  is_not_taken : Ipaddr.V4.t -> bool;
  auth_user_pass : (user:string -> pass:string -> bool) option;
  linger : string;
  control_crypto : control_crypto;
  state : state;
  session : session;
  channel : channel;
  lame_duck : (channel * int64) option;
  last_received : int64;
  last_sent : int64;
  remotes :
    ([ `Domain of [ `host ] Domain_name.t * [ `Ipv4 | `Ipv6 | `Any ]
     | `Ip of Ipaddr.t ]
    * int
    * [ `Udp | `Tcp ])
    list;
}

let[@coverage off] pp ppf t =
  let lame_duck =
    match t.lame_duck with None -> None | Some (ch, _) -> Some ch
  in
  Fmt.pf ppf
    "linger %d@ state %a@ control crypto %a@ session %a@ active %a@ lame duck \
     %a@ last-rcvd %Lu@ last-sent %Lu"
    (String.length t.linger) pp_state t.state pp_control_crypto t.control_crypto
    pp_session t.session pp_channel t.channel
    Fmt.(option ~none:(any "no") pp_channel)
    lame_duck t.last_received t.last_sent

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
      let block_size = Mirage_crypto.AES.CBC.block_size in
      let hmac =
        let module H = (val Digestif.module_of_hash' (Config.get Auth config))
        in
        H.digest_size
      in
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
      let tag_size = Mirage_crypto.AES.GCM.tag_size in
      assert (Mirage_crypto.Chacha20.tag_size = tag_size);
      let hdr =
        Packet.id_len + tag_size + 1
        (* key / op *) + (if compress then 1 else 0)
        + if session.protocol = `Tcp then 2 else 0
      in
      tun_mtu - hdr

let control_mtu config control_crypto session =
  (* we assume to have a tun interface and the server send us a tun-mtu *)
  let tun_mtu =
    match Config.find Tun_mtu config with
    | None -> 1500 (* TODO "client_merge_server_config" should do this! *)
    | Some x -> x
  in
  let mac_len =
    match control_crypto with
    | `Tls_auth _ ->
        (* here, the hash is used from auth *)
        let module H = (val Digestif.module_of_hash' (Config.get Auth config))
        in
        H.digest_size
    | `Tls_crypt _ ->
        (* AES_CTR and SHA256 *)
        Digestif.SHA256.digest_size
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
        | Client (Rekeying channel) when channel.keyid = keyid ->
            let set s ch =
              let state = Client (Rekeying ch) in
              { s with state }
            in
            Some (channel, set)
        | Server (Server_rekeying channel) when channel.keyid = keyid ->
            let set s ch =
              let state = Server (Server_rekeying ch) in
              { s with state }
            in
            Some (channel, set)
        | _ -> None)

let transition_to_established t =
  match t.state with
  | Client (Handshaking _) ->
      let compress =
        match Config.find Comp_lzo t.config with
        | None -> false
        | Some () -> true
      in
      let session = { t.session with compress }
      and mtu = data_mtu t.config t.session in
      Ok ({ t with state = Client Ready; session }, Some mtu)
  | Client (Rekeying _) ->
      (* TODO: may cipher (i.e. mtu) or compress change between rekeys? *)
      let lame_duck = Some (t.channel, Mirage_mtime.elapsed_ns ()) in
      Ok ({ t with state = Client Ready; lame_duck }, None)
  | Server Server_handshaking ->
      let mtu = data_mtu t.config t.session in
      Ok ({ t with state = Server Server_ready }, Some mtu)
  | Server (Server_rekeying _) ->
      (* TODO: may cipher (i.e. mtu) or compress (or IP?) change between rekeys? *)
      let lame_duck = Some (t.channel, Mirage_mtime.elapsed_ns ()) in
      Ok ({ t with state = Server Server_ready; lame_duck }, None)
  | state ->
      Error
        (`Msg
          (Fmt.str "couldn't transition to established, state %a" pp_state state))

type server = {
  server_config : Config.t;
  is_not_taken : Ipaddr.V4.t -> bool;
  auth_user_pass : (user:string -> pass:string -> bool) option;
}

let[@coverage off] pp_server ppf _s = Fmt.pf ppf "server"
