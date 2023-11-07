open State

module Log =
  (val Logs.(
         src_log
         @@ Src.create ~doc:"Miragevpn library's engine module" "ovpn.engine")
      : Logs.LOG)

let tls_ciphers config =
  (* update when ocaml-tls changes default ciphers *)
  let tls_default_ciphers13 =
    [
      `AES_128_GCM_SHA256;
      `AES_256_GCM_SHA384;
      `CHACHA20_POLY1305_SHA256;
      `AES_128_CCM_SHA256;
    ]
  and tls_default_ciphers =
    [
      `DHE_RSA_WITH_AES_256_GCM_SHA384;
      `DHE_RSA_WITH_AES_128_GCM_SHA256;
      `DHE_RSA_WITH_AES_256_CCM;
      `DHE_RSA_WITH_AES_128_CCM;
      `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
      `ECDHE_RSA_WITH_AES_128_GCM_SHA256;
      `ECDHE_RSA_WITH_AES_256_GCM_SHA384;
      `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
      `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
      `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
      `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    ]
  in
  match (Config.find Tls_cipher config, Config.find Tls_ciphersuite config) with
  | Some c, None -> Some (c @ tls_default_ciphers13)
  | None, Some c ->
      Some (tls_default_ciphers @ (c :> Tls.Ciphersuite.ciphersuite list))
  | Some c, Some c' -> Some (c @ (c' :> Tls.Ciphersuite.ciphersuite list))
  | None, None -> None

let tls_version config =
  (* update when ocaml-tls supports new versions *)
  let tls_lowest_version = `TLS_1_0 and tls_highest_version = `TLS_1_3 in
  let lower_bound =
    match Config.find Tls_version_min config with
    | None -> None
    | Some (v, or_highest) ->
        if or_highest then Some tls_highest_version else Some v
  and upper_bound = Config.find Tls_version_max config in
  match (lower_bound, upper_bound) with
  | None, None -> None
  | Some a, Some b -> Some (a, b)
  | Some a, None -> Some (a, tls_highest_version)
  | None, Some b -> Some (tls_lowest_version, b)

let guard p e = if p then Ok () else Error e
let opt_guard p x e = match x with None -> Ok () | Some x -> guard (p x) e

let next_message_id state =
  ( { state with my_message_id = Int32.succ state.my_message_id },
    state.my_message_id )

let header session transport timestamp =
  let rec acked_message_ids id =
    if transport.their_message_id = id then []
    else id :: acked_message_ids (Int32.succ id)
  in
  let ack_message_ids = acked_message_ids transport.last_acked_message_id in
  let remote_session =
    match ack_message_ids with [] -> None | _ -> Some session.their_session_id
  in
  let packet_id = session.my_packet_id
  and last_acked_message_id = transport.their_message_id in
  let my_packet_id = Int32.succ packet_id in
  ( { session with my_packet_id },
    { transport with last_acked_message_id },
    {
      Packet.local_session = session.my_session_id;
      hmac = Cstruct.empty;
      packet_id;
      timestamp;
      ack_message_ids;
      remote_session;
    } )

let ptime_to_ts_exn now =
  match Ptime.(Span.to_int_s (to_span now)) with
  | None -> assert false (* this will break in 2038-01-19 *)
  | Some x -> Int32.of_int x

let compute_hmac key p hmac_algorithm hmac_key =
  let tbs = Packet.to_be_signed key p in
  Mirage_crypto.Hash.mac hmac_algorithm ~key:hmac_key tbs

let hmac_and_out protocol { hmac_algorithm; my_hmac; _ }
    (key, (p : [< Packet.ack | Packet.control ])) =
  let hmac = compute_hmac key p hmac_algorithm my_hmac in
  let header = Packet.header p in
  let p' = Packet.with_header { header with Packet.hmac } p in
  Packet.encode protocol (key, p')

let encrypt_and_out protocol { my_key; my_hmac; _ }
    (key, (p : [< Packet.ack | Packet.control ])) =
  let to_be_signed = Packet.Tls_crypt.to_be_signed key p in
  let hmac = Mirage_crypto.Hash.SHA256.hmac ~key:my_hmac to_be_signed in
  let iv = Cstruct.sub hmac 0 16 in
  let ctr = Mirage_crypto.Cipher_block.AES.CTR.ctr_of_cstruct iv in
  let header = Packet.header p in
  let p = Packet.with_header { header with Packet.hmac } p in
  let buf, enc_off, enc_len = Packet.Tls_crypt.encode protocol (key, p) in
  let encrypted =
    Mirage_crypto.Cipher_block.AES.CTR.encrypt ~key:my_key ~ctr
      (Cstruct.sub buf enc_off enc_len)
  in
  Cstruct.blit encrypted 0 buf enc_off enc_len;
  buf

let tls_auth config =
  match Config.find Tls_auth config with
  | None -> Error (`Msg "no tls auth payload in config")
  | Some (direction, _, hmac1, _, hmac2) ->
      let hmac_algorithm = Config.get Auth config in
      let hmac_len = Mirage_crypto.Hash.digest_size hmac_algorithm in
      let a, b =
        match direction with
        | None -> (hmac1, hmac1)
        | Some `Incoming -> (hmac2, hmac1)
        | Some `Outgoing -> (hmac1, hmac2)
      in
      let s cs = Cstruct.sub cs 0 hmac_len in
      Ok { hmac_algorithm; my_hmac = s a; their_hmac = s b }

let secret config =
  match Config.find Secret config with
  | None -> Error (`Msg "no pre-shared secret found")
  | Some (dir, key1, hmac1, key2, hmac2) -> (
      let hmac_len = Mirage_crypto.Hash.digest_size (Config.get Auth config) in
      let hm cs = Cstruct.sub cs 0 hmac_len
      and cipher cs = Cstruct.sub cs 0 32 in
      match dir with
      | None -> Ok (cipher key1, hm hmac1, cipher key1, hm hmac1)
      | Some `Incoming -> Ok (cipher key2, hm hmac2, cipher key1, hm hmac1)
      | Some `Outgoing -> Ok (cipher key1, hm hmac1, cipher key2, hm hmac2))

let tls_crypt config =
  match Config.find Tls_crypt_v2_client config with
  | None -> Error (`Msg "no tls-crypt payload in config")
  | Some ((their_key, their_hmac, my_key, my_hmac), wkc, force_cookie) ->
      let hm cs = Cstruct.sub cs 0 Packet.Tls_crypt.hmac_len in
      let cipher cs =
        Mirage_crypto.Cipher_block.AES.CTR.of_secret (Cstruct.sub cs 0 32)
      in
      Ok
        ( {
            my_key = cipher my_key;
            my_hmac = hm my_hmac;
            their_key = cipher their_key;
            their_hmac = hm their_hmac;
          },
          wkc,
          force_cookie )

let client config ts now rng =
  let open Result.Syntax in
  let current_ts = ts () in
  let config =
    match Config.get Remote_random config with
    | exception Not_found -> config
    | () ->
        let remotes = Config.get Remote config in
        let remotes = Array.of_list remotes in
        for i = Array.length remotes - 1 downto 1 do
          let j = Randomconv.int rng ~bound:(succ i) in
          let t = remotes.(i) in
          remotes.(i) <- remotes.(j);
          remotes.(j) <- t
        done;
        let remotes = Array.to_list remotes in
        Config.add Remote remotes config
  in
  let* action, state =
    match Config.get Remote config with
    | (`Domain (name, ip_version), _port, _proto) :: _ ->
        Ok (`Resolve (name, ip_version), Resolving (0, current_ts, 0))
    | (`Ip ip, port, dp) :: _ ->
        Ok (`Connect (ip, port, dp), Connecting (0, current_ts, 0))
    | [] -> Error (`Msg "couldn't find remote in configuration")
  in
  match (tls_auth config, tls_crypt config, secret config) with
  | Error e, Error _, Error _ -> Error e
  | Error _, Error _, Ok (my_key, my_hmac, their_key, their_hmac) ->
      (* in static key mode, only CBC is allowed *)
      assert (Config.get Cipher config = `AES_256_CBC);
      let keys =
        let keys =
          AES_CBC
            {
              my_key = Mirage_crypto.Cipher_block.AES.CBC.of_secret my_key;
              my_hmac;
              their_key = Mirage_crypto.Cipher_block.AES.CBC.of_secret their_key;
              their_hmac;
            }
        in
        { my_packet_id = 1l; their_packet_id = 1l; keys }
      in
      let compress =
        match Config.find Comp_lzo config with None -> false | Some () -> true
      in
      let session = init_session ~my_session_id:0L ~compress () in
      let channel = new_channel 0 current_ts in
      let state =
        {
          config;
          state = Client_static { keys; state };
          linger = Cstruct.empty;
          rng;
          ts;
          now;
          session;
          channel;
          lame_duck = None;
          last_received = current_ts;
          last_sent = current_ts;
        }
      in
      Ok (state, action)
  | Error _, Ok (tls_crypt, wkc, _force_cookie), _ ->
      let session = init_session ~my_session_id:0L () in
      let channel = new_channel 0 current_ts in
      let state =
        {
          config;
          state = Client_tls_crypt { state; tls_crypt = (tls_crypt, wkc) };
          linger = Cstruct.empty;
          rng;
          ts;
          now;
          session;
          channel;
          lame_duck = None;
          last_received = current_ts;
          last_sent = current_ts;
        }
      in
      Ok (state, action)
  | Ok tls_auth, _, _ ->
      let session = init_session ~my_session_id:0L () in
      let channel = new_channel 0 current_ts in
      let state =
        {
          config;
          state = Client_tls_auth { state; tls_auth };
          linger = Cstruct.empty;
          rng;
          ts;
          now;
          session;
          channel;
          lame_duck = None;
          last_received = current_ts;
          last_sent = current_ts;
        }
      in
      Ok (state, action)

let server server_config server_ts server_now server_rng =
  let open Result.Syntax in
  let port =
    match Config.find Port server_config with None -> 1194 | Some p -> p
  in
  let+ tls_auth = tls_auth server_config in
  (* TODO validate server configuration to contain stuff we need later *)
  (* what must be present: server, topology subnet, ping_interval, ping_timeout,
      ca, tls_cert, tls_key, _no_ comp_lzo *)
  ( { server_config; server_rng; server_ts; server_now; tls_auth },
    server_ip server_config,
    port )

let new_connection server =
  let session =
    init_session ~my_session_id:(Randomconv.int64 server.server_rng) ()
  in
  let current_ts = server.server_ts () in
  let channel = new_channel 0 current_ts in
  {
    config = server.server_config;
    state =
      Server_tls_auth { state = Server_handshaking; tls_auth = server.tls_auth };
    linger = Cstruct.empty;
    rng = server.server_rng;
    ts = server.server_ts;
    now = server.server_now;
    session;
    channel;
    lame_duck = None;
    last_received = current_ts;
    last_sent = current_ts;
  }

let pp_tls_error ppf = function
  | `Eof -> Fmt.string ppf "EOF from other side"
  | `Alert typ ->
      Fmt.pf ppf "alert from other side %s"
        (Tls.Packet.alert_type_to_string typ)
  | `Fail f ->
      Fmt.pf ppf "failure from our side %s" (Tls.Engine.string_of_failure f)

let prf ?sids ~label ~secret ~client_random ~server_random len =
  (* This is the same as TLS_1_0 / TLS_1_1
     (copied from ocaml-tls/lib/handshake_crypto.ml):
     - split secret into upper and lower half
     - compute md5 hmac (with upper half) and sha1 hmac (with lower half)
       - iterate until len reached: H seed ++ H (n-1 ++ seed)
     - XOR the md5 and sha1 output
  *)
  let sids =
    match sids with
    | None -> Cstruct.empty
    | Some (c, s) ->
        let buf = Cstruct.create 16 in
        Cstruct.BE.set_uint64 buf 0 c;
        Cstruct.BE.set_uint64 buf 8 s;
        buf
  in
  let seed =
    Cstruct.(concat [ of_string label; client_random; server_random; sids ])
  in
  let p_hash (hmac, hmac_len) key =
    let rec expand a to_go =
      let res = hmac ~key (Cstruct.append a seed) in
      if to_go > hmac_len then
        Cstruct.append res (expand (hmac ~key a) (to_go - hmac_len))
      else Cstruct.sub res 0 to_go
    in
    expand (hmac ~key seed) len
  in
  let halve secret = Cstruct.split secret (Cstruct.length secret / 2) in
  let s1, s2 = halve secret in
  let md5 = p_hash Mirage_crypto.Hash.MD5.(hmac, digest_size) s1
  and sha = p_hash Mirage_crypto.Hash.SHA1.(hmac, digest_size) s2 in
  Mirage_crypto.Uncommon.Cs.xor md5 sha

let derive_keys session (my_key_material : State.my_key_material)
    (their_key_material : Packet.tls_data) =
  (* are we the server? *)
  let server = Cstruct.is_empty my_key_material.pre_master in
  let ( pre_master,
        client_random,
        server_random,
        client_random',
        server_random',
        sids ) =
    if server then
      ( their_key_material.pre_master,
        their_key_material.random1,
        my_key_material.random1,
        their_key_material.random2,
        my_key_material.random2,
        (session.their_session_id, session.my_session_id) )
    else
      ( my_key_material.pre_master,
        my_key_material.random1,
        their_key_material.random1,
        my_key_material.random2,
        their_key_material.random2,
        (session.my_session_id, session.their_session_id) )
  in
  let master_key =
    prf ~label:"OpenVPN master secret" ~secret:pre_master ~client_random
      ~server_random 48
  in
  let keys =
    prf ~label:"OpenVPN key expansion" ~secret:master_key
      ~client_random:client_random' ~server_random:server_random' ~sids (4 * 64)
  in
  (server, keys)

let incoming_tls tls data =
  match Tls.Engine.handle_tls tls data with
  | Error (f, `Response _) -> Error (`Tls (`Fail f))
  | Ok (r, `Response out, `Data d) -> (
      match r with
      | (`Eof | `Alert _) as e ->
          Log.err (fun m ->
              m "response %a, TLS payload %a"
                Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
                out
                Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
                d);
          Error (`Tls e)
      | `Ok tls' -> Ok (tls', out, d))

let incoming_tls_without_reply tls data =
  let open Result.Syntax in
  let* t = incoming_tls tls data in
  match t with
  | tls', None, d -> Ok (tls', d)
  | _, Some _, _ -> Error (`Msg "expected no TLS reply")

let maybe_kex_client rng config tls =
  let open Result.Syntax in
  if Tls.Engine.can_handle_appdata tls then
    let pre_master, random1, random2 = (rng 48, rng 32, rng 32) in
    let* options = Config.client_generate_connect_options config in
    let pull = Config.mem Pull config in
    let user_pass = Config.find Auth_user_pass config in
    let peer_info =
      let ciphers =
        String.concat ":"
          (List.map Config.aead_cipher_to_string
             (Config.get Data_ciphers config))
      in
      Some [ "IV_PLAT=mirage"; "IV_CIPHERS=" ^ ciphers; "IV_NCP=2" ]
    in
    let peer_info =
      match peer_info with
      | Some peer_info when pull ->
          Some ("IV_PROTO=4" (* IV_PROTO_REQUEST_PUSH *) :: peer_info)
      | Some peer_info -> Some ("IV_PROTO=0" :: peer_info)
      | None -> None
    in
    let td =
      { Packet.pre_master; random1; random2; options; user_pass; peer_info }
    and my_key_material = { State.pre_master; random1; random2 } in
    match
      Tls.Engine.send_application_data tls [ Packet.encode_tls_data td ]
    with
    | None -> Error (`Msg "Tls.send application data failed for tls_data")
    | Some (tls', payload) ->
        let client_state = TLS_established (tls', my_key_material) in
        Ok (client_state, Some payload)
  else Ok (TLS_handshake tls, None)

let kdf session cipher hmac_algorithm my_key_material their_key_material =
  let server, keys = derive_keys session my_key_material their_key_material in
  let maybe_swap (a, b, c, d) = if server then (c, d, a, b) else (a, b, c, d) in
  let extract klen hlen =
    ( Cstruct.sub keys 0 klen,
      Cstruct.sub keys 64 hlen,
      Cstruct.sub keys 128 klen,
      Cstruct.sub keys 192 hlen )
  in
  let keys =
    match cipher with
    | `AES_256_CBC ->
        let hmac_len = Mirage_crypto.Hash.digest_size hmac_algorithm in
        let my_key, my_hmac, their_key, their_hmac =
          maybe_swap (extract 32 hmac_len)
        in
        AES_CBC
          {
            my_key = Mirage_crypto.Cipher_block.AES.CBC.of_secret my_key;
            my_hmac;
            their_key = Mirage_crypto.Cipher_block.AES.CBC.of_secret their_key;
            their_hmac;
          }
    | `AES_128_GCM ->
        let my_key, my_implicit_iv, their_key, their_implicit_iv =
          maybe_swap (extract 16 (Packet.aead_nonce - Packet.packet_id_len))
        in
        AES_GCM
          {
            my_key = Mirage_crypto.Cipher_block.AES.GCM.of_secret my_key;
            my_implicit_iv;
            their_key = Mirage_crypto.Cipher_block.AES.GCM.of_secret their_key;
            their_implicit_iv;
          }
    | `AES_256_GCM ->
        let my_key, my_implicit_iv, their_key, their_implicit_iv =
          maybe_swap (extract 32 (Packet.aead_nonce - Packet.packet_id_len))
        in
        AES_GCM
          {
            my_key = Mirage_crypto.Cipher_block.AES.GCM.of_secret my_key;
            my_implicit_iv;
            their_key = Mirage_crypto.Cipher_block.AES.GCM.of_secret their_key;
            their_implicit_iv;
          }
    | `CHACHA20_POLY1305 ->
        let my_key, my_implicit_iv, their_key, their_implicit_iv =
          maybe_swap (extract 32 (Packet.aead_nonce - Packet.packet_id_len))
        in
        CHACHA20_POLY1305
          {
            my_key = Mirage_crypto.Chacha20.of_secret my_key;
            my_implicit_iv;
            their_key = Mirage_crypto.Chacha20.of_secret their_key;
            their_implicit_iv;
          }
  in
  { my_packet_id = 1l; their_packet_id = 1l; keys }

let kex_server config session (my_key_material : my_key_material) tls data =
  let open Result.Syntax in
  (* TODO verify username + password, respect incoming data, including NCP *)
  let options = Config.server_generate_connect_options config in
  let td =
    {
      Packet.pre_master = Cstruct.empty;
      random1 = my_key_material.random1;
      random2 = my_key_material.random2;
      options;
      user_pass = None;
      peer_info = None;
    }
  in
  let* their_tls_data = Packet.decode_tls_data ~with_premaster:true data in
  match Tls.Engine.send_application_data tls [ Packet.encode_tls_data td ] with
  | None -> Error (`Msg "not yet established")
  | Some (tls', payload) ->
      let+ state =
        match Config.find Ifconfig config with
        | None ->
            Ok (Push_request_sent (tls', my_key_material, their_tls_data), None)
        | Some (Ipaddr.V4 address, Ipaddr.V4 netmask) ->
            let ip_config =
              let cidr = Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address in
              { cidr; gateway = fst (server_ip config) }
            in
            let cipher = Config.get Cipher config
            and hmac_algorithm = Config.get Auth config in
            let keys_ctx =
              kdf session cipher hmac_algorithm my_key_material their_tls_data
            in
            Ok (Established keys_ctx, Some ip_config)
        | _ ->
            Error
              (`Msg "found Ifconfig without IPv4 addresses, not yet supported")
      in
      (state, payload)

let push_request tls =
  match Tls.Engine.send_application_data tls [ Packet.push_request ] with
  | None -> Error (`Msg "Tls.send application data failed for push request")
  | Some (tls', payload) -> Ok (tls', payload)

let push_reply tls data =
  (* a trailing 0 byte.. (Cstruct.create 1) *)
  let repl =
    Cstruct.concat
      [ Packet.push_reply; Cstruct.of_string data; Cstruct.create 1 ]
  in
  match Tls.Engine.send_application_data tls [ repl ] with
  | None -> Error (`Msg "Tls.send application data failed for push request")
  | Some (tls', payload) -> Ok (tls', payload)

let maybe_push_reply config = function
  | Some data ->
      if Cstruct.(equal empty data) then
        Error (`Msg "push request sent: empty TLS reply")
      else
        let str = Cstruct.(to_string (sub data 0 (pred (length data)))) in
        Log.info (fun m -> m "push request sent, received TLS payload %S" str);
        let p_r = "PUSH_REPLY" in
        let p_r_len = String.length p_r in
        if String.starts_with str ~prefix:p_r then
          let opts = String.sub str p_r_len (String.length str - p_r_len) in
          Config.merge_push_reply config opts
        else if String.starts_with str ~prefix:"AUTH_FAILED" then
          let msg =
            "Authentication failed: "
            ^ (List.tl (String.split_on_char ',' str) |> String.concat ",")
          in
          Error (`Msg msg)
        else
          Error (`Msg (Fmt.str "push request expected push_reply, got %S" str))
  | None -> Error (`Msg "push request expected data, received no data")

let incoming_control_client config rng session channel now op data =
  match (channel.channel_st, op) with
  | Expect_reset, (Packet.Hard_reset_server_v2 | Packet.Soft_reset_v2) ->
      (* for rekey we receive a soft_reset -- a bit alien that we don't send soft_reset *)
      (* we reply with embedded ACK + TLS client hello! *)
      (* NOTE: For tls-crypt-v2 hmac cookies it is important we don't send a
         dedicated ACK as we need to ensure the Control_wkc arrives first *)
      let tls, ch =
        let authenticator =
          match Config.find Ca config with
          | None ->
              Log.warn (fun m ->
                  m "not authenticating certificate (missing CA)");
              fun ?ip:_ ~host:_ _ -> Ok None
          | Some ca ->
              Log.info (fun m ->
                  m "authenticating with CA %a"
                    Fmt.(list ~sep:(any "\n") X509.Certificate.pp)
                    ca);
              X509.Authenticator.chain_of_trust
                ~allowed_hashes:Mirage_crypto.Hash.hashes
                ~time:(fun () -> Some now)
                ca
        and certificates =
          match (Config.find Tls_cert config, Config.find Tls_key config) with
          | Some cert, Some key -> `Single ([ cert ], key)
          | _ -> `None
        and ciphers = tls_ciphers config
        and version = tls_version config
        and peer_name = Config.find Verify_x509_name config in
        Tls.(
          Engine.client
            (Config.client ?ciphers ?version ?peer_name ~certificates
               ~authenticator ()))
      in
      Ok
        ( None,
          config,
          { channel with channel_st = TLS_handshake tls },
          [ (`Control, ch) ] )
  | TLS_handshake tls, Packet.Control ->
      (* we reply with ACK + maybe TLS response *)
      let open Result.Syntax in
      let* tls', tls_response, d = incoming_tls tls data in
      Log.debug (fun m ->
          m "TLS payload is %a"
            Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
            d);
      let+ channel_st, data = maybe_kex_client rng config tls' in
      let out =
        match (tls_response, data) with
        | None, None ->
            []
            (* happens while handshake is in process and we're waiting for further messages from the server *)
        | None, Some data -> [ (`Control, data) ]
        | Some res, None -> [ (`Control, res) ]
        | Some res, Some data ->
            Log.warn (fun m -> m "tls handshake response and application data");
            [ (`Control, res); (`Control, data) ]
      in
      (None, config, { channel with channel_st }, out)
  | TLS_established (tls, my_key_material), Packet.Control -> (
      let open Result.Syntax in
      let* tls', tls_resp, d = incoming_tls tls data in
      let tls_out =
        match tls_resp with None -> [] | Some c -> [ (`Control, c) ]
      in
      match d with
      | None ->
          let channel_st = TLS_established (tls', my_key_material) in
          Ok (None, config, { channel with channel_st }, tls_out)
      | Some d -> (
          let* tls_data = Packet.decode_tls_data d in
          let config =
            let merged =
              Config.client_merge_server_config config tls_data.Packet.options
            in
            Result.iter_error
              (fun (`Msg msg) ->
                Log.err (fun m ->
                    m "server options (%S) failure: %s" tls_data.options msg))
              merged;
            Result.value ~default:config merged
          in
          (* ok, two options:
             - initial handshake done, we need push request / reply
             - subsequent handshake, we're ready for data delivery [we already have ip and route in cfg]
          *)
          (* this may be a bit too early since tls_response...  *)
          match Config.(find Ifconfig config) with
          | Some _ ->
              let ip_config = ip_from_config config in
              let cipher = Config.get Cipher config
              and hmac_algorithm = Config.get Auth config in
              let keys =
                kdf session cipher hmac_algorithm my_key_material tls_data
              in
              let channel_st = Established keys in
              Ok (Some ip_config, config, { channel with channel_st }, tls_out)
          | None ->
              let pull = Config.mem Pull config in
              if pull then
                let channel_st =
                  Push_request_sent (tls', my_key_material, tls_data)
                in
                Ok
                  ( None,
                    config,
                    { channel with channel_st },
                    tls_out @ [ (`Ack, Cstruct.empty) ] )
              else
                (* now we send a PUSH_REQUEST\0 and see what happens *)
                let+ tls'', out = push_request tls' in
                let channel_st =
                  Push_request_sent (tls'', my_key_material, tls_data)
                in
                (* first send an ack for the received key data packet (this needs to be
                   a separate packet from the PUSH_REQUEST for unknown reasons) *)
                ( None,
                  config,
                  { channel with channel_st },
                  tls_out @ [ (`Ack, Cstruct.empty); (`Control, out) ] )))
  | Push_request_sent (tls, key, tls_data), Packet.Control ->
      let open Result.Syntax in
      Log.debug (fun m -> m "in push request sent");
      let* _tls', d = incoming_tls_without_reply tls data in
      let+ config' = maybe_push_reply config d in
      let cipher = Config.get Cipher config'
      and hmac_algorithm = Config.get Auth config' in
      let keys = kdf session cipher hmac_algorithm key tls_data in
      let channel_st = Established keys in
      Log.info (fun m -> m "channel %d is established now!!!" channel.keyid);
      let ip_config = ip_from_config config' in
      (Some ip_config, config', { channel with channel_st }, [])
  | _ -> Error (`No_transition (channel, op, data))

let init_channel ?(payload = Cstruct.empty) how session keyid now ts =
  let channel = new_channel keyid ts in
  let timestamp = ptime_to_ts_exn now in
  let session, transport, header = header session channel.transport timestamp in
  let transport, m_id = next_message_id transport in
  let out = (keyid, `Control (how, (header, m_id, payload))) in
  let out_packets = IM.add m_id (ts, out) transport.out_packets in
  let transport = { transport with out_packets } in
  (session, { channel with transport }, out)

let incoming_control_server is_not_taken config rng session channel _now _ts
    _key op data =
  match (channel.channel_st, op) with
  | Expect_reset, (Packet.Hard_reset_client_v2 | Packet.Soft_reset_v2) ->
      (* TODO may need to do client certificate authentication here! *)
      let _ca, server, key =
        ( Config.get Ca config,
          Config.get Tls_cert config,
          Config.get Tls_key config )
      in
      let ciphers = tls_ciphers config and version = tls_version config in
      let tls_config =
        Tls.Config.server ?ciphers ?version
          ~certificates:(`Single ([ server ], key))
          ()
      in
      let tls = Tls.Engine.server tls_config in
      let channel = { channel with channel_st = TLS_handshake tls } in
      let control_typ =
        match Config.find Ifconfig config with
        | None -> `Reset_server
        | Some _ -> `Reset
      in
      Ok (None, config, session, channel, [ (control_typ, Cstruct.empty) ])
  | TLS_handshake tls, Packet.Control ->
      (* we reply with ACK + maybe TLS response *)
      let open Result.Syntax in
      let+ tls', tls_response, d = incoming_tls tls data in
      Log.debug (fun m ->
          m "TLS handshake payload is %a"
            Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
            d);
      (* if tls is established, move to next state (await tls_data) *)
      let channel_st =
        if Tls.Engine.can_handle_appdata tls' then
          (* this could be generated later, but is done here to accomodate the client state machine *)
          let random1, random2 = (rng 32, rng 32)
          and pre_master = Cstruct.empty in
          TLS_established (tls', { State.pre_master; random1; random2 })
        else TLS_handshake tls'
      in
      let out =
        match tls_response with None -> [] | Some c -> [ (`Control, c) ]
      in
      (None, config, session, { channel with channel_st }, out)
  | TLS_established (tls, keys), Packet.Control ->
      let open Result.Syntax in
      let* tls', d = incoming_tls_without_reply tls data in
      let* d =
        Option.to_result
          ~none:(`Msg "TLS established, expected data, received nothing") d
      in
      let+ (channel_st, ip_config), out =
        kex_server config session keys tls' d
      in
      (* keys established, move forward to "expect push request (reply with push reply)" *)
      ( ip_config,
        config,
        session,
        { channel with channel_st },
        [ (`Control, out) ] )
  | Push_request_sent (tls, key, tls_data), Packet.Control ->
      (* TODO naming: this is actually server_stuff sent, awaiting push request *)
      let open Result.Syntax in
      let* tls', d = incoming_tls_without_reply tls data in
      let* data = Option.to_result ~none:(`Msg "expected push request") d in
      if Cstruct.(equal Packet.push_request data) then
        (* send push reply, register IP etc. *)
        let server_ip = fst (server_ip config) in
        let* ip, cidr = next_free_ip config is_not_taken in
        let ping =
          match Config.get Ping_interval config with
          | `Not_configured -> 10
          | `Seconds n -> n
        and restart =
          match Config.get Ping_timeout config with
          | `Restart n -> "ping-restart " ^ string_of_int (n / 2)
          | `Exit n -> "ping-exit " ^ string_of_int (n / 2)
        in
        (* PUSH_REPLY,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 30,ifconfig 10.8.0.3 255.255.255.0 *)
        let reply_things =
          [
            "";
            (* need an initial , after PUSH_REPLY *)
            "route-gateway " ^ Ipaddr.V4.to_string server_ip;
            "topology subnet";
            "ping " ^ string_of_int ping;
            restart;
            "ifconfig " ^ Ipaddr.V4.to_string ip ^ " "
            ^ Ipaddr.V4.to_string (Ipaddr.V4.Prefix.netmask cidr);
          ]
        in
        let reply = String.concat "," reply_things in
        let* _tls'', out = push_reply tls' reply in
        let cipher = Config.get Cipher config
        and hmac_algorithm = Config.get Auth config in
        let keys = kdf session cipher hmac_algorithm key tls_data in
        let channel_st = Established keys in
        let ip_config = { cidr; gateway = server_ip } in
        let config' =
          Config.add Ifconfig
            (Ipaddr.V4 ip, Ipaddr.V4 (Ipaddr.V4.Prefix.netmask cidr))
            config
        in
        Ok
          ( Some ip_config,
            config',
            session,
            { channel with channel_st },
            [ (`Control, out) ] )
      else Error (`Msg "expected push request")
  | _, _ -> Error (`No_transition (channel, op, data))

let incoming_control is_not_taken config rng state session channel now ts key op
    data =
  Log.info (fun m ->
      m "incoming control! op %a (channel %a)" Packet.pp_operation op pp_channel
        channel);
  match state with
  | Client_tls_auth _ | Client_tls_crypt _ ->
      let open Result.Syntax in
      let+ est, config', ch'', outs =
        incoming_control_client config rng session channel now op data
      in
      (est, config', session, ch'', outs)
  | Server_tls_auth _ ->
      incoming_control_server is_not_taken config rng session channel now ts key
        op data
  | Client_static _ ->
      Error (`Msg "client with static keys, no control packets expected")

let expected_packet session transport data =
  let open Result.Syntax in
  (* expects monotonic packet + message id, session ids matching *)
  let hdr = Packet.header data and msg_id = Packet.message_id data in
  (* TODO timestamp? - epsilon-same as ours? monotonically increasing? *)
  let* () =
    opt_guard
      (Int64.equal session.my_session_id)
      hdr.Packet.remote_session
      (`Mismatch_my_session_id (transport, hdr))
  in
  let* () =
    guard
      (Int64.equal session.their_session_id 0L
      || Int64.equal session.their_session_id hdr.Packet.local_session)
      (`Mismatch_their_session_id (transport, hdr))
  in
  (* TODO deal with it, properly: packets may be lost (e.g. udp)
     both from their side, and acks from our side *)
  let* () =
    guard
      (Int32.equal session.their_packet_id hdr.Packet.packet_id)
      (`Non_monotonic_packet_id (transport, hdr))
  in
  let+ () =
    opt_guard
      (Int32.equal transport.their_message_id)
      msg_id
      (`Non_monotonic_message_id (transport, msg_id, hdr))
  in
  let session =
    {
      session with
      their_session_id = hdr.Packet.local_session;
      their_packet_id = Int32.succ hdr.Packet.packet_id;
    }
  in
  let their_message_id =
    match msg_id with
    | None -> transport.their_message_id
    | Some x -> Int32.succ x
  in
  let out_packets =
    List.fold_left
      (fun m id -> IM.remove id m)
      transport.out_packets hdr.Packet.ack_message_ids
  in
  let transport = { transport with their_message_id; out_packets } in
  (session, transport)

type error =
  [ Packet.error
  | Lzo.error
  | `Non_monotonic_packet_id of transport * Packet.header
  | `Non_monotonic_message_id of transport * int32 option * Packet.header
  | `Mismatch_their_session_id of transport * Packet.header
  | `Mismatch_my_session_id of transport * Packet.header
  | `Msg_id_required_in_fresh_key of transport * int * Packet.header
  | `Different_message_id_expected_fresh_key of transport * int * Packet.header
  | `Bad_mac of t * Cstruct.t * Packet.t
  | `No_transition of channel * Packet.operation * Cstruct.t
  | `Tls of
    [ `Alert of Tls.Packet.alert_type | `Eof | `Fail of Tls.Engine.failure ]
  | `Msg of string ]

let pp_error ppf = function
  | #Packet.error as e -> Fmt.pf ppf "decode %a" Packet.pp_error e
  | #Lzo.error as e -> Fmt.pf ppf "lzo %a" Lzo.pp_error e
  | `Non_monotonic_packet_id (state, hdr) ->
      Fmt.pf ppf "non monotonic packet id in %a@ (state %a)" Packet.pp_header
        hdr pp_transport state
  | `Non_monotonic_message_id (state, msg_id, hdr) ->
      Fmt.pf ppf "non monotonic message id %a in %a@ (state %a)"
        Fmt.(option ~none:(any "no") int32)
        msg_id Packet.pp_header hdr pp_transport state
  | `Mismatch_their_session_id (state, hdr) ->
      Fmt.pf ppf "mismatched their session id in %a@ (state %a)"
        Packet.pp_header hdr pp_transport state
  | `Mismatch_my_session_id (state, hdr) ->
      Fmt.pf ppf "mismatched my session id in %a@ (state %a)" Packet.pp_header
        hdr pp_transport state
  | `Msg_id_required_in_fresh_key (state, key, hdr) ->
      Fmt.pf ppf "no message id in a fresh key (%d) message %a@ (state %a)" key
        Packet.pp_header hdr pp_transport state
  | `Different_message_id_expected_fresh_key (state, key, hdr) ->
      Fmt.pf ppf
        "different message id expected for fresh key (%d) message %a@ (state \
         %a)"
        key Packet.pp_header hdr pp_transport state
  | `Bad_mac (state, computed, data) ->
      Fmt.pf ppf "bad mac: computed %a data %a@ (state %a)" Cstruct.hexdump_pp
        computed Packet.pp data pp state
  | `No_transition (channel, op, data) ->
      Fmt.pf ppf "no transition found for typ %a (channel %a)@.data %a"
        Packet.pp_operation op pp_channel channel Cstruct.hexdump_pp data
  | `Tls tls_e -> pp_tls_error ppf tls_e
  | `Msg msg -> Fmt.string ppf msg

let pad block_size cs =
  let pad_len =
    let l = Cstruct.length cs mod block_size in
    if l = 0 then block_size else block_size - l
  in
  let out = Cstruct.create pad_len in
  Cstruct.memset out pad_len;
  Cstruct.append cs out

let unpad block_size cs =
  let l = Cstruct.length cs in
  let amount = Cstruct.get_uint8 cs (pred l) in
  let len = l - amount in
  if len >= 0 && amount <= block_size then Ok (Cstruct.sub cs 0 len)
  else Error (`Msg "bad padding")

let out ?add_timestamp (ctx : keys) hmac_algorithm compress rng data =
  (* - compression only if configured (0xfa for uncompressed)
     the ~add_timestamp argument is only used in static key mode
  *)
  let packet_id =
    let buf = Cstruct.create Packet.packet_id_len in
    Cstruct.BE.set_uint32 buf 0 ctx.my_packet_id;
    buf
  in
  let compression =
    if compress then (
      let buf = Cstruct.create 1 in
      (* 0xFA is "no compression" *)
      Cstruct.set_uint8 buf 0 0xfa;
      buf)
    else Cstruct.empty
  in
  let data = Cstruct.append compression data in
  ( { ctx with my_packet_id = Int32.succ ctx.my_packet_id },
    match ctx.keys with
    | AES_CBC { my_key; my_hmac; _ } ->
        (* the wire format of CBC data packets is:
           hmac (IV enc(packet_id [timestamp] [compression] data pad))
           where:
           - hmac over the entire encrypted payload
             - timestamp only used in static key mode (32bit, seconds since unix epoch)
        *)
        let ts =
          let ts_len = Option.fold ~none:0 ~some:(fun _ -> 4) add_timestamp in
          let ts_buf = Cstruct.create ts_len in
          Option.iter
            (fun ts -> Cstruct.BE.set_uint32 ts_buf 0 ts)
            add_timestamp;
          ts_buf
        in
        let hdr = Cstruct.append packet_id ts in
        let iv = rng Packet.cipher_block_size
        and data = pad Packet.cipher_block_size (Cstruct.append hdr data) in
        let open Mirage_crypto in
        let enc = Cipher_block.AES.CBC.encrypt ~key:my_key ~iv data in
        let payload = Cstruct.append iv enc in
        let hmac = Hash.mac hmac_algorithm ~key:my_hmac payload in
        Cstruct.append hmac payload
    | AES_GCM { my_key; my_implicit_iv; _ } ->
        let nonce = Cstruct.append packet_id my_implicit_iv in
        let enc, tag =
          Mirage_crypto.Cipher_block.AES.GCM.authenticate_encrypt_tag
            ~key:my_key ~nonce ~adata:packet_id data
        in
        Cstruct.concat [ packet_id; tag; enc ]
    | CHACHA20_POLY1305 { my_key; my_implicit_iv; _ } ->
        let nonce = Cstruct.append packet_id my_implicit_iv in
        let enc, tag =
          Mirage_crypto.Chacha20.authenticate_encrypt_tag ~key:my_key ~nonce
            ~adata:packet_id data
        in
        Cstruct.concat [ packet_id; tag; enc ] )

let data_out ?add_timestamp (ctx : keys) hmac_algorithm compress protocol rng
    key data =
  (* as described in [out], ~add_timestamp is only used in static key mode *)
  let ctx, payload = out ?add_timestamp ctx hmac_algorithm compress rng data in
  let out = Packet.encode protocol (key, `Data payload) in
  Log.debug (fun m ->
      m "sending %d bytes data (enc %d) out id %lu" (Cstruct.length data)
        (Cstruct.length out) ctx.my_packet_id);
  (ctx, out)

let static_out ~add_timestamp ctx hmac_algorithm compress protocol rng data =
  let ctx, payload = out ~add_timestamp ctx hmac_algorithm compress rng data in
  let prefix = Packet.encode_protocol protocol (Cstruct.length payload) in
  let out = Cstruct.append prefix payload in
  Log.debug (fun m ->
      m "sending %d bytes data (enc %d) out id %lu" (Cstruct.length data)
        (Cstruct.length payload) ctx.my_packet_id);
  (ctx, out)

let outgoing s data =
  let incr ch out =
    { ch with packets = succ ch.packets; bytes = Cstruct.length out + ch.bytes }
  in
  match (s.state, keys_opt s.channel) with
  | Client_static { keys; state }, _ ->
      let add_timestamp = ptime_to_ts_exn (s.now ()) in
      let hmac_algorithm = Config.get Auth s.config in
      let keys, out =
        static_out ~add_timestamp keys hmac_algorithm s.session.compress
          s.session.protocol s.rng data
      in
      let channel = incr s.channel out in
      let state = Client_static { keys; state } in
      Ok ({ s with state; channel; last_sent = s.ts () }, out)
  | _, None -> Error `Not_ready
  | _, Some ctx ->
      let sess = s.session in
      let hmac_algorithm = Config.get Auth s.config in
      let ctx, out =
        data_out ctx hmac_algorithm sess.compress sess.protocol s.rng
          s.channel.keyid data
      in
      let channel = incr (set_keys s.channel ctx) out in
      Ok ({ s with channel; last_sent = s.ts () }, out)

let ping =
  (* constant ping_string in OpenVPN: src/openvpn/ping.c *)
  Cstruct.of_hex "2a 18 7b f3 64 1e b4 cb  07 ed 2d 0a 98 1f c7 48"

let maybe_ping state =
  (* ping if we haven't send anything for the configured interval *)
  let current_ts = state.ts () in
  let s_since_sent = Duration.to_sec (Int64.sub current_ts state.last_sent) in
  let interval = Config.(get Ping_interval state.config) in
  match interval with
  | `Not_configured -> (state, [])
  | `Seconds threshold when s_since_sent < threshold -> (state, [])
  | `Seconds _ -> (
      Log.debug (fun m ->
          m "sending a ping after %d seconds of inactivity" s_since_sent);
      match outgoing state ping with
      | Error _ -> (state, [])
      | Ok (s', d) -> (s', [ d ]))

let maybe_init_rekey s =
  (* if there's a rekey in process we don't do anything *)
  let keyid =
    let n = succ s.channel.keyid mod 8 in
    if n = 0 then 1 else n
    (* From src/openvpn/ssl_pkt.h: tls_session_get_tls_wrap():
       OpenVPN has the hardcoded assumption in its protocol that
       key-id 0 is always first session and renegotiations use key-id
       1 to 7 and wrap around to 1 after that. So key-id > 0 is equivalent
       to "this is a renegotiation" *)
  in
  let init_channel () =
    init_channel Packet.Soft_reset_v2 s.session keyid (s.now ()) (s.ts ())
  in
  match s.state with
  | Client_tls_auth { state = Ready; tls_auth } ->
      let session, channel, out = init_channel () in
      (* allocate new channel, send out a rst (and await a rst) *)
      let state = Client_tls_auth { state = Rekeying channel; tls_auth } in
      let out = hmac_and_out s.session.protocol tls_auth out in
      ({ s with state; session }, [ out ])
  | Server_tls_auth { state = Server_ready; tls_auth } ->
      let session, channel, out = init_channel () in
      let state =
        Server_tls_auth { state = Server_rekeying channel; tls_auth }
      in
      let out = hmac_and_out s.session.protocol tls_auth out in
      ({ s with state; session }, [ out ])
  | Client_tls_crypt { state = Ready; tls_crypt } ->
      let session, channel, out = init_channel () in
      let state = Client_tls_crypt { state = Rekeying channel; tls_crypt } in
      let out = encrypt_and_out s.session.protocol (fst tls_crypt) out in
      ({ s with state; session }, [ out ])
  | Client_static _ ->
      (* there's no rekey mechanism in static mode *)
      (s, [])
  | Client_tls_auth _ | Client_tls_crypt _ | Server_tls_auth _ ->
      Log.warn (fun m ->
          m "maybe init rekey, but not in client or server ready %a" pp_state
            s.state);
      (s, [])

let maybe_rekey state =
  (* rekeying may happen iff:
     - channel has been up for <reneg_seconds>
     - channel has transferred bytes >= reneg_bytes
     - channel has transferred packets >= reneg_packets
     crucial to note: we only check the active channel!
      should we insert some fuzzyness since a rekey takes time, so that the
      deadlines are always met? *)
  let should_rekey =
    match
      Config.
        ( find Renegotiate_seconds state.config,
          find Renegotiate_bytes state.config,
          find Renegotiate_packets state.config )
    with
    | Some y, _, _
      when y <= Duration.to_sec (Int64.sub (state.ts ()) state.channel.started)
      ->
        true
    | _, Some b, _ when b <= state.channel.bytes -> true
    | _, _, Some p when p <= state.channel.packets -> true
    | _ -> false
  in
  if should_rekey then maybe_init_rekey state else (state, [])

let maybe_drop_lame_duck state =
  match (state.lame_duck, Config.find Transition_window state.config) with
  | None, _ -> state
  | _, None -> state (* TODO: warn? *)
  | Some (_, ts'), Some s ->
      (* TODO: log when dropped *)
      if Duration.to_sec (Int64.sub (state.ts ()) ts') >= s then
        { state with lame_duck = None }
      else state

let timer state =
  let s', out = maybe_ping state in
  let s'', out' = maybe_rekey s' in
  let s''' = maybe_drop_lame_duck s'' in
  (s''', out @ out')

let incoming_data ?(add_timestamp = false) err (ctx : keys) hmac_algorithm
    compress data =
  let open Result.Syntax in
  let* data =
    match ctx.keys with
    | AES_CBC { their_key; their_hmac; _ } ->
        (* spec described the layout as:
           hmac <+> payload
           where payload consists of IV <+> encrypted data
           where plain data consists of packet_id [timestamp] [compress] data pad

           note that the timestamp is only used in static key mode, when
           ~add_timestamp is provided and true.
        *)
        let open Mirage_crypto in
        let module H = (val Mirage_crypto.Hash.module_of hmac_algorithm) in
        let hmac, data = Cstruct.split data H.digest_size in
        let computed_hmac = H.hmac ~key:their_hmac data in
        let* () =
          guard (Cstruct.equal hmac computed_hmac) (err computed_hmac)
        in
        let iv, data = Cstruct.split data Packet.cipher_block_size in
        let dec = Cipher_block.AES.CBC.decrypt ~key:their_key ~iv data in
        (* dec is: uint32 packet id followed by (lzo-compressed) data and padding *)
        let hdr_len = Packet.packet_id_len + if add_timestamp then 4 else 0 in
        let* () =
          guard
            (Cstruct.length dec >= hdr_len)
            (Result.msgf "payload too short (need %d bytes): %a" hdr_len
               Cstruct.hexdump_pp dec)
        in
        (* TODO validate packet id and ordering *)
        Log.debug (fun m ->
            m "received packet id is %lu" (Cstruct.BE.get_uint32 dec 0));
        (* TODO validate ts if provided (avoid replay) *)
        unpad Packet.cipher_block_size (Cstruct.shift dec hdr_len)
    | AES_GCM { their_key; their_implicit_iv; _ } ->
        let tag_len = Mirage_crypto.Cipher_block.AES.GCM.tag_size in
        let* () =
          guard
            (Cstruct.length data >= Packet.packet_id_len + tag_len)
            (Result.msgf "payload too short (need %d bytes): %a"
               (Packet.packet_id_len + tag_len)
               Cstruct.hexdump_pp data)
        in
        let packet_id, tag, payload =
          let p_id, rest = Cstruct.split data Packet.packet_id_len in
          let tag, payload = Cstruct.split rest tag_len in
          (p_id, tag, payload)
        in
        let nonce = Cstruct.append packet_id their_implicit_iv in
        let plain =
          Mirage_crypto.Cipher_block.AES.GCM.authenticate_decrypt_tag
            ~key:their_key ~nonce ~adata:packet_id ~tag payload
        in
        (* TODO validate packet id and ordering *)
        Log.debug (fun m ->
            m "received packet id is %lu" (Cstruct.BE.get_uint32 packet_id 0));
        Option.to_result ~none:(`Msg "AEAD decrypt failed") plain
    | CHACHA20_POLY1305 { their_key; their_implicit_iv; _ } ->
        let tag_len = Mirage_crypto.Chacha20.tag_size in
        let* () =
          guard
            (Cstruct.length data >= Packet.packet_id_len + tag_len)
            (Result.msgf "payload too short (need %d bytes): %a"
               (Packet.packet_id_len + tag_len)
               Cstruct.hexdump_pp data)
        in
        let packet_id, tag, payload =
          let p_id, rest = Cstruct.split data Packet.packet_id_len in
          let tag, payload = Cstruct.split rest tag_len in
          (p_id, tag, payload)
        in
        let nonce = Cstruct.append packet_id their_implicit_iv in
        let plain =
          Mirage_crypto.Chacha20.authenticate_decrypt_tag ~key:their_key ~nonce
            ~adata:packet_id ~tag payload
        in
        (* TODO validate packet id and ordering *)
        Log.debug (fun m ->
            m "received packet id is %lu" (Cstruct.BE.get_uint32 packet_id 0));
        Option.to_result ~none:(`Msg "AEAD decrypt failed") plain
  in
  let+ data' =
    if compress then
      (* if dec[hdr_len - 1] == 0xfa, then compression is off *)
      let* () =
        guard
          (Cstruct.length data >= 1)
          (`Msg "payload too short, need compression byte")
      in
      let comp, data = Cstruct.split data 1 in
      match Cstruct.get_uint8 comp 0 with
      | 0xFA -> Ok data
      | 0x66 ->
          let+ lz = Lzo.uncompress_with_buffer (Cstruct.to_bigarray data) in
          let lz = Cstruct.of_string lz in
          Log.debug (fun m -> m "decompressed:@.%a" Cstruct.hexdump_pp lz);
          lz
      | comp ->
          Result.error_msgf "unknown compression %#X in packet:@.%a" comp
            Cstruct.hexdump_pp data
    else Ok data
  in
  if Cstruct.equal data' ping then (
    Log.debug (fun m -> m "received ping!");
    None)
  else Some data'

let check_control_integrity err key p hmac_algorithm hmac_key =
  let open Result.Syntax in
  let computed_mac, packet_mac =
    (compute_hmac key p hmac_algorithm hmac_key, Packet.((header p).hmac))
  in
  let+ () = guard (Cstruct.equal computed_mac packet_mac) (err computed_mac) in
  Log.info (fun m -> m "mac good")

let split_control mtu outs =
  List.concat_map
    (function
      | `Control, data ->
          let rec datas acc data =
            if Cstruct.is_empty data then List.rev acc
            else
              let l = min mtu (Cstruct.length data) in
              let data, data' = Cstruct.split data l in
              datas (data :: acc) data'
          in
          List.map (fun data -> (`Control, data)) (datas [] data)
      | ((`Ack | `Reset_server | `Reset), _) as p -> [ p ])
    outs

let op_of_typ = function
  | `Ack -> Packet.Ack
  | `Control -> Packet.Control
  | `Reset_server -> Packet.Hard_reset_server_v2
  | `Reset -> Packet.Soft_reset_v2

let wrap_hmac_control now ts mtu session tls_auth key transport outs =
  let now_ts = ptime_to_ts_exn now in
  let outs = split_control mtu outs in
  let session, transport, outs =
    List.fold_left
      (fun (session, transport, acc) (typ, out) ->
        (* add the OpenVPN header *)
        let session, transport, p =
          match typ with
          | `Ack ->
              let session, transport, header =
                header session transport now_ts
              in
              (session, transport, `Ack header)
          | (`Control | `Reset_server | `Reset) as typ ->
              let op = op_of_typ typ in
              let session, transport, header =
                header session transport now_ts
              in
              let transport, m_id = next_message_id transport in
              (session, transport, `Control (op, (header, m_id, out)))
        in
        (* hmac each outgoing frame and encode *)
        let out = hmac_and_out session.protocol tls_auth (key, p) in
        let out_packets =
          match p with
          | `Ack _ -> transport.out_packets
          | `Control (_, (_, m_id, _)) as p ->
              IM.add m_id (ts, (key, p)) transport.out_packets
        in
        (session, { transport with out_packets }, out :: acc))
      (session, transport, []) outs
  in
  (session, transport, List.rev outs)

let wrap_tls_crypt_control now ts mtu session (tls_crypt, wkc) needs_wkc key
    transport outs =
  let now_ts = ptime_to_ts_exn now in
  (* If we reply with hmac cookie we must split such that the first control
     packet, the Control_wkc has room for the /cleartext/ wkc, and fix the
     packet length afterwards *)
  let session, transport, maybe_out, outs =
    match (needs_wkc, outs) with
    | true, (`Control, data) :: rest ->
        let l = min (mtu - Cstruct.length wkc) (Cstruct.length data) in
        let data, data' = Cstruct.split data l in
        let rest =
          if Cstruct.is_empty data' then rest else (`Control, data') :: rest
        in
        let session, transport, header = header session transport now_ts in
        let transport, m_id = next_message_id transport in
        let p = `Control (Packet.Control_wkc, (header, m_id, data)) in
        (* First we encrypt *)
        let out = encrypt_and_out session.protocol tls_crypt (key, p) in
        (* Then we append wkc and fix the length if TCP *)
        let len =
          Cstruct.length out
          - match session.protocol with `Tcp -> 2 | `Udp -> 0
        in
        let out = Cstruct.append out wkc in
        let proto = Packet.encode_protocol session.protocol len in
        Cstruct.blit proto 0 out 0 (Cstruct.length proto);
        (session, transport, Some out, rest)
    | true, _ ->
        Log.err (fun m ->
            m "wrap_tls_crypt_control: expected control to append wkc");
        assert false
    | false, _ -> (session, transport, None, outs)
  in
  let session, transport, outs =
    List.fold_left
      (fun (session, transport, acc) (typ, out) ->
        (* add the OpenVPN header *)
        let session, transport, p =
          match typ with
          | `Ack ->
              let session, transport, header =
                header session transport now_ts
              in
              (session, transport, `Ack header)
          | (`Control | `Reset_server | `Reset) as typ ->
              let op = op_of_typ typ in
              let session, transport, header =
                header session transport now_ts
              in
              let transport, m_id = next_message_id transport in
              (session, transport, `Control (op, (header, m_id, out)))
        in
        let out = encrypt_and_out session.protocol tls_crypt (key, p) in
        let out_packets =
          match p with
          | `Ack _ -> transport.out_packets
          | `Control (_, (_, m_id, _)) as p ->
              IM.add m_id (ts, (key, p)) transport.out_packets
        in
        (session, { transport with out_packets }, out :: acc))
      (session, transport, []) outs
  in
  let outs =
    let outs = List.rev outs in
    Option.fold ~none:outs ~some:(fun c_wkc -> c_wkc :: outs) maybe_out
  in
  (session, transport, outs)

let merge_payload a b =
  match (a, b) with
  | None, None -> None
  | Some a, None -> Some a
  | None, Some b -> Some (`Payload [ b ])
  | Some (`Payload a), Some b -> Some (`Payload (b :: a))
  | Some a, Some b ->
      Log.warn (fun m ->
          m "merging %a with payload %a (ignoring payload)" pp_action a
            Cstruct.hexdump_pp b);
      Some a

let find_channel state key op =
  match channel_of_keyid key state with
  | Some (ch, set_ch) -> Some (ch, set_ch)
  | None -> (
      Log.warn (fun m -> m "no channel found! %d" key);
      match (state.state, op) with
      | Client_tls_auth { state = Ready; tls_auth }, Packet.Soft_reset_v2 ->
          let channel = new_channel key (state.ts ()) in
          Some
            ( channel,
              fun s ch ->
                {
                  s with
                  state = Client_tls_auth { state = Rekeying ch; tls_auth };
                } )
      | Server_tls_auth { state = Server_ready; tls_auth }, Packet.Soft_reset_v2
        ->
          let channel = new_channel key (state.ts ()) in
          Some
            ( channel,
              fun s ch ->
                {
                  s with
                  state =
                    Server_tls_auth { state = Server_rekeying ch; tls_auth };
                } )
      | _ ->
          Log.warn (fun m ->
              m "ignoring unexpected packet %a in %a" Packet.pp_operation op pp
                state);
          None)

let incoming ?(is_not_taken = fun _ip -> false) state buf =
  let open Result.Syntax in
  let state = { state with last_received = state.ts () } in
  let rec multi buf (state, out, act) =
    match Packet.decode_key_op state.session.protocol buf with
    | (Error (`Unknown_operation _) | Error `Partial) as e -> e
    | Error `Tcp_partial ->
        (* we don't need to check protocol as [`Tcp_partial] is only ever returned for tcp *)
        Ok ({ state with linger = buf }, out, act)
    | Ok (op, key, payload, linger) ->
        let* state, out, act =
          match find_channel state key op with
          | None ->
              (* XXX(reynir): why do we ignore it? Because the channel is unknown to us and we are not rekeying? *)
              Ok (state, out, act)
          | Some (ch, set_ch) -> (
              Log.debug (fun m ->
                  m "channel %a - received key %u op %a" pp_channel ch key
                    Packet.pp_operation op);
              match (op, state.state) with
              | Packet.Data_v1, _ -> (
                  match keys_opt ch with
                  | None ->
                      Log.warn (fun m -> m "received data, but no keys yet");
                      Ok (state, out, None)
                  | Some keys ->
                      let ch = received_packet ch payload in
                      let bad_mac hmac =
                        `Bad_mac (state, hmac, (key, `Data payload))
                      in
                      let hmac_algorithm = Config.get Auth state.config in
                      let+ payload =
                        incoming_data bad_mac keys hmac_algorithm
                          state.session.compress payload
                      in
                      let act = merge_payload act payload in
                      (set_ch state ch, out, act))
              | _, Client_static _ ->
                  (* non-data packet for static client *)
                  (* XXX(reynir): should we rather fail!? *)
                  Log.warn (fun m ->
                      m
                        "Static client received control channel packet; \
                         ignoring.");
                  Ok (state, out, act)
              | Packet.Hard_reset_client_v3, Client_tls_auth _
              | Packet.Hard_reset_client_v3, Server_tls_auth _ ->
                  Error (`No_transition (ch, op, payload))
              | ( Packet.Ack,
                  ( Client_tls_auth { tls_auth; _ }
                  | Server_tls_auth { tls_auth; _ } ) ) -> (
                  let hmac_len =
                    Mirage_crypto.Hash.digest_size tls_auth.hmac_algorithm
                  in
                  let* ack = Packet.decode_ack ~hmac_len payload in
                  let p = `Ack ack in
                  let bad_mac hmac = `Bad_mac (state, hmac, (key, p)) in
                  match
                    let* () =
                      check_control_integrity bad_mac key p
                        tls_auth.hmac_algorithm tls_auth.their_hmac
                    in
                    expected_packet state.session ch.transport p
                  with
                  | Error e ->
                      (* XXX: only in udp mode? *)
                      Log.warn (fun m -> m "ignoring bad packet %a" pp_error e);
                      Ok (state, out, None)
                  | Ok (session, transport) ->
                      let state = { state with session }
                      and ch = { ch with transport } in
                      Ok (set_ch state ch, out, act))
              | ( _control_op,
                  ( Client_tls_auth { tls_auth; _ }
                  | Server_tls_auth { tls_auth; _ } ) ) -> (
                  let hmac_len =
                    Mirage_crypto.Hash.digest_size tls_auth.hmac_algorithm
                  in
                  let* ((_, _, data) as control) =
                    Packet.decode_control ~hmac_len payload
                  in
                  let p = `Control (op, control) in
                  let bad_mac hmac = `Bad_mac (state, hmac, (key, p)) in
                  match
                    let* () =
                      check_control_integrity bad_mac key p
                        tls_auth.hmac_algorithm tls_auth.their_hmac
                    in
                    expected_packet state.session ch.transport p
                  with
                  | Error e ->
                      (* XXX: only in udp mode? *)
                      Log.warn (fun m -> m "ignoring bad packet %a" pp_error e);
                      Ok (state, out, None)
                  | Ok (session, transport) -> (
                      let state = { state with session }
                      and ch = { ch with transport } in
                      let+ est, config, session, ch, out' =
                        incoming_control is_not_taken state.config state.rng
                          state.state state.session ch (state.now ())
                          (state.ts ()) key op data
                      in
                      Log.debug (fun m ->
                          m "out channel %a, pkts %d" pp_channel ch
                            (List.length out'));
                      let state = { state with session } in
                      (* each control needs to be acked! *)
                      let out' =
                        match out' with
                        | [] -> [ (`Ack, Cstruct.empty) ]
                        | xs -> xs
                      in
                      (* now prepare outgoing packets *)
                      let my_mtu =
                        let compress =
                          match Config.find Comp_lzo config with
                          | None -> false
                          | Some () -> true
                        in
                        mtu config compress
                      in
                      let session, transport, encs =
                        wrap_hmac_control (state.now ()) (state.ts ()) my_mtu
                          state.session tls_auth key ch.transport out'
                      in
                      let out = out @ encs
                      and ch = { ch with transport }
                      and state = { state with config; session } in
                      match est with
                      | None -> (set_ch state ch, out, act)
                      | Some ip_config -> (
                          match state.state with
                          | Client_tls_auth { state = Handshaking _; tls_auth }
                            ->
                              let compress =
                                match Config.find Comp_lzo config with
                                | None -> false
                                | Some () -> true
                              in
                              let session = { state.session with compress }
                              and mtu = mtu config compress in
                              let act = Some (`Established (ip_config, mtu)) in
                              ( {
                                  state with
                                  state =
                                    Client_tls_auth { state = Ready; tls_auth };
                                  session;
                                  channel = ch;
                                },
                                out,
                                act )
                          | Client_tls_auth { state = Rekeying _; tls_auth } ->
                              (* TODO: may cipher (i.e. mtu) or compress change between rekeys? *)
                              let lame_duck =
                                Some (state.channel, state.ts ())
                              in
                              ( {
                                  state with
                                  state =
                                    Client_tls_auth { state = Ready; tls_auth };
                                  channel = ch;
                                  lame_duck;
                                },
                                out,
                                act )
                          | Server_tls_auth
                              { state = Server_handshaking; tls_auth } ->
                              let compress = false in
                              (* TODO? *)
                              let act =
                                let mtu = mtu config compress in
                                `Established (ip_config, mtu)
                              in
                              ( {
                                  state with
                                  state =
                                    Server_tls_auth
                                      { state = Server_ready; tls_auth };
                                  channel = ch;
                                },
                                out,
                                Some act )
                          | Server_tls_auth
                              { state = Server_rekeying _; tls_auth } ->
                              (* TODO: may cipher (i.e. mtu) or compress (or IP?) change between rekeys? *)
                              let lame_duck =
                                Some (state.channel, state.ts ())
                              in
                              ( {
                                  state with
                                  state =
                                    Server_tls_auth
                                      { state = Server_ready; tls_auth };
                                  channel = ch;
                                  lame_duck;
                                },
                                out,
                                act )
                          | _ -> assert false)))
              | Packet.Ack, Client_tls_crypt { tls_crypt = tls_crypt, _wkc; _ }
                -> (
                  let* cleartext, off =
                    Packet.Tls_crypt.decode_cleartext_header payload
                  in
                  let module Aes_ctr = Mirage_crypto.Cipher_block.AES.CTR in
                  let encrypted = Cstruct.shift payload off in
                  let iv = Cstruct.sub cleartext.hmac 0 16 in
                  let ctr = Aes_ctr.ctr_of_cstruct iv in
                  let decrypted =
                    Aes_ctr.decrypt ~key:tls_crypt.their_key ~ctr encrypted
                  in
                  let* ack =
                    Packet.Tls_crypt.decode_decrypted_ack cleartext decrypted
                  in
                  let p = `Ack ack in
                  let to_be_signed = Packet.Tls_crypt.to_be_signed key p in
                  let computed_hmac =
                    Mirage_crypto.Hash.SHA256.hmac ~key:tls_crypt.their_hmac
                      to_be_signed
                  in
                  let* () =
                    (* XXX maybe just ignore? *)
                    if Eqaf_cstruct.equal computed_hmac cleartext.hmac then
                      Ok ()
                    else Error (`Bad_mac (state, computed_hmac, (key, p)))
                  in
                  match expected_packet state.session ch.transport p with
                  | Error e ->
                      (* XXX: only in udp mode? *)
                      Log.warn (fun m -> m "ignoring bad packet %a" pp_error e);
                      Ok (state, out, None)
                  | Ok (session, transport) ->
                      let state = { state with session }
                      and ch = { ch with transport } in
                      Ok (set_ch state ch, out, act))
              | Packet.Hard_reset_client_v3, Client_tls_crypt _ ->
                  Error (`No_transition (ch, op, payload))
              | _control_op, Client_tls_crypt { tls_crypt = tls_crypt, wkc; _ }
                -> (
                  let* cleartext, off =
                    Packet.Tls_crypt.decode_cleartext_header payload
                  in
                  let module Aes_ctr = Mirage_crypto.Cipher_block.AES.CTR in
                  let encrypted = Cstruct.shift payload off in
                  let iv = Cstruct.sub cleartext.hmac 0 16 in
                  let ctr = Aes_ctr.ctr_of_cstruct iv in
                  let decrypted =
                    Aes_ctr.decrypt ~key:tls_crypt.their_key ~ctr encrypted
                  in
                  let* ((_, _, data) as control) =
                    Packet.Tls_crypt.decode_decrypted_control cleartext
                      decrypted
                  in
                  let* needs_wkc =
                    match op with
                    | Hard_reset_server_v2 ->
                        Packet.decode_early_negotiation_tlvs data
                    | _ -> Ok false
                  in
                  let p = `Control (op, control) in
                  let to_be_signed = Packet.Tls_crypt.to_be_signed key p in
                  let computed_hmac =
                    Mirage_crypto.Hash.SHA256.hmac ~key:tls_crypt.their_hmac
                      to_be_signed
                  in
                  let* () =
                    (* XXX maybe just ignore? *)
                    if Eqaf_cstruct.equal computed_hmac cleartext.hmac then
                      Ok ()
                    else Error (`Bad_mac (state, computed_hmac, (key, p)))
                  in
                  (* Workaround for hmac cookie *)
                  let session =
                    match (state.channel.channel_st, op) with
                    | Expect_reset, Hard_reset_server_v2 ->
                        let hdr = Packet.header p in
                        Log.warn (fun m ->
                            m "fixing their_packet_id: %08lx" hdr.packet_id);
                        { state.session with their_packet_id = hdr.packet_id }
                    | _ -> state.session
                  in
                  let state = { state with session } in
                  match expected_packet session ch.transport p with
                  | Error e ->
                      (* XXX: only in udp mode? *)
                      Log.warn (fun m -> m "ignoring bad packet %a" pp_error e);
                      Ok (state, out, None)
                  | Ok (session, transport) -> (
                      let state = { state with session }
                      and ch = { ch with transport } in
                      let+ est, config, session, ch, out' =
                        incoming_control is_not_taken state.config state.rng
                          state.state state.session ch (state.now ())
                          (state.ts ()) key op data
                      in
                      Log.debug (fun m ->
                          m "out channel %a, pkts %d" pp_channel ch
                            (List.length out'));
                      let state = { state with session } in
                      (* each control needs to be acked! *)
                      let out' =
                        match out' with
                        | [] -> [ (`Ack, Cstruct.empty) ]
                        | xs -> xs
                      in
                      (* now prepare outgoing packets *)
                      let my_mtu =
                        let compress =
                          match Config.find Comp_lzo config with
                          | None -> false
                          | Some () -> true
                        in
                        mtu config compress
                      in
                      let session, transport, encs =
                        wrap_tls_crypt_control (state.now ()) (state.ts ())
                          my_mtu state.session (tls_crypt, wkc) needs_wkc key
                          ch.transport out'
                      in
                      let out = out @ encs
                      and ch = { ch with transport }
                      and state = { state with config; session } in
                      match est with
                      | None -> (set_ch state ch, out, act)
                      | Some ip_config -> (
                          match state.state with
                          | Client_tls_crypt
                              { state = Handshaking _; tls_crypt } ->
                              let compress =
                                match Config.find Comp_lzo config with
                                | None -> false
                                | Some () -> true
                              in
                              let session = { state.session with compress }
                              and mtu = mtu config compress in
                              let act = Some (`Established (ip_config, mtu)) in
                              ( {
                                  state with
                                  state =
                                    Client_tls_crypt
                                      { state = Ready; tls_crypt };
                                  session;
                                  channel = ch;
                                },
                                out,
                                act )
                          | Client_tls_crypt { state = Rekeying _; tls_crypt }
                            ->
                              (* TODO: may cipher (i.e. mtu) or compress change between rekeys? *)
                              let lame_duck =
                                Some (state.channel, state.ts ())
                              in
                              ( {
                                  state with
                                  state =
                                    Client_tls_crypt
                                      { state = Ready; tls_crypt };
                                  channel = ch;
                                  lame_duck;
                                },
                                out,
                                act )
                          | _ -> assert false))))
        in
        (* Invariant: [linger] is always empty for UDP *)
        if Cstruct.is_empty linger then Ok (state, out, act)
        else multi linger (state, out, act)
  in
  let+ s', out, act =
    multi (Cstruct.append state.linger buf) (state, [], None)
  in
  let act' =
    match act with Some (`Payload a) -> Some (`Payload (List.rev a)) | y -> y
  in
  Log.debug (fun m -> m "out state is %a" State.pp s');
  Log.debug (fun m ->
      m "%d outgoing packets (%d bytes)" (List.length out) (Cstruct.lenv out));
  Log.debug (fun m -> m "action %a" Fmt.(option ~none:(any "no") pp_action) act);
  (s', out, act')

let maybe_ping_timeout state =
  (* timeout fires if no data was received within the configured interval *)
  let s_since_rcvd =
    Duration.to_sec (Int64.sub (state.ts ()) state.last_received)
  in
  let timeout, action =
    match Config.(get Ping_timeout state.config) with
    | `Restart x -> (x, `Restart)
    | `Exit x -> (x, `Exit)
  in
  if s_since_rcvd > timeout then (
    Log.warn (fun m -> m "timeout!");
    Some action)
  else None

let maybe_hand_timeout timeout ts transport =
  let t = Duration.of_sec timeout in
  IM.fold
    (fun _ (ts', _) m ->
      if Int64.sub ts ts' >= t then Error `Hand_timeout else m)
    transport.out_packets (Ok ())

let retransmit timeout ts transport =
  let t = Duration.of_sec timeout in
  (* TODO should the timestamp in the packet be updated? *)
  let out, out_packets =
    IM.fold
      (fun k (ts', data) (acc, m) ->
        if Int64.sub ts ts' >= t then (data :: acc, IM.add k (ts, data) m)
        else (acc, IM.add k (ts', data) m))
      transport.out_packets ([], IM.empty)
  in
  ({ transport with out_packets }, out)

let resolve_connect_client config ts s ev =
  let open Result.Syntax in
  let remote, next_remote =
    let remotes = Config.get Remote config in
    let r idx = List.nth remotes idx in
    let next idx =
      if succ idx = List.length remotes then None else Some (r (succ idx))
    in
    (r, next)
  and retry_exceeded r =
    match Config.get Connect_retry_max config with
    | `Times m -> m > r
    | `Unlimited -> false
  in
  let next_or_fail idx retry =
    let idx', retry', v =
      match next_remote idx with
      | None -> (0, succ retry, remote 0)
      | Some x -> (succ idx, retry, x)
    in
    if retry_exceeded retry' then
      Error (`Msg "maximum connection retries exceeded")
    else
      Ok
        (match v with
        | `Domain (name, ip_version), _, _ ->
            (Resolving (idx', ts, retry'), `Resolve (name, ip_version))
        | `Ip ip, port, dp ->
            (Connecting (idx', ts, retry'), `Connect (ip, port, dp)))
  in
  match (s, ev) with
  | Resolving (idx, _, retry), `Resolved ip ->
      (* TODO enforce ipv4/ipv6 *)
      let endp = match remote idx with _, port, dp -> (ip, port, dp) in
      Ok (Connecting (idx, ts, retry), Some (`Connect endp))
  | Resolving (idx, _, retry), `Resolve_failed ->
      let+ state, action = next_or_fail idx retry in
      (state, Some action)
  | Connecting (idx, _, retry), `Connection_failed ->
      let+ state, action = next_or_fail idx retry in
      (state, Some action)
  | Connecting (idx, initial_ts, retry), `Tick ->
      (* We are trying to establish a connection and a clock tick happens.
         We need to determine if {!Config.Connect_timeout} seconds has passed
         since [initial_ts] (when we started connecting), and if so,
         try the next [Remote]. *)
      let conn_timeout = Duration.of_sec Config.(get Connect_timeout config) in
      if Int64.sub ts initial_ts >= conn_timeout then (
        Log.err (fun m -> m "Connecting to remote #%d timed out" idx);
        let+ state, action = next_or_fail idx retry in
        (state, Some action))
      else Ok (s, None)
  | _, `Connection_failed ->
      (* re-start from scratch *)
      let+ state, action = next_or_fail (-1) 0 in
      (state, Some action)
  | _ -> Error (`Not_handled (remote, next_or_fail))

let handshake_timeout next_or_fail client t s ts =
  let open Result.Syntax in
  match
    match (t.session.protocol, s) with
    | `Udp, Handshaking _ -> Some (t.channel, fun channel -> { t with channel })
    | `Udp, Rekeying ch ->
        Some (ch, fun channel -> { t with state = client (Rekeying channel) })
    | _ -> None
  with
  | None -> Ok (t, [], None)
  | Some (ch, set_ch) -> (
      (* TODO exponential back-off mentioned in openvpn man page *)
      let tls_timeout = Config.get Tls_timeout t.config in
      match
        maybe_hand_timeout
          (Config.get Handshake_window t.config)
          ts ch.transport
      with
      | Ok () ->
          let transport, out = retransmit tls_timeout ts t.channel.transport in
          let channel = { ch with transport } in
          Ok (set_ch channel, out, None)
      | Error `Hand_timeout ->
          let+ state, action = next_or_fail (-1) 0 in
          ({ t with state = client state }, [], Some action))

let handle_client_tls_auth t s tls_auth ev =
  let open Result.Syntax in
  let now = t.now () and ts = t.ts () in
  let client state = Client_tls_auth { state; tls_auth } in
  match resolve_connect_client t.config ts s ev with
  | Ok (s, action) -> Ok ({ t with state = client s }, [], action)
  | Error (`Msg _) as e -> e
  | Error (`Not_handled (remote, next_or_fail)) -> (
      match (s, ev) with
      | Connecting (idx, _, _), `Connected ->
          let my_session_id = Randomconv.int64 t.rng in
          let protocol = match remote idx with _, _, proto -> proto in
          let session = init_session ~my_session_id ~protocol () in
          let session, channel, out =
            init_channel Packet.Hard_reset_client_v2 session 0 now ts
          in
          let state = client (Handshaking (idx, ts)) in
          let out = hmac_and_out t.session.protocol tls_auth out in
          Ok ({ t with state; channel; session }, [ out ], None)
      | s, `Tick -> (
          let* t, out, action_opt =
            handshake_timeout next_or_fail client t s ts
          in
          let out = List.map (hmac_and_out t.session.protocol tls_auth) out in
          match action_opt with
          | Some action -> Ok (t, out, Some action)
          | None -> (
              match maybe_ping_timeout t with
              | Some `Exit -> Ok (t, out, Some `Exit)
              | Some `Restart ->
                  let+ state, action = next_or_fail (-1) 0 in
                  ({ t with state = client state }, out, Some action)
              | None ->
                  let t', outs = timer t in
                  Ok (t', out @ outs, None)))
      | _, `Data cs -> incoming t cs
      | s, ev ->
          Result.error_msgf "handle_client: unexpected event %a in state %a"
            pp_event ev pp_client_state s)

let handle_client_tls_crypt t s tls_crypt wkc ev =
  let open Result.Syntax in
  let now = t.now () and ts = t.ts () in
  let client state = Client_tls_crypt { state; tls_crypt = (tls_crypt, wkc) } in
  match resolve_connect_client t.config ts s ev with
  | Ok (s, action) -> Ok ({ t with state = client s }, [], action)
  | Error (`Msg _) as e -> e
  | Error (`Not_handled (remote, next_or_fail)) -> (
      match (s, ev) with
      | Connecting (idx, _, _), `Connected ->
          let my_session_id = Randomconv.int64 t.rng in
          let protocol = match remote idx with _, _, proto -> proto in
          let session = init_session ~my_session_id ~protocol () in
          let session = { session with my_packet_id = 0x0f000001l } in
          let session, channel, out =
            init_channel ~payload:wkc Packet.Hard_reset_client_v3 session 0 now
              ts
          in
          let state = client (Handshaking (idx, ts)) in
          let out = encrypt_and_out t.session.protocol tls_crypt out in
          Ok ({ t with state; channel; session }, [ out ], None)
      | s, `Tick -> (
          let* t, out, action_opt =
            handshake_timeout next_or_fail client t s ts
          in
          let out =
            List.map (encrypt_and_out t.session.protocol tls_crypt) out
          in
          match action_opt with
          | Some action -> Ok (t, out, Some action)
          | None -> (
              match maybe_ping_timeout t with
              | Some `Exit -> Ok (t, out, Some `Exit)
              | Some `Restart ->
                  let+ state, action = next_or_fail (-1) 0 in
                  ({ t with state = client state }, out, Some action)
              | None ->
                  let t', outs = timer t in
                  Ok (t', out @ outs, None)))
      | _, `Data cs -> incoming t cs
      | s, ev ->
          Result.error_msgf "handle_client: unexpected event %a in state %a"
            pp_event ev pp_client_state s)

(* timeouts from a server perspective:
   still TODO (similar to client, maybe in udp branch)
   hs; - handshake-window -- until handshaking -> ready (discard connection attempt)
   hs; - tls-timeout -- same, discard connection attempt [in tcp not yet relevant]
*)
let handle_server ?is_not_taken t s ev =
  match (s, ev) with
  | _, `Data cs -> incoming ?is_not_taken t cs
  | (Server_ready | Server_rekeying _), `Tick -> (
      match maybe_ping_timeout t with
      | Some _ -> Ok (t, [], Some `Exit)
      | None ->
          let t', outs = timer t in
          Ok (t', outs, None))
  | Server_handshaking, `Tick ->
      Log.warn (fun m -> m "ignoring tick in handshaking");
      Ok (t, [], None)
  | s, ev ->
      Result.error_msgf "handle_server: unexpected event %a in state %a"
        pp_event ev pp_server_state s

let handle_static_client t s keys ev =
  let open Result.Syntax in
  let ts = t.ts () in
  let client state = Client_static { keys; state } in
  match resolve_connect_client t.config ts s ev with
  | Ok (s, action) -> Ok ({ t with state = client s }, [], action)
  | Error (`Msg _) as e -> e
  | Error (`Not_handled (remote, next_or_fail)) -> (
      match (s, ev) with
      | Connecting (idx, _, _), `Connected -> (
          match Config.get Ifconfig t.config with
          | V4 my_ip, V4 their_ip ->
              let mtu = Config.get Tun_mtu t.config in
              let cidr = Ipaddr.V4.Prefix.make 32 my_ip in
              let est = `Established ({ cidr; gateway = their_ip }, mtu) in
              let protocol = match remote idx with _, _, proto -> proto in
              let session = { t.session with protocol } in
              let hmac_algorithm = Config.get Auth t.config in
              let keys, payload =
                let add_timestamp = ptime_to_ts_exn (t.now ()) in
                static_out ~add_timestamp keys hmac_algorithm t.session.compress
                  protocol t.rng ping
              in
              let state = Client_static { keys; state = Ready } in
              Ok
                ( { t with state; session; last_sent = ts },
                  [ payload ],
                  Some est )
          | _ -> Error (`Msg "expected IPv4 addresses"))
      | _, `Tick -> (
          match maybe_ping_timeout t with
          | Some `Exit -> Ok (t, [], Some `Exit)
          | Some `Restart ->
              let+ state, action = next_or_fail (-1) 0 in
              ({ t with state = client state }, [], Some action)
          | None ->
              let t', outs = timer t in
              Ok (t', outs, None))
      | _, `Data cs ->
          let t = { t with last_received = ts } in
          let add_timestamp = true
          and compress = t.session.compress
          and hmac_algorithm = Config.get Auth t.config in
          let rec process_one acc linger =
            if Cstruct.length linger = 0 then
              Ok ({ t with linger = Cstruct.empty }, [], acc)
            else
              match Packet.decode_protocol t.session.protocol linger with
              | Error `Partial -> Error `Partial
              | Error `Tcp_partial ->
                  (* we don't need to check protocol as [`Tcp_partial] is only ever returned for tcp *)
                  Ok ({ t with linger }, [], acc)
              | Ok (cs, linger) ->
                  let bad_mac hmac = `Bad_mac (t, hmac, (0, `Data cs)) in
                  let* d =
                    incoming_data ~add_timestamp bad_mac keys hmac_algorithm
                      compress cs
                  in
                  process_one (merge_payload acc d) linger
          in
          process_one None (Cstruct.append t.linger cs)
      | s, ev ->
          Result.error_msgf
            "handle_static_client: unexpected event %a in state %a" pp_event ev
            pp_client_state s)

let handle t ?is_not_taken ev =
  match t.state with
  | Client_tls_auth { state; tls_auth } ->
      handle_client_tls_auth t state tls_auth ev
  | Client_static { state; keys } -> handle_static_client t state keys ev
  | Server_tls_auth { state; tls_auth = _ } ->
      handle_server ?is_not_taken t state ev
  | Client_tls_crypt { state; tls_crypt = tls_crypt, wkc } ->
      handle_client_tls_crypt t state tls_crypt wkc ev
