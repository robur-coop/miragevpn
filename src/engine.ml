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

let opt_guard p x e =
  Option.value ~default:(Ok ()) (Option.map (fun x -> guard (p x) e) x)

let next_sequence_number state =
  ( { state with my_sequence_number = Int32.succ state.my_sequence_number },
    state.my_sequence_number )

let header session transport timestamp =
  let rec acked_sequence_numbers id =
    if transport.their_sequence_number = id then []
    else id :: acked_sequence_numbers (Int32.succ id)
  in
  let ack_sequence_numbers =
    acked_sequence_numbers transport.last_acked_sequence_number
  in
  Log.debug (fun m ->
      m "last ack %lu, seq %lu ack: %a" transport.last_acked_sequence_number
        transport.their_sequence_number
        Fmt.(list ~sep:(any ", ") (fun ppf -> pf ppf "%lu"))
        ack_sequence_numbers);
  let remote_session =
    match ack_sequence_numbers with
    | [] -> None
    | _ -> Some session.their_session_id
  in
  let replay_id = session.my_replay_id
  and last_acked_sequence_number = transport.their_sequence_number in
  let my_replay_id = Int32.succ replay_id in
  ( { session with my_replay_id },
    { transport with last_acked_sequence_number },
    {
      Packet.local_session = session.my_session_id;
      replay_id;
      timestamp;
      ack_sequence_numbers;
      remote_session;
    } )

let ptime_to_ts_exn now =
  match Ptime.(Span.to_int_s (to_span now)) with
  | None -> assert false (* this will break in 2038-01-19 *)
  | Some x -> Int32.of_int x

let hmac_and_out protocol { hmac_algorithm; my_hmac; _ } key
    (p : [< Packet.ack | Packet.control ]) =
  let hmac_len = Mirage_crypto.Hash.digest_size hmac_algorithm in
  let buf, feeder = Packet.encode protocol hmac_len (key, p) in
  let hmac = Mirage_crypto.Hash.maci hmac_algorithm ~key:my_hmac feeder in
  Packet.set_hmac buf protocol hmac;
  buf

let encrypt_and_out protocol { my; _ } key
    (p : [< Packet.ack | Packet.control ]) =
  let my_key = Tls_crypt.Key.cipher_key my in
  let my_hmac = Tls_crypt.Key.hmac my in
  let buf, enc_off, enc_len, feeder =
    Packet.Tls_crypt.encode protocol (key, p)
  in
  let hmac = Mirage_crypto.Hash.SHA256.hmaci ~key:my_hmac feeder in
  let iv = Cstruct.sub hmac 0 16 in
  let ctr = Mirage_crypto.Cipher_block.AES.CTR.ctr_of_cstruct iv in
  Packet.Tls_crypt.set_hmac buf protocol hmac;
  let encrypted =
    Mirage_crypto.Cipher_block.AES.CTR.encrypt ~key:my_key ~ctr
      (Cstruct_ext.sub buf enc_off enc_len)
  in
  Cstruct.blit encrypted 0 buf enc_off enc_len;
  buf

let wrap_and_out protocol control_crypto key p =
  match control_crypto with
  | `Tls_auth tls_auth -> hmac_and_out protocol tls_auth key p
  | `Tls_crypt (tls_crypt, _wkc_opt) -> encrypt_and_out protocol tls_crypt key p

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
  match (Config.find Tls_mode config, Config.find Tls_crypt config) with
  | None, Some _ -> assert false
  | _, None -> Error (`Msg "no tls-crypt payload in config")
  | Some `Client, Some kc ->
      Ok { my = Tls_crypt.client_key kc; their = Tls_crypt.server_key kc }
  | Some `Server, Some kc ->
      Ok { my = Tls_crypt.server_key kc; their = Tls_crypt.client_key kc }

let tls_crypt_v2_client config =
  match Config.find Tls_crypt_v2_client config with
  | None -> Error (`Msg "no tls-crypt-v2 payload in config")
  | Some (kc, wkc, force_cookie) ->
      Ok
        ( { my = Tls_crypt.client_key kc; their = Tls_crypt.server_key kc },
          wkc,
          force_cookie )

let client ?pkcs12_password config ts now rng =
  let open Result.Syntax in
  let current_ts = ts () in
  let* () = Config.is_valid_client_config config in
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
  let* config =
    match Config.find Pkcs12 config with
    | None -> Ok config
    | Some p12 -> (
        let* pass =
          Option.to_result ~none:(`Msg "missing pkcs12 password")
            pkcs12_password
        in
        let* stuff = X509.PKCS12.verify pass p12 in
        let certs =
          List.filter_map
            (function `Certificate c -> Some c | _ -> None)
            stuff
        and keys =
          List.filter_map
            (function
              | `Private_key pk | `Decrypted_private_key pk -> Some pk
              | _ -> None)
            stuff
        in
        match keys with
        | [ pk ] -> (
            let key_fp =
              X509.Public_key.fingerprint (X509.Private_key.public pk)
            in
            match
              List.partition
                (fun cert ->
                  let cert_pubkey = X509.Certificate.public_key cert in
                  Cstruct.equal (X509.Public_key.fingerprint cert_pubkey) key_fp)
                certs
            with
            | [ cert ], extra_certs ->
                (* OpenVPN adds the certs to [Ca] if it is not present;
                   we don't as it is easily surprising behavior *)
                if extra_certs <> [] then
                  Log.warn (fun m ->
                      m "Extra certificates found in PKCS12 file%s: %a"
                        (if Config.mem Ca config then ""
                         else " (not using them as --ca)")
                        Fmt.(
                          list ~sep:(any ", ") (fun ppf cert ->
                              pf ppf "%a" X509.Distinguished_name.pp
                                (X509.Certificate.subject cert)))
                        extra_certs);
                Ok
                  Config.(
                    add Tls_key pk (add Tls_cert cert (remove Pkcs12 config)))
            | _ ->
                Error
                  (`Msg "PKCS12: couldn't find matching cert for private key"))
        | keys ->
            Error
              (`Msg
                (Fmt.str
                   "expected exactly one private key in PKCS12, found %u \
                    private keys"
                   (List.length keys))))
  in
  let* action, state =
    match Config.get Remote config with
    | (`Domain (name, ip_version), _port, _proto) :: _ ->
        Ok (`Resolve (name, ip_version), Resolving (0, current_ts, 0))
    | (`Ip ip, port, dp) :: _ ->
        Ok (`Connect (ip, port, dp), Connecting (0, current_ts, 0))
    | [] -> Error (`Msg "couldn't find remote in configuration")
  in
  let* control_crypto =
    match
      ( tls_auth config,
        tls_crypt config,
        tls_crypt_v2_client config,
        secret config )
    with
    | Error e, Error _, Error _, Error _ -> Error e
    | Error _, Error _, Error _, Ok (my_key, my_hmac, their_key, their_hmac) ->
        (* in static key mode, only CBC is allowed *)
        assert (Config.get Cipher config = `AES_256_CBC);
        let keys =
          let keys =
            AES_CBC
              {
                my_key = Mirage_crypto.Cipher_block.AES.CBC.of_secret my_key;
                my_hmac;
                their_key =
                  Mirage_crypto.Cipher_block.AES.CBC.of_secret their_key;
                their_hmac;
              }
          in
          { my_replay_id = 1l; their_replay_id = 1l; keys }
        in
        Ok (`Static keys)
    | Error _, Ok tls_crypt, _, _ -> Ok (`Tls_crypt (tls_crypt, None))
    | Error _, Error _, Ok (tls_crypt, wkc, _force_cookie), _ ->
        Ok (`Tls_crypt (tls_crypt, Some wkc))
    | Ok tls_auth, _, _, _ -> Ok (`Tls_auth tls_auth)
  in
  let state =
    let compress =
      match Config.find Comp_lzo config with None -> false | Some () -> true
    in
    let session = init_session ~my_session_id:0L ~compress ()
    and channel = new_channel 0 current_ts in
    {
      config;
      is_not_taken = (fun _ -> false);
      auth_user_pass = None;
      state = Client state;
      control_crypto;
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

let server server_config ~is_not_taken ?auth_user_pass server_ts server_now
    server_rng =
  let open Result.Syntax in
  let+ () = Config.is_valid_server_config server_config in
  (match (auth_user_pass, Config.find Verify_client_cert server_config) with
  | None, Some `None ->
      Log.warn (fun m ->
          m
            "Server configuration without authentication! Your server accepts \
             all clients. You should reconsider and use '--verify-client-cert \
             required' and provide a '--ca' or '--peer-fingerprint'. \
             Alternatively, provide ~auth_user_pass that checks for usernames \
             and password.")
  | _ -> ());
  let port = Option.value ~default:1194 (Config.find Port server_config) in
  ( {
      server_config;
      is_not_taken;
      auth_user_pass;
      server_rng;
      server_ts;
      server_now;
    },
    server_ip server_config,
    port )

let pp_tls_error ppf = function
  | `Eof -> Fmt.string ppf "EOF from other side"
  | `Alert typ ->
      Fmt.pf ppf "alert from other side %s"
        (Tls.Packet.alert_type_to_string typ)
  | `Fail f ->
      Fmt.pf ppf "failure from our side %s" (Tls.Engine.string_of_failure f)

let prf ?sids ~label ~secret ~client_random ~server_random len =
  let sids =
    Option.value ~default:Cstruct.empty
      (Option.map
         (fun (c, s) ->
           let buf = Cstruct.create_unsafe 16 in
           Cstruct.BE.set_uint64 buf 0 c;
           Cstruct.BE.set_uint64 buf 8 s;
           buf)
         sids)
  in
  let seed = Cstruct.concat [ client_random; server_random; sids ] in
  Tls.Handshake_crypto.pseudo_random_function `TLS_1_0
    `RSA_WITH_AES_256_GCM_SHA384 (* cipher, does not matter for TLS 1.0 *) len
    secret label seed

let derive_keys ~tls_ekm session (my_key_material : State.my_key_material)
    (their_key_material : Packet.tls_data) =
  (* are we the server? *)
  let server = Cstruct.is_empty my_key_material.pre_master in
  let length = 4 * 64 in
  let keys =
    match tls_ekm with
    | None ->
        Log.debug (fun m -> m "Using old PRF style key derivation");
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
        prf ~label:"OpenVPN key expansion" ~secret:master_key
          ~client_random:client_random' ~server_random:server_random' ~sids
          length
    | Some tls ->
        Log.debug (fun m -> m "Using new TLS-EKM style key derivation");
        let epoch = Result.get_ok (Tls.Engine.epoch tls) in
        Tls.Engine.export_key_material epoch "EXPORTER-OpenVPN-datakeys" length
  in
  (server, keys)

let incoming_tls tls data =
  match Tls.Engine.handle_tls tls data with
  | Error (`Alert a, `Response _) -> Error (`Tls (`Alert a))
  | Error (f, `Response _) -> Error (`Tls (`Fail f))
  | Ok (tls', eof, `Response out, `Data d) -> (
      match eof with
      | Some `Eof ->
          Log.err (fun m ->
              m "response %a, TLS payload %a"
                Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
                out
                Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
                d);
          Error (`Tls `Eof)
      | None -> Ok (tls', out, d))

let incoming_tls_without_reply tls data =
  let open Result.Syntax in
  let* t = incoming_tls tls data in
  match t with
  | tls', None, d -> Ok (tls', d)
  | _, Some _, _ -> Error (`Msg "expected no TLS reply")

let maybe_kex_client rng config tls =
  let open Result.Syntax in
  if Tls.Engine.handshake_in_progress tls then Ok (TLS_handshake tls, None)
  else
    let pre_master, random1, random2 = (rng 48, rng 32, rng 32) in
    let options = Config.client_generate_connect_options config in
    let pull = Config.mem Pull config in
    let user_pass = Config.find Auth_user_pass config in
    let peer_info =
      let ciphers = Config.get Data_ciphers config in
      let maybe_iv_ncp_2 =
        if List.mem `AES_128_GCM ciphers && List.mem `AES_256_GCM ciphers then
          [ "IV_NCP=2" ]
        else []
      in
      let ciphers =
        String.concat ":" (List.map Config.aead_cipher_to_string ciphers)
      in
      Some (maybe_iv_ncp_2 @ [ "IV_PLAT=mirage"; "IV_CIPHERS=" ^ ciphers ])
    in
    let peer_info =
      let iv_proto =
        Packet.Iv_proto.(
          Tls_key_export :: Use_cc_exit_notify
          :: (if pull then [ Request_push ] else []))
      in
      Option.map
        (fun pi ->
          ("IV_PROTO=" ^ string_of_int (Packet.Iv_proto.byte iv_proto)) :: pi)
        peer_info
    in
    let td =
      { Packet.pre_master; random1; random2; options; user_pass; peer_info }
    and my_key_material = { State.pre_master; random1; random2 } in
    let+ tls', payload =
      Option.to_result
        ~none:(`Msg "Tls.send application data failed for tls_data")
        (Tls.Engine.send_application_data tls [ Packet.encode_tls_data td ])
    in
    let client_state = TLS_established (tls', my_key_material) in
    (client_state, Some payload)

let kdf ~tls_ekm session cipher hmac_algorithm my_key_material
    their_key_material =
  let server, keys =
    derive_keys ~tls_ekm session my_key_material their_key_material
  in
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
          maybe_swap (extract 16 (Packet.aead_nonce - Packet.id_len))
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
          maybe_swap (extract 32 (Packet.aead_nonce - Packet.id_len))
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
          maybe_swap (extract 32 (Packet.aead_nonce - Packet.id_len))
        in
        CHACHA20_POLY1305
          {
            my_key = Mirage_crypto.Chacha20.of_secret my_key;
            my_implicit_iv;
            their_key = Mirage_crypto.Chacha20.of_secret their_key;
            their_implicit_iv;
          }
  in
  { my_replay_id = 1l; their_replay_id = 1l; keys }

let tls_ekm tls config =
  match
    (Config.find Key_derivation config, Config.find Protocol_flags config)
  with
  | Some `Tls_ekm, _ -> Some tls
  | None, Some flags -> if List.mem `Tls_ekm flags then Some tls else None
  | None, None -> None

let kex_server config auth_user_pass session (my_key_material : my_key_material)
    tls data =
  let open Result.Syntax in
  let* their_tls_data = Packet.decode_tls_data ~with_premaster:true data in
  let authenticated =
    match (auth_user_pass, their_tls_data.user_pass) with
    | None, _ -> true (* erm... *)
    | Some _, None -> false
    | Some auth, Some (user, pass) -> auth ~user ~pass
  in
  if not authenticated then
    let td =
      let options = Config.server_generate_connect_options config in
      {
        Packet.pre_master = Cstruct.empty;
        random1 = my_key_material.random1;
        random2 = my_key_material.random2;
        options;
        user_pass = None;
        peer_info = None;
      }
    in
    let* tls', payload =
      Option.to_result ~none:(`Msg "not yet established")
        (Tls.Engine.send_application_data tls [ Packet.encode_tls_data td ])
    in
    let* tls'', payload' =
      Option.to_result ~none:(`Msg "not yet established")
        (Tls.Engine.send_application_data tls' [ Packet.auth_failed ])
    in
    Ok (`Authentication_failed tls'', config, [ payload; payload' ])
  else
    let* cipher =
      let client_ciphers =
        match their_tls_data.peer_info with
        | Some pi -> (
            match
              List.find_opt (String.starts_with ~prefix:"IV_CIPHERS=") pi
            with
            | Some ciphers ->
                List.filter_map Config.aead_cipher_of_string
                  (String.split_on_char ':'
                     (String.sub ciphers 11 (String.length ciphers - 11)))
            | None ->
                if List.mem "IV_NCP=2" pi then [ `AES_128_GCM; `AES_256_GCM ]
                else [])
        | None -> []
      in
      List.find_opt
        (fun candidate -> List.mem candidate client_ciphers)
        (Config.get Config.Data_ciphers config)
      |> Option.to_result ~none:(`Msg "No shared ciphers")
    in
    let iv_proto =
      let ( let* ) = Option.bind in
      let prefix = "IV_PROTO=" in
      let* peer_info = their_tls_data.peer_info in
      let* iv_proto_s = List.find_opt (String.starts_with ~prefix) peer_info in
      let v =
        String.sub iv_proto_s (String.length prefix)
          (String.length iv_proto_s - String.length prefix)
      in
      int_of_string_opt v
    in
    let config = Config.add Cipher (cipher :> Config.cipher) config in
    let config =
      let supports_tls_ekm =
        Option.fold iv_proto ~none:false
          ~some:Packet.Iv_proto.(contains Tls_key_export)
      in
      let config =
        if
          supports_tls_ekm
          && Option.fold iv_proto ~none:false
               ~some:Packet.Iv_proto.(contains Use_cc_exit_notify)
        then Config.add_protocol_flag `Tls_ekm config
        else config
      in
      (* XXX(reynir): if a client supports tls-ekm and set [Use_cc_exit_notify]
         it is unnecessary to use 'key-derivation tls-ekm' in addition to
         'protocol-flags tls-ekm'. In that case 'protocol-flags tls-ekm' is
         sufficient. *)
      if supports_tls_ekm then Config.add Key_derivation `Tls_ekm config
      else config
    in
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
    let* tls', payload =
      Option.to_result ~none:(`Msg "not yet established")
        (Tls.Engine.send_application_data tls [ Packet.encode_tls_data td ])
    in
    let+ state =
      match Config.find Ifconfig config with
      | None ->
          let requested_push =
            Option.fold iv_proto ~none:false
              ~some:Packet.Iv_proto.(contains Request_push)
          in
          if requested_push then
            Ok (`Send_push_reply (tls', my_key_material, their_tls_data))
          else
            Ok
              (`State
                (Push_request_sent (tls', my_key_material, their_tls_data), None))
      | Some (Ipaddr.V4 address, Ipaddr.V4 netmask) ->
          let ip_config =
            let cidr = Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address in
            { cidr; gateway = fst (server_ip config) }
          in
          let cipher = Config.get Cipher config
          and hmac_algorithm = Config.get Auth config
          and tls_ekm = tls_ekm tls' config in
          let keys_ctx =
            kdf ~tls_ekm session cipher hmac_algorithm my_key_material
              their_tls_data
          in
          Ok
            (`State
              (Established (tls', keys_ctx), Some (`Established ip_config)))
      | _ ->
          Error
            (`Msg "found Ifconfig without IPv4 addresses, not yet supported")
    in
    (state, config, [ payload ])

let push_request tls =
  Option.to_result
    ~none:(`Msg "Tls.send application data failed for push request")
    (Tls.Engine.send_application_data tls [ Packet.push_request ])

let push_reply tls data =
  (* a trailing 0 byte.. (Cstruct.create 1) *)
  let repl =
    Cstruct.concat
      [ Packet.push_reply; Cstruct.of_string data; Cstruct.create 1 ]
  in
  Option.to_result
    ~none:(`Msg "Tls.send application data failed for push request")
    (Tls.Engine.send_application_data tls [ repl ])

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
          match
            (Config.find Ca config, Config.find Peer_fingerprint config)
          with
          | None, None ->
              Log.warn (fun m ->
                  m
                    "not authenticating certificate (missing CA and \
                     peer-fingerprint)");
              fun ?ip:_ ~host:_ _ -> Ok None
          | Some ca, _ ->
              Log.info (fun m ->
                  m "authenticating with CA %a"
                    Fmt.(list ~sep:(any "\n") X509.Certificate.pp)
                    ca);
              X509.Authenticator.chain_of_trust
                ~allowed_hashes:Mirage_crypto.Hash.hashes
                ~time:(fun () -> Some now)
                ca
          | _, Some fps ->
              Logs.info (fun m ->
                  m "authenticating with fingerprints %a"
                    Fmt.(list ~sep:(any "\n") Hex.pp)
                    (List.map Hex.of_cstruct fps));
              fun ?ip ~host chain ->
                List.fold_left
                  (fun acc fingerprint ->
                    match acc with
                    | Ok _ -> acc
                    | Error _ ->
                        X509.Validation.trust_cert_fingerprint
                          ~time:(fun () -> Some now)
                          ~hash:`SHA256 ~fingerprint ?ip ~host chain)
                  (Error (`Msg "No fingerprints provided"))
                  fps
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
        Option.to_list (Option.map (fun c -> (`Control, c)) tls_resp)
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
              and hmac_algorithm = Config.get Auth config
              and tls_ekm = tls_ekm tls' config in
              let keys =
                kdf ~tls_ekm session cipher hmac_algorithm my_key_material
                  tls_data
              in
              let channel_st = Established (tls', keys) in
              Ok
                ( Some (`Established ip_config),
                  config,
                  { channel with channel_st },
                  tls_out )
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
      let* tls', d = incoming_tls_without_reply tls data in
      let+ config' = maybe_push_reply config d in
      let cipher = Config.get Cipher config'
      and hmac_algorithm = Config.get Auth config'
      and tls_ekm = tls_ekm tls config' in
      let keys = kdf ~tls_ekm session cipher hmac_algorithm key tls_data in
      let channel_st = Established (tls', keys) in
      Log.info (fun m -> m "channel %d is established now!!!" channel.keyid);
      let ip_config = ip_from_config config' in
      (Some (`Established ip_config), config', { channel with channel_st }, [])
  | Established (tls, keys), Packet.Control ->
      let open Result.Syntax in
      let+ tls', d = incoming_tls_without_reply tls data in
      let channel = { channel with channel_st = Established (tls', keys) } in
      let act =
        Option.bind d (fun d ->
            let d = Cstruct.to_string d in
            match Cc_message.parse d with
            | Some msg -> Some msg
            | None ->
                Log.warn (fun m -> m "Received unknown control message: %S" d);
                None)
      in
      (act, config, channel, [])
  | _ -> Error (`No_transition (channel, op, data))

let init_channel ?(payload = Cstruct.empty) how session keyid now ts =
  let channel = new_channel keyid ts in
  let timestamp = ptime_to_ts_exn now in
  let session, transport, header = header session channel.transport timestamp in
  let transport, sn = next_sequence_number transport in
  let out = `Control (how, (header, sn, payload)) in
  let out_packets = IM.add sn (ts, (keyid, out)) transport.out_packets in
  let transport = { transport with out_packets } in
  (session, { channel with transport }, out)

let server_send_push_reply config is_not_taken tls session key tls_data =
  let open Result.Syntax in
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
  let topology =
    (* Since OpenVPN 2.7 the default topology is subnet *)
    Config.find Topology config |> Option.value ~default:`Subnet
  in
  let reply_things =
    [
      "";
      (* need an initial , after PUSH_REPLY *)
      (* reynir: route-gateway assumes --topology subnet (which we ensure in config.ml) *)
      "route-gateway " ^ Ipaddr.V4.to_string server_ip;
      "topology " ^ Config.topology_to_string topology;
      "ping " ^ string_of_int ping;
      restart;
      "ifconfig " ^ Ipaddr.V4.to_string ip ^ " "
      ^ Ipaddr.V4.to_string (Ipaddr.V4.Prefix.netmask cidr);
      (* Important to send cipher as that is how cipher negotiation is communicated *)
      "cipher " ^ Config.cipher_to_string (Config.get Cipher config);
    ]
    (* XXX(reynir): here we assume the binding for [Key_derivation] is only ever [`Tls_ekm] *)
    @ (if Config.mem Key_derivation config then [ "key-derivation tls-ekm" ]
       else [])
    @ (Option.to_list (Config.find Protocol_flags config)
      |> List.map (fun flags ->
             Fmt.str "%a" (Config.pp_b ?sep:None)
               (Config.Conf_map.B (Protocol_flags, flags))))
  in
  let reply = String.concat "," reply_things in
  let* tls', out = push_reply tls reply in
  let cipher = Config.get Cipher config
  and hmac_algorithm = Config.get Auth config
  and tls_ekm = tls_ekm tls' config in
  let keys = kdf ~tls_ekm session cipher hmac_algorithm key tls_data in
  let channel_st = Established (tls', keys) in
  let ip_config = { cidr; gateway = server_ip } in
  let config' =
    Config.add Ifconfig
      (Ipaddr.V4 ip, Ipaddr.V4 (Ipaddr.V4.Prefix.netmask cidr))
      config
  in
  Ok (Some (`Established ip_config), config', channel_st, [ (`Control, out) ])

let server_handle_tls_data config auth_user_pass is_not_taken session keys tls d
    =
  let open Result.Syntax in
  let* next, config, out =
    kex_server config auth_user_pass session keys tls d
  in
  let out = List.map (fun out -> (`Control, out)) out in
  match next with
  | `Send_push_reply (tls', key, tls_data) ->
      let* ip_config, config, channel_st, out' =
        server_send_push_reply config is_not_taken tls' session key tls_data
      in
      Ok (ip_config, config, channel_st, out @ out')
  | `State (channel_st, ip_config) ->
      (* keys established, move forward to "expect push request (reply with push reply)" *)
      Ok (ip_config, config, channel_st, out)
  | `Authentication_failed _tls -> Ok (Some `Exit, config, Expect_reset, out)

let incoming_control_server auth_user_pass is_not_taken config rng session
    channel now _ts _key op data =
  let open Result.Syntax in
  match (channel.channel_st, op) with
  | ( Expect_reset,
      ( Packet.Hard_reset_client_v2 | Packet.Hard_reset_client_v3
      | Packet.Soft_reset_v2 ) ) ->
      let server, key =
        (Config.get Tls_cert config, Config.get Tls_key config)
      in
      let ciphers = tls_ciphers config and version = tls_version config in
      let* authenticator =
        match
          ( Config.find Verify_client_cert config,
            Config.find Ca config,
            Config.find Peer_fingerprint config )
        with
        | None, Some ca, None | Some `Required, Some ca, None ->
            Ok
              (Some
                 (X509.Authenticator.chain_of_trust
                    ~time:(fun () -> Some now)
                    ~allowed_hashes:Mirage_crypto.Hash.hashes ca))
        | None, None, Some fps | Some `Required, None, Some fps ->
            Ok
              (Some
                 (fun ?ip ~host chain ->
                   List.fold_left
                     (fun acc fingerprint ->
                       match acc with
                       | Ok _ -> acc
                       | Error _ ->
                           X509.Validation.trust_cert_fingerprint
                             ~time:(fun () -> Some now)
                             ~hash:`SHA256 ~fingerprint ?ip ~host chain)
                     (Error (`Msg "No fingerprints provided"))
                     fps))
        | Some `None, _, _ -> Ok None
        | Some `Optional, _, _
        | (None | Some `Required), None, None
        | (None | Some `Required), Some _, Some _ ->
            (* already checked in config.ml *)
            assert false
      in
      let tls_config =
        Tls.Config.server ?ciphers ?version
          ~certificates:(`Single ([ server ], key))
          ?authenticator ()
      in
      let tls = Tls.Engine.server tls_config in
      let channel = { channel with channel_st = TLS_handshake tls } in
      let control_typ =
        match Config.find Ifconfig config with
        | None -> `Reset_server
        | Some _ -> `Reset
      in
      Ok (None, config, channel, [ (control_typ, Cstruct.empty) ])
  | TLS_handshake tls, Packet.Control -> (
      let open Result.Syntax in
      let* tls', tls_response, d = incoming_tls tls data in
      Log.debug (fun m ->
          m "TLS handshake payload is %a"
            Fmt.(option ~none:(any "no") Cstruct.hexdump_pp)
            d);
      (* if tls is established, move to next state (await tls_data) *)
      let channel_st =
        if Tls.Engine.handshake_in_progress tls' then TLS_handshake tls'
        else
          let random1, random2 = (rng 32, rng 32)
          and pre_master = Cstruct.empty in
          TLS_established (tls', { State.pre_master; random1; random2 })
      in
      let out =
        Option.to_list (Option.map (fun c -> (`Control, c)) tls_response)
      in
      match (channel_st, d) with
      | TLS_established (tls', keys), Some d ->
          let* ip_config, config, channel_st, out' =
            server_handle_tls_data config auth_user_pass is_not_taken session
              keys tls' d
          in
          Ok (ip_config, config, { channel with channel_st }, out @ out')
      | _ -> Ok (None, config, { channel with channel_st }, out))
  | TLS_established (tls, keys), Packet.Control -> (
      let open Result.Syntax in
      let* tls', d = incoming_tls_without_reply tls data in
      match d with
      | Some d ->
          let* ip_config, config, channel_st, out =
            server_handle_tls_data config auth_user_pass is_not_taken session
              keys tls' d
          in
          Ok (ip_config, config, { channel with channel_st }, out)
      | None ->
          let channel_st = TLS_established (tls', keys) in
          Ok (None, config, { channel with channel_st }, []))
  | Push_request_sent (tls, key, tls_data), Packet.Control ->
      (* TODO naming: this is actually server_stuff sent, awaiting push request *)
      let open Result.Syntax in
      let* tls', d = incoming_tls_without_reply tls data in
      let* data = Option.to_result ~none:(`Msg "expected push request") d in
      if Cstruct.(equal Packet.push_request data) then
        let* ip_config, config, channel_st, out =
          server_send_push_reply config is_not_taken tls' session key tls_data
        in
        Ok (ip_config, config, { channel with channel_st }, out)
      else Error (`Msg "expected push request")
  | Established (tls, keys), Packet.Control ->
      let open Result.Syntax in
      let+ tls', d = incoming_tls_without_reply tls data in
      let channel = { channel with channel_st = Established (tls', keys) } in
      let act =
        match d with
        | None -> None
        | Some d -> (
            let d = Cstruct.to_string d in
            match Cc_message.parse d with
            | Some (`Cc_exit as msg) -> Some msg
            | Some (`Cc_restart _ | `Cc_halt _) ->
                Log.info (fun m -> m "Received control message (ignored): %S" d);
                None
            | None ->
                Log.warn (fun m -> m "Received unknown control message: %S" d);
                None)
      in
      (act, config, channel, [])
  | _, _ -> Error (`No_transition (channel, op, data))

let incoming_control auth_user_pass is_not_taken config rng state session
    channel now ts key op data =
  Log.info (fun m ->
      m "incoming control! op %a (channel %a)" Packet.pp_operation op pp_channel
        channel);
  match state with
  | Client _ -> incoming_control_client config rng session channel now op data
  | Server _ ->
      incoming_control_server auth_user_pass is_not_taken config rng session
        channel now ts key op data

let expected_packet session transport data =
  let open Result.Syntax in
  (* expects monotonic packet + sequence number, session ids matching *)
  let hdr = Packet.header data and sn = Packet.sequence_number data in
  (* TODO timestamp? - epsilon-same as ours? monotonically increasing? *)
  let* () =
    Option.fold ~none:(Ok ())
      ~some:(fun sid ->
        guard
          (Int64.equal session.my_session_id sid)
          (`Mismatch_my_session_id (session.my_session_id, sid)))
      hdr.Packet.remote_session
  in
  let* () =
    guard
      (Int64.equal session.their_session_id 0L
      || Int64.equal session.their_session_id hdr.Packet.local_session)
      (`Mismatch_their_session_id
        (session.their_session_id, hdr.Packet.local_session))
  in
  (* TODO deal with it, properly: packets may be lost (e.g. udp)
     both from their side, and acks from our side *)
  let* () =
    guard
      (Int32.unsigned_compare session.their_replay_id hdr.Packet.replay_id <= 0)
      (`Non_monotonic_replay_id (session.their_replay_id, hdr.Packet.replay_id))
  in
  Log.debug (fun m ->
      m "received %a" Fmt.(option ~none:(any "no") (fun ppf -> pf ppf "%lu")) sn);
  let+ () =
    Option.fold ~none:(Ok ())
      ~some:(fun seq ->
        guard
          (Int32.equal transport.their_sequence_number seq)
          (`Non_monotonic_sequence_number
            (transport.their_sequence_number, seq)))
      sn
  in
  let session =
    {
      session with
      their_session_id = hdr.Packet.local_session;
      their_replay_id = Int32.succ hdr.Packet.replay_id;
    }
  in
  let their_sequence_number =
    Option.value ~default:transport.their_sequence_number
      (Option.map Int32.succ sn)
  in
  Log.debug (fun m ->
      m "their sequence number: %lu -> %lu" transport.their_sequence_number
        their_sequence_number);
  let out_packets =
    List.fold_left
      (fun m id -> IM.remove id m)
      transport.out_packets hdr.Packet.ack_sequence_numbers
  in
  let transport = { transport with their_sequence_number; out_packets } in
  (session, transport)

type error =
  [ Packet.error
  | Lzo.error
  | `Non_monotonic_replay_id of int32 * int32
  | `Non_monotonic_sequence_number of int32 * int32
  | `Mismatch_their_session_id of int64 * int64
  | `Mismatch_my_session_id of int64 * int64
  | `Bad_mac of t * Cstruct.t * Cstruct.t * Cstruct.t
  | `No_transition of channel * Packet.operation * Cstruct.t
  | `No_channel of int
  | `Tls of
    [ `Alert of Tls.Packet.alert_type | `Eof | `Fail of Tls.Engine.failure ]
  | `Payload_too_short of int * int
  | `Msg of string ]

let pp_error ppf = function
  | #Packet.error as e -> Fmt.pf ppf "decode %a" Packet.pp_error e
  | #Lzo.error as e -> Fmt.pf ppf "lzo %a" Lzo.pp_error e
  | `Non_monotonic_replay_id (expected, received) ->
      Fmt.pf ppf "non monotonic replay id: expected %lu, received %lu" expected
        received
  | `Non_monotonic_sequence_number (expected, received) ->
      Fmt.pf ppf "non monotonic sequence number: expected %lu, received %lu"
        expected received
  | `Mismatch_their_session_id (expected, received) ->
      Fmt.pf ppf "mismatched their session id: expected %016LX, received %016LX"
        expected received
  | `Mismatch_my_session_id (expected, received) ->
      Fmt.pf ppf "mismatched my session id: expected %016LX, received %016LX"
        expected received
  | `Bad_mac (state, computed, received, data) ->
      Fmt.pf ppf "bad mac: computed %a received %a data %a@ (state %a)"
        Cstruct.hexdump_pp computed Cstruct.hexdump_pp received
        Cstruct.hexdump_pp data pp state
  | `No_transition (channel, op, data) ->
      Fmt.pf ppf "no transition found for typ %a (channel %a)@.data %a"
        Packet.pp_operation op pp_channel channel Cstruct.hexdump_pp data
  | `No_channel keyid ->
      Fmt.pf ppf
        "no channel found for keyid %u, and not in the right state for rekeying"
        keyid
  | `Tls tls_e -> pp_tls_error ppf tls_e
  | `Payload_too_short (expected, actual) ->
      Fmt.pf ppf "payload too short (need %u bytes); got %u bytes" expected
        actual
  | `Msg msg -> Fmt.string ppf msg

let unpad block_size cs =
  let l = Cstruct.length cs in
  let amount = Cstruct.get_uint8 cs (pred l) in
  let len = l - amount in
  if len >= 0 && amount <= block_size then Ok (Cstruct_ext.sub cs 0 len)
  else Error (`Msg "bad padding")

let out ?add_timestamp prefix_len (ctx : keys) hmac_algorithm compress rng data
    =
  (* - compression only if configured (0xfa for uncompressed)
     the ~add_timestamp argument is only used in static key mode
  *)
  let set_replay_id dest off =
    Cstruct.BE.set_uint32 dest off ctx.my_replay_id
  in
  let aead (type key)
      (authenticate_encrypt_tag :
        key:key ->
        nonce:Cstruct.t ->
        ?adata:Cstruct.t ->
        Cstruct.t ->
        Cstruct.t * Cstruct.t) (my_key : key) my_implicit_iv =
    let nonce, replay_id =
      let b =
        Cstruct.create_unsafe (Packet.id_len + Cstruct.length my_implicit_iv)
      in
      set_replay_id b 0;
      Cstruct.blit my_implicit_iv 0 b 4 (Cstruct.length my_implicit_iv);
      (* We reuse the replay id part of the nonce to avoid another allocation *)
      (b, Cstruct.sub b 0 4)
    in
    let data =
      if compress then (
        let b =
          Cstruct.create_unsafe (Bool.to_int compress + Cstruct.length data)
        in
        (* 0xFA is "no compression" *)
        Cstruct.set_uint8 b 0 0xfa;
        Cstruct.blit data 0 b 1 (Cstruct.length data);
        b)
      else data
    in
    let enc, tag =
      authenticate_encrypt_tag ~key:my_key ~nonce ~adata:replay_id data
    in
    Cstruct_ext.concat_with_unsafe_prefix prefix_len [ replay_id; tag; enc ]
  in
  ( { ctx with my_replay_id = Int32.succ ctx.my_replay_id },
    match ctx.keys with
    | AES_CBC { my_key; my_hmac; _ } ->
        (* the wire format of CBC data packets is:
           hmac (IV enc(replay_id [timestamp] [compression] data pad))
           where:
           - hmac over the entire encrypted payload
             - timestamp only used in static key mode (32bit, seconds since unix epoch)
        *)
        let open Mirage_crypto in
        let hdr_len = 4 + if Option.is_some add_timestamp then 4 else 0 in
        let data =
          let unpad_len =
            hdr_len + Bool.to_int compress + Cstruct.length data
          in
          let pad_len =
            let l = unpad_len mod Cipher_block.AES.CBC.block_size in
            Cipher_block.AES.CBC.block_size - l
          in
          let b = Cstruct.create_unsafe (unpad_len + pad_len) in
          set_replay_id b 0;
          Option.iter (fun ts -> Cstruct.BE.set_uint32 b 4 ts) add_timestamp;
          if compress then
            (* 0xFA is "no compression" *)
            Cstruct.set_uint8 b hdr_len 0xfa;
          Cstruct.blit data 0 b
            (hdr_len + Bool.to_int compress)
            (Cstruct.length data);
          Cstruct.memset (Cstruct.sub b unpad_len pad_len) pad_len;
          b
        in
        let iv = rng Cipher_block.AES.CBC.block_size in
        let enc = Cipher_block.AES.CBC.encrypt ~key:my_key ~iv data in
        let hmac =
          Hash.maci hmac_algorithm ~key:my_hmac (fun feed ->
              feed iv;
              feed enc)
        in
        Cstruct_ext.concat_with_unsafe_prefix prefix_len [ hmac; iv; enc ]
    | AES_GCM { my_key; my_implicit_iv; _ } ->
        aead Mirage_crypto.Cipher_block.AES.GCM.authenticate_encrypt_tag my_key
          my_implicit_iv
    | CHACHA20_POLY1305 { my_key; my_implicit_iv; _ } ->
        aead Mirage_crypto.Chacha20.authenticate_encrypt_tag my_key
          my_implicit_iv )

let data_out ?add_timestamp (ctx : keys) hmac_algorithm compress protocol rng
    key data =
  (* as described in [out], ~add_timestamp is only used in static key mode *)
  let prefix_len = Packet.protocol_len protocol + 1 in
  let ctx, out =
    out ?add_timestamp prefix_len ctx hmac_algorithm compress rng data
  in
  Packet.encode_data out protocol key;
  Log.debug (fun m ->
      m "sending %d bytes data (enc %d) out id %lu" (Cstruct.length data)
        (Cstruct.length out) ctx.my_replay_id);
  (ctx, out)

let static_out ~add_timestamp ctx hmac_algorithm compress protocol rng data =
  let prefix_len = Packet.protocol_len protocol in
  let ctx, out =
    out ~add_timestamp prefix_len ctx hmac_algorithm compress rng data
  in
  Packet.set_protocol out protocol;
  Log.debug (fun m ->
      m "sending %d bytes data (enc %d) out id %lu" (Cstruct.length data)
        (Cstruct.length out) ctx.my_replay_id);
  (ctx, out)

let outgoing s data =
  let incr ch out =
    { ch with packets = succ ch.packets; bytes = Cstruct.length out + ch.bytes }
  in
  match (s.control_crypto, keys_opt s.channel) with
  | `Static keys, _ ->
      let add_timestamp = ptime_to_ts_exn (s.now ()) in
      let hmac_algorithm = Config.get Auth s.config in
      let keys, out =
        static_out ~add_timestamp keys hmac_algorithm s.session.compress
          s.session.protocol s.rng data
      in
      let channel = incr s.channel out in
      let control_crypto = `Static keys in
      Ok ({ s with control_crypto; channel; last_sent = s.ts () }, out)
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
  match (s.state, s.control_crypto) with
  | Client Ready, (#control_tls as cc) ->
      let session, channel, out = init_channel () in
      (* allocate new channel, send out a rst (and await a rst) *)
      let state = Client (Rekeying channel) in
      let out = wrap_and_out s.session.protocol cc keyid out in
      ({ s with state; session }, [ out ])
  | Server Server_ready, `Tls_auth tls_auth ->
      let session, channel, out = init_channel () in
      let state = Server (Server_rekeying channel) in
      let out = hmac_and_out s.session.protocol tls_auth keyid out in
      ({ s with state; session }, [ out ])
  | _, `Static _ ->
      (* there's no rekey mechanism in static mode *)
      (s, [])
  | _, _ ->
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
           && y > 0 ->
        true
    | _, Some b, _ when b <= state.channel.bytes && b > 0 -> true
    | _, _, Some p when p <= state.channel.packets && p > 0 -> true
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
           where plain data consists of replay_id [timestamp] [compress] data pad

           note that the timestamp is only used in static key mode, when
           ~add_timestamp is provided and true.
        *)
        let open Mirage_crypto in
        let module H = (val Mirage_crypto.Hash.module_of hmac_algorithm) in
        let hmac, data = Cstruct.split data H.digest_size in
        let computed_hmac = H.hmac ~key:their_hmac data in
        let* () =
          guard (Cstruct.equal hmac computed_hmac) (err hmac computed_hmac)
        in
        let iv, data = Cstruct.split data Cipher_block.AES.CBC.block_size in
        let dec = Cipher_block.AES.CBC.decrypt ~key:their_key ~iv data in
        (* dec is: uint32 replay packet id followed by (lzo-compressed) data and padding *)
        let hdr_len = Packet.id_len + if add_timestamp then 4 else 0 in
        let* () =
          guard
            (Cstruct.length dec >= hdr_len)
            (`Payload_too_short (hdr_len, Cstruct.length dec))
        in
        (* TODO validate replay packet id and ordering *)
        Log.debug (fun m ->
            m "received replay packet id is %lu" (Cstruct.BE.get_uint32 dec 0));
        (* TODO validate ts if provided (avoid replay) *)
        unpad Cipher_block.AES.CBC.block_size (Cstruct.shift dec hdr_len)
    | AES_GCM { their_key; their_implicit_iv; _ } ->
        let tag_len = Mirage_crypto.Cipher_block.AES.GCM.tag_size in
        let* () =
          guard
            (Cstruct.length data >= Packet.id_len + tag_len)
            (`Payload_too_short (Packet.id_len + tag_len, Cstruct.length data))
        in
        let replay_id, tag, payload =
          let sn, rest = Cstruct.split data Packet.id_len in
          let tag, payload = Cstruct.split rest tag_len in
          (sn, tag, payload)
        in
        let nonce = Cstruct.append replay_id their_implicit_iv in
        let plain =
          Mirage_crypto.Cipher_block.AES.GCM.authenticate_decrypt_tag
            ~key:their_key ~nonce ~adata:replay_id ~tag payload
        in
        (* TODO validate replay packet id and ordering *)
        Log.debug (fun m ->
            m "received replay packet id is %lu"
              (Cstruct.BE.get_uint32 replay_id 0));
        Option.to_result ~none:(`Msg "AEAD decrypt failed") plain
    | CHACHA20_POLY1305 { their_key; their_implicit_iv; _ } ->
        let tag_len = Mirage_crypto.Chacha20.tag_size in
        let* () =
          guard
            (Cstruct.length data >= Packet.id_len + tag_len)
            (`Payload_too_short (Packet.id_len + tag_len, Cstruct.length data))
        in
        let replay_id, tag, payload =
          let sn, rest = Cstruct.split data Packet.id_len in
          let tag, payload = Cstruct.split rest tag_len in
          (sn, tag, payload)
        in
        let nonce = Cstruct.append replay_id their_implicit_iv in
        let plain =
          Mirage_crypto.Chacha20.authenticate_decrypt_tag ~key:their_key ~nonce
            ~adata:replay_id ~tag payload
        in
        (* TODO validate replay packet id and ordering *)
        Log.debug (fun m ->
            m "received replay packet id is %lu"
              (Cstruct.BE.get_uint32 replay_id 0));
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

let split_control ~acks mtu outs =
  (* only the first control/ack packet is carrying acks *)
  List.rev
    (fst
       (List.fold_left
          (fun (acc, idx) -> function
            | `Control, data ->
                let first_mtu = if idx = 0 then mtu - acks else mtu in
                let outs =
                  if first_mtu < Cstruct.length data then
                    let rec datas acc data =
                      if Cstruct.is_empty data then acc
                      else
                        let l = min mtu (Cstruct.length data) in
                        let data, rest = Cstruct.split data l in
                        datas (data :: acc) rest
                    in
                    let data1, rdata = Cstruct.split data first_mtu in
                    datas [ data1 ] rdata
                  else [ data ]
                in
                (List.map (fun data -> (`Control, data)) outs @ acc, succ idx)
            | ((`Ack | `Reset_server | `Reset), _) as p ->
                (* we could assert that it always fits into a single packet *)
                (p :: acc, succ idx))
          ([], 0) outs))

let op_of_typ = function
  | `Ack -> Packet.Ack
  | `Control -> Packet.Control
  | `Reset_server -> Packet.Hard_reset_server_v2
  | `Reset -> Packet.Soft_reset_v2

let bytes_of_acks transport =
  let amount =
    Int32.to_int
      (Int32.sub transport.their_sequence_number
         transport.last_acked_sequence_number)
  in
  if amount > 0 then
    (amount * Packet.id_len) + Packet.session_id_len (* remote session *)
  else amount

let finish_control now ts mtu session key transport outs =
  let now_ts = ptime_to_ts_exn now in
  let acks = bytes_of_acks transport in
  let outs = split_control ~acks mtu outs in
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
              let transport, sn = next_sequence_number transport in
              (session, transport, `Control (op, (header, sn, out)))
        in
        let out_packets =
          match p with
          | `Ack _ -> transport.out_packets
          | `Control (_, (_, sn, _)) as p ->
              IM.add sn (ts, (key, p)) transport.out_packets
        in
        (session, { transport with out_packets }, p :: acc))
      (session, transport, []) outs
  in
  (session, transport, List.rev outs)

let maybe_add_wkc now mtu session tls_crypt needs_wkc key transport outs =
  let now_ts = ptime_to_ts_exn now in
  (* If we reply with hmac cookie we must split such that the first control
     packet, the Control_wkc has room for the /cleartext/ wkc, and fix the
     packet length afterwards *)
  match (needs_wkc, outs) with
  | Some wkc, (`Control, data) :: rest ->
      let wkc = Tls_crypt.Wrapped_key.unsafe_to_cstruct wkc in
      let acks = bytes_of_acks transport in
      let l = min (mtu - acks - Cstruct.length wkc) (Cstruct.length data) in
      let data, data' = Cstruct.split data l in
      let rest =
        if Cstruct.is_empty data' then rest else (`Control, data') :: rest
      in
      let session, transport, header = header session transport now_ts in
      let transport, sn = next_sequence_number transport in
      let p = `Control (Packet.Control_wkc, (header, sn, data)) in
      (* First we encrypt *)
      let out = encrypt_and_out session.protocol tls_crypt key p in
      (* Then we append wkc and fix the length if TCP *)
      let out = Cstruct.append out wkc in
      Packet.set_protocol out session.protocol;
      (session, transport, Some out, rest)
  | Some _, _ ->
      Log.err (fun m ->
          m "wrap_tls_crypt_control: expected control to append wkc");
      assert false
  | None, _ -> (session, transport, None, outs)

let wrap_control state control_crypto needs_wkc key transport outs =
  let now = state.now ()
  and ts = state.ts ()
  and my_mtu = control_mtu state.config control_crypto state.session in
  let session, transport, maybe_wkc, outs =
    match control_crypto with
    | `Tls_auth _ -> (state.session, transport, None, outs)
    | `Tls_crypt (tls_crypt, _wkc) ->
        maybe_add_wkc now my_mtu state.session tls_crypt needs_wkc key transport
          outs
  in
  let session, transport, outs =
    finish_control now ts my_mtu session key transport outs
  in
  let outs = List.map (wrap_and_out session.protocol control_crypto key) outs in
  let outs =
    Option.fold ~none:outs ~some:(fun c_wkc -> c_wkc :: outs) maybe_wkc
  in
  (session, transport, outs)

let send_control_message s data =
  let open Result.Syntax in
  match s.control_crypto with
  | `Static _ ->
      (* XXX(reynir) :/ *)
      Error `Not_ready
  | #control_tls as control_crypto ->
      let* channel_st, out =
        match (s.state, s.channel.channel_st) with
        | (Client Ready | Server Server_ready), Established (tls, keys) ->
            let data' = Cstruct.create_unsafe (String.length data + 1) in
            Cstruct.blit_from_string data 0 data' 0 (String.length data);
            Cstruct.set_uint8 data' (String.length data) 0;
            let* tls, out =
              (* reynir: I *think* it only returns [None] when not established
                 or after write is shutdown. *)
              Option.to_result ~none:`Not_ready
                (Tls.Engine.send_application_data tls [ data' ])
            in
            Ok (Established (tls, keys), (`Control, out))
        | _, _ ->
            Log.warn (fun m ->
                m
                  "Failed to send control channel message %S on an \
                   unestablished or unready connection"
                  data);
            Error `Not_ready
      in
      let key = s.channel.keyid in
      let session, transport, encs =
        wrap_control s control_crypto None key s.channel.transport [ out ]
      in
      let channel = { s.channel with transport; channel_st } in
      let s = { s with channel; session } in
      Ok (s, encs)

let find_channel state key op =
  match channel_of_keyid key state with
  | Some _ as c -> c
  | None -> (
      Log.warn (fun m -> m "no channel found! %d" key);
      match (state.state, op) with
      | Client Ready, Packet.Soft_reset_v2 ->
          let channel = new_channel key (state.ts ()) in
          Some (channel, fun s ch -> { s with state = Client (Rekeying ch) })
      | Server Server_ready, Packet.Soft_reset_v2 ->
          let channel = new_channel key (state.ts ()) in
          Some
            (channel, fun s ch -> { s with state = Server (Server_rekeying ch) })
      | ( ( Client (Resolving _ | Connecting _ | Handshaking _ | Rekeying _)
          | Server (Server_handshaking | Server_rekeying _) ),
          Packet.Soft_reset_v2 ) ->
          Log.warn (fun m ->
              m "ignoring soft_reset_v2 in non-ready state %a" pp state);
          None
      | ( ( Client
              (Resolving _ | Connecting _ | Handshaking _ | Ready | Rekeying _)
          | Server (Server_handshaking | Server_ready | Server_rekeying _) ),
          Packet.(
            ( Control | Ack | Data_v1 | Hard_reset_client_v2
            | Hard_reset_server_v2 | Hard_reset_client_v3 | Control_wkc )) ) ->
          Log.warn (fun m ->
              m "ignoring unexpected packet %a in %a" Packet.pp_operation op pp
                state);
          None)

let received_data state ch set_ch payload =
  let open Result.Syntax in
  match keys_opt ch with
  | None ->
      Log.warn (fun m -> m "received data, but no keys yet");
      Ok (state, None)
  | Some keys ->
      let ch = received_packet ch payload in
      let hmac_algorithm = Config.get Auth state.config in
      let bad_mac computed rcv = `Bad_mac (state, computed, rcv, payload) in
      let+ payload =
        incoming_data bad_mac keys hmac_algorithm state.session.compress payload
      in
      (set_ch state ch, payload)

let validate_control state control_crypto op key payload =
  let open Result.Syntax in
  match control_crypto with
  | `Tls_auth { hmac_algorithm; their_hmac; _ } ->
      let hmac, tbs =
        let hmac_len = Mirage_crypto.Hash.digest_size hmac_algorithm in
        Packet.split_hmac hmac_len op key payload
      in
      let computed_mac =
        Mirage_crypto.Hash.mac hmac_algorithm ~key:their_hmac tbs
      in
      let* () =
        guard
          (Eqaf_cstruct.equal computed_mac hmac)
          (`Bad_mac (state, computed_mac, hmac, tbs))
      in
      let+ p = Packet.decode_ack_or_control op tbs in
      (p, None)
  | `Tls_crypt ({ their; _ }, wkc_opt) ->
      let* cleartext, encrypted =
        Packet.Tls_crypt.decode_cleartext_header payload
      in
      let module Aes_ctr = Mirage_crypto.Cipher_block.AES.CTR in
      let iv = Cstruct.sub cleartext.hmac 0 16 in
      let ctr = Aes_ctr.ctr_of_cstruct iv in
      let decrypted =
        let key = Tls_crypt.Key.cipher_key their in
        Aes_ctr.decrypt ~key ~ctr encrypted
      in
      let to_be_signed =
        Packet.Tls_crypt.to_be_signed op key cleartext decrypted
      in
      let computed_hmac =
        let key = Tls_crypt.Key.hmac their in
        Mirage_crypto.Hash.SHA256.hmac ~key to_be_signed
      in
      let* () =
        guard
          (Eqaf_cstruct.equal computed_hmac cleartext.hmac)
          (`Bad_mac (state, computed_hmac, cleartext.hmac, to_be_signed))
      in
      let* p =
        Packet.Tls_crypt.decode_decrypted_ack_or_control cleartext op decrypted
      in
      let+ needs_wkc =
        match (p, wkc_opt) with
        | `Control (Packet.Hard_reset_server_v2, (_, _, data)), Some wkc ->
            let+ needs_wkc = Packet.decode_early_negotiation_tlvs data in
            if needs_wkc then Some wkc else None
        | _ -> Ok None
      in
      (p, needs_wkc)

let incoming state control_crypto buf =
  let open Result.Syntax in
  let state = { state with last_received = state.ts () } in
  let udp_ignore = function
    | Error `Udp_ignore ->
        (* XXX: probably we want to track how many bad packets we get? *)
        Ok (state, [], [], None)
    | Error #error as r -> r
    | Ok _ as r -> r
  in
  let ignore_udp_error r =
    match (state.session.protocol, r) with
    | `Udp, Error e ->
        Log.info (fun m -> m "Ignoring bad packet: %a" pp_error e);
        Error `Udp_ignore
    | _, r -> (r : (_, error) result :> (_, [ error | `Udp_ignore ]) result)
  in
  let rec multi buf (state, out, payloads, act_opt) =
    match Packet.decode_key_op state.session.protocol buf with
    | (Error (`Unknown_operation _) | Error `Partial) as e -> ignore_udp_error e
    | Error `Tcp_partial ->
        (* we don't need to check protocol as [`Tcp_partial] is only ever returned for tcp *)
        Ok ({ state with linger = buf }, out, payloads, act_opt)
    | Ok (op, key, received, linger) ->
        let state = { state with linger } in
        let* state, out, payloads, act_opt =
          match find_channel state key op with
          | None -> ignore_udp_error (Error (`No_channel key))
          | Some (ch, set_ch) -> (
              Log.debug (fun m ->
                  m "channel %a - received key %u op %a" pp_channel ch key
                    Packet.pp_operation op);
              match op with
              | Packet.Data_v1 ->
                  let+ state, payload =
                    ignore_udp_error (received_data state ch set_ch received)
                  in
                  let payloads =
                    Option.fold payload ~none:payloads ~some:(fun p ->
                        p :: payloads)
                  in
                  (state, out, payloads, act_opt)
              | op -> (
                  let* p, needs_wkc =
                    ignore_udp_error
                      (validate_control state control_crypto op key received)
                  in
                  let* session, transport =
                    ignore_udp_error
                      (expected_packet state.session ch.transport p)
                  in
                  let state = { state with session }
                  and ch = { ch with transport } in
                  match p with
                  | `Ack _ -> Ok (set_ch state ch, out, payloads, act_opt)
                  | `Control (_, (_, _, data)) -> (
                      let* est, config, ch, out' =
                        incoming_control state.auth_user_pass state.is_not_taken
                          state.config state.rng state.state state.session ch
                          (state.now ()) (state.ts ()) key op data
                      in
                      Log.debug (fun m ->
                          m "out channel %a, pkts %d" pp_channel ch
                            (List.length out'));
                      (* each control needs to be acked! *)
                      let out' =
                        match out' with
                        | [] -> [ (`Ack, Cstruct.empty) ]
                        | xs -> xs
                      in
                      (* now prepare outgoing packets *)
                      let state = { state with session } in
                      let session, transport, encs =
                        wrap_control state control_crypto needs_wkc key
                          ch.transport out'
                      in
                      let out = out @ encs
                      and ch = { ch with transport }
                      and state = { state with config; session } in
                      match est with
                      | None -> Ok (set_ch state ch, out, payloads, act_opt)
                      | Some `Exit ->
                          let act =
                            match act_opt with
                            | None -> Some `Exit
                            | Some a_old ->
                                Log.warn (fun m ->
                                    m
                                      "Producing another action; ignoring \
                                       older %a and using newer %a"
                                      pp_action a_old pp_action `Exit);
                                Some `Exit
                          in
                          Ok (set_ch state ch, out, payloads, act)
                      | Some (#Cc_message.cc_message as a_new) ->
                          let act =
                            match act_opt with
                            | None -> Some a_new
                            | Some a_old ->
                                Log.warn (fun m ->
                                    m
                                      "Ignoring new control channel message %a \
                                       due to older action %a"
                                      pp_action a_new pp_action a_old);
                                Some a_old
                          in
                          Ok (set_ch state ch, out, payloads, act)
                      | Some (`Established ip_config) ->
                          let state = { state with channel = ch } in
                          let+ state, mtu = transition_to_established state in
                          let est =
                            Option.map
                              (fun mtu -> `Established (ip_config, mtu))
                              mtu
                          in
                          let act =
                            match (act_opt, est) with
                            | None, None -> None
                            | None, (Some _ as a) | (Some _ as a), None -> a
                            | Some a_old, (Some a_new as a) ->
                                Log.warn (fun m ->
                                    m
                                      "Producing another action; ignoring \
                                       older %a and using newer %a"
                                      pp_action a_old pp_action a_new);
                                a
                          in
                          (state, out, payloads, act))))
        in
        (* Invariant: [linger] is always empty for UDP *)
        if Cstruct.is_empty linger then Ok (state, out, payloads, act_opt)
        else multi linger (state, out, payloads, act_opt)
  in
  let r = multi (Cstruct_ext.append' state.linger buf) (state, [], [], None) in
  let+ s', out, payloads, act_opt = udp_ignore r in
  Log.debug (fun m -> m "out state is %a" State.pp s');
  Log.debug (fun m ->
      m "%u outgoing packets (%d bytes)" (List.length out) (Cstruct.lenv out));
  Log.debug (fun m ->
      m "%u payloads (%d bytes)" (List.length payloads) (Cstruct.lenv payloads));
  Log.debug (fun m ->
      m "action %a" Fmt.(option ~none:(any "none") pp_action) act_opt);
  (s', out, List.rev payloads, act_opt)

let new_connection server data =
  let open Result.Syntax in
  let protocol = `Tcp in
  let session =
    init_session
      ~my_session_id:(Randomconv.int64 server.server_rng)
      ~protocol ()
  in
  let current_ts = server.server_ts () in
  let channel = new_channel 0 current_ts in
  let* t, (control_crypto : control_tls), packet =
    let tls_auth_or_tls_crypt error =
      let+ (control_crypto : control_tls) =
        match
          (tls_auth server.server_config, tls_crypt server.server_config)
        with
        | Ok auth, Error _ -> Ok (`Tls_auth auth)
        | Error _, Ok crypt -> Ok (`Tls_crypt (crypt, None))
        | _ -> Error error
      in
      ( {
          config = server.server_config;
          is_not_taken = server.is_not_taken;
          auth_user_pass = server.auth_user_pass;
          control_crypto :> control_crypto;
          state = Server Server_handshaking;
          linger = Cstruct.empty;
          rng = server.server_rng;
          ts = server.server_ts;
          now = server.server_now;
          session;
          channel;
          lame_duck = None;
          last_received = current_ts;
          last_sent = current_ts;
        },
        control_crypto,
        data )
    in
    match Config.find Tls_crypt_v2_server server.server_config with
    | None ->
        tls_auth_or_tls_crypt
          (`Msg "server only supports tls-auth or tls-crypt")
    | Some (_wrapping_key, true) ->
        (* TODO: HMAC cookie support *)
        Error (`Msg "Server does not support hmac cookies (yet)")
    | Some (wrapping_key, false) -> (
        match Packet.decode_key_op protocol data with
        | Error `Tcp_partial ->
            (* It is unlikely that we don't read a full packet in first try and it is annoying to handle. *)
            assert false
        | Error _ as e -> e
        | Ok (Packet.Hard_reset_client_v2, _key, _received, linger) ->
            assert (Cstruct.is_empty linger);
            tls_auth_or_tls_crypt (`Msg "server only supports tls-crypt-v2")
        | Ok (Packet.Hard_reset_client_v3, key, received, linger) ->
            assert (Cstruct.is_empty linger);
            (* decode and unwrap wKc *)
            let* actual_packet, wkc =
              Tls_crypt.Wrapped_key.of_cstruct received
            in
            let actual_packet =
              let buf = Cstruct.create (Cstruct.length actual_packet + 3) in
              Packet.set_protocol buf `Tcp;
              Cstruct.set_uint8 buf 2
                (Packet.op_key Packet.Hard_reset_client_v3 key);
              Cstruct.blit actual_packet 0 buf 3 (Cstruct.length actual_packet);
              buf
            in
            let* tls_crypt, metadata =
              Tls_crypt.Wrapped_key.unwrap ~key:wrapping_key wkc
            in
            Log.debug (fun m ->
                m "metadata is %a" Tls_crypt.Metadata.pp_hum metadata);
            let control_crypto =
              `Tls_crypt
                ( {
                    my = Tls_crypt.server_key tls_crypt;
                    their = Tls_crypt.client_key tls_crypt;
                  },
                  None )
            in
            Ok
              ( {
                  config = server.server_config;
                  auth_user_pass = server.auth_user_pass;
                  is_not_taken = server.is_not_taken;
                  control_crypto;
                  state = Server Server_handshaking;
                  linger = Cstruct.empty;
                  rng = server.server_rng;
                  ts = server.server_ts;
                  now = server.server_now;
                  session;
                  channel;
                  lame_duck = None;
                  last_received = current_ts;
                  last_sent = current_ts;
                },
                control_crypto,
                actual_packet )
        | Ok (_not_hard_reset_client, _key, _received, _linger) ->
            Error (`Msg "invalid initial packet"))
    (* `No_transition *)
  in
  incoming t control_crypto packet

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

let resolve_connect_client t ts s ev =
  let open Result.Syntax in
  let remote, next_remote =
    let remotes = Config.get Remote t.config in
    let r idx = List.nth remotes idx in
    let next idx =
      if succ idx = List.length remotes then None else Some (r (succ idx))
    in
    (r, next)
  and retry_exceeded r =
    match Config.get Connect_retry_max t.config with
    | `Times m -> r >= m
    | `Unlimited -> false
  in
  let next_or_fail t idx retry =
    let idx', retry', v =
      match next_remote idx with
      | None -> (0, succ retry, remote 0)
      | Some x -> (succ idx, retry, x)
    in
    if retry_exceeded retry' then
      Error (`Msg "maximum connection retries exceeded")
    else
      let state, action =
        match v with
        | `Domain (name, ip_version), _, _ ->
            (Resolving (idx', ts, retry'), `Resolve (name, ip_version))
        | `Ip ip, port, dp ->
            (Connecting (idx', ts, retry'), `Connect (ip, port, dp))
      in
      (* We reset [linger] to enforce the invariant that [linger] is empty when
         we are connecting (or resolving) *)
      Ok ({ t with linger = Cstruct.empty; state = Client state }, action)
  in
  match (s, ev) with
  | Resolving (idx, _, retry), `Resolved ip ->
      (* TODO enforce ipv4/ipv6 *)
      let endp = match remote idx with _, port, dp -> (ip, port, dp) in
      let t = { t with state = Client (Connecting (idx, ts, retry)) } in
      Ok (t, Some (`Connect endp))
  | Resolving (idx, _, retry), `Resolve_failed ->
      let+ t, action = next_or_fail t idx retry in
      (t, Some action)
  | Connecting (idx, _, retry), `Connection_failed ->
      let+ t, action = next_or_fail t idx retry in
      (t, Some action)
  | Connecting (idx, initial_ts, retry), `Tick ->
      (* We are trying to establish a connection and a clock tick happens.
         We need to determine if {!Config.Connect_timeout} seconds has passed
         since [initial_ts] (when we started connecting), and if so,
         try the next [Remote]. *)
      let conn_timeout =
        Duration.of_sec Config.(get Connect_timeout t.config)
      in
      if Int64.sub ts initial_ts >= conn_timeout then (
        Log.err (fun m -> m "Connecting to remote #%d timed out" idx);
        let+ t, action = next_or_fail t idx retry in
        (t, Some action))
      else Ok (t, None)
  | _, `Connection_failed ->
      (* re-start from scratch *)
      let+ t, action = next_or_fail t (-1) 0 in
      (t, Some action)
  | _ -> Error (`Not_handled (remote, next_or_fail))

let handshake_timeout next_or_fail t s ts =
  let open Result.Syntax in
  match
    match (t.session.protocol, s) with
    | `Udp, Handshaking _ -> Some (t.channel, fun channel -> { t with channel })
    | `Udp, Rekeying ch ->
        Some (ch, fun channel -> { t with state = Client (Rekeying channel) })
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
          let+ t, action = next_or_fail t (-1) 0 in
          (t, [], Some action))

let handle_client t control_crypto s ev =
  let open Result.Syntax in
  let now = t.now () and ts = t.ts () in
  match resolve_connect_client t ts s ev with
  | Ok (t, action) -> Ok (t, [], [], action)
  | Error (`Msg _) as e -> e
  | Error (`Not_handled (remote, next_or_fail)) -> (
      match (s, ev) with
      | Connecting (idx, _, _), `Connected ->
          let my_session_id = Randomconv.int64 t.rng in
          let protocol = match remote idx with _, _, proto -> proto in
          let keyid = 0 in
          let session = init_session ~my_session_id ~protocol () in
          let session, channel, out =
            match control_crypto with
            | `Tls_crypt (_, Some wkc) ->
                let wkc = Tls_crypt.Wrapped_key.unsafe_to_cstruct wkc in
                let session = { session with my_replay_id = 0x0f000001l } in
                init_channel ~payload:wkc Packet.Hard_reset_client_v3 session
                  keyid now ts
            | `Tls_crypt (_, None) | `Tls_auth _ ->
                init_channel Packet.Hard_reset_client_v2 session keyid now ts
          in
          let state = Client (Handshaking (idx, ts)) in
          let out = wrap_and_out t.session.protocol control_crypto keyid out in
          Ok ({ t with state; channel; session }, [ out ], [], None)
      | s, `Tick -> (
          let* t, out, action_opt = handshake_timeout next_or_fail t s ts in
          let out =
            List.map
              (fun (keyid, p) ->
                wrap_and_out t.session.protocol control_crypto keyid p)
              out
          in
          match action_opt with
          | Some action -> Ok (t, out, [], Some action)
          | None -> (
              match maybe_ping_timeout t with
              | Some `Exit -> Ok (t, out, [], Some `Exit)
              | Some `Restart ->
                  let+ t, action = next_or_fail t (-1) 0 in
                  (t, out, [], Some action)
              | None ->
                  let t', outs = timer t in
                  Ok (t', out @ outs, [], None)))
      | _, `Data cs -> incoming t control_crypto cs
      | s, ev ->
          Result.error_msgf "handle_client: unexpected event %a in state %a"
            pp_event ev pp_client_state s)

(* timeouts from a server perspective:
   still TODO (similar to client, maybe in udp branch)
   hs; - handshake-window -- until handshaking -> ready (discard connection attempt)
   hs; - tls-timeout -- same, discard connection attempt [in tcp not yet relevant]
*)
let handle_server t cc s ev =
  match (s, ev) with
  | _, `Data cs -> incoming t cc cs
  | (Server_ready | Server_rekeying _), `Tick -> (
      match maybe_ping_timeout t with
      | Some _ -> Ok (t, [], [], Some `Exit)
      | None ->
          let t', outs = timer t in
          Ok (t', outs, [], None))
  | Server_handshaking, `Tick ->
      Log.warn (fun m -> m "ignoring tick in handshaking");
      Ok (t, [], [], None)
  | s, ev ->
      Result.error_msgf "handle_server: unexpected event %a in state %a"
        pp_event ev pp_server_state s

let handle_static_client t s keys ev =
  let open Result.Syntax in
  let ts = t.ts () in
  match resolve_connect_client t ts s ev with
  | Ok (t, action) -> Ok (t, [], [], action)
  | Error (`Msg _) as e -> e
  | Error (`Not_handled (remote, next_or_fail)) -> (
      match (s, ev) with
      | Connecting (idx, _, _), `Connected -> (
          match Config.get Ifconfig t.config with
          | V4 my_ip, V4 their_ip ->
              let mtu = data_mtu t.config t.session in
              let cidr = Ipaddr.V4.Prefix.make 32 my_ip in
              let est = `Established ({ cidr; gateway = their_ip }, mtu) in
              let protocol = match remote idx with _, _, proto -> proto in
              let session = { t.session with protocol } in
              let hmac_algorithm = Config.get Auth t.config in
              let keys, out =
                let add_timestamp = ptime_to_ts_exn (t.now ()) in
                static_out ~add_timestamp keys hmac_algorithm t.session.compress
                  protocol t.rng ping
              in
              let state = Client Ready and control_crypto = `Static keys in
              Ok
                ( { t with state; control_crypto; session; last_sent = ts },
                  [ out ],
                  [],
                  Some est )
          | _ -> Error (`Msg "expected IPv4 addresses"))
      | _, `Tick -> (
          match maybe_ping_timeout t with
          | Some `Exit -> Ok (t, [], [], Some `Exit)
          | Some `Restart ->
              let+ t, action = next_or_fail t (-1) 0 in
              (t, [], [], Some action)
          | None ->
              let t', outs = timer t in
              Ok (t', outs, [], None))
      | _, `Data cs ->
          let t = { t with last_received = ts } in
          let add_timestamp = true
          and compress = t.session.compress
          and hmac_algorithm = Config.get Auth t.config in
          let rec process_one acc linger =
            if Cstruct.length linger = 0 then
              Ok ({ t with linger = Cstruct.empty }, acc)
            else
              match Packet.decode_protocol t.session.protocol linger with
              | Error `Partial -> Error `Partial
              | Error `Tcp_partial ->
                  (* we don't need to check protocol as [`Tcp_partial] is only ever returned for tcp *)
                  Ok ({ t with linger }, acc)
              | Ok (cs, linger) ->
                  let bad_mac computed rcv = `Bad_mac (t, computed, rcv, cs) in
                  let* d =
                    incoming_data ~add_timestamp bad_mac keys hmac_algorithm
                      compress cs
                  in
                  let acc = Option.fold d ~none:acc ~some:(fun p -> p :: acc) in
                  process_one acc linger
          in
          let+ t, payloads = process_one [] (Cstruct_ext.append' t.linger cs) in
          (t, [], List.rev payloads, None)
      | s, ev ->
          Result.error_msgf
            "handle_static_client: unexpected event %a in state %a" pp_event ev
            pp_client_state s)

let handle t ev =
  match (t.state, t.control_crypto) with
  | Client state, (#control_tls as cc) -> handle_client t cc state ev
  | Client state, `Static keys -> handle_static_client t state keys ev
  | Server state, (#control_tls as cc) -> handle_server t cc state ev
  | Server _, `Static _ -> Error (`Msg "server does not support static keys")
