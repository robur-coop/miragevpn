let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)
let now = Ptime_clock.now
let ts () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())

let tls_auth =
  ( None,
    Cstruct.create 64,
    Cstruct.create 64,
    Cstruct.create 64,
    Cstruct.create 64 )

let () =
  let reporter_with_ts ~dst () =
    let pp_tags f tags =
      let pp tag () =
        let (Logs.Tag.V (def, value)) = tag in
        Format.fprintf f " %s=%a" (Logs.Tag.name def) (Logs.Tag.printer def)
          value;
        ()
      in
      Logs.Tag.fold pp tags ()
    in
    let report src level ~over k msgf =
      let tz_offset_s = Ptime_clock.current_tz_offset_s () in
      let posix_time = Ptime_clock.now () in
      let src = Logs.Src.name src in
      let k _ =
        over ();
        k ()
      in
      msgf @@ fun ?header ?tags fmt ->
      Format.kfprintf k dst
        ("%a:%a %a [%s] @[" ^^ fmt ^^ "@]@.")
        (Ptime.pp_rfc3339 ?tz_offset_s ())
        posix_time
        Fmt.(option ~none:(any "") pp_tags)
        tags Logs_fmt.pp_header (level, header) src
    in
    { Logs.report }
  in
  Fmt_tty.setup_std_outputs ();
  Logs.set_level (Some Logs.Info);
  List.iter
    (fun src ->
      if String.starts_with ~prefix:"ovpn" (Logs.Src.name src) then
        Logs.Src.set_level src (Some Logs.Debug))
    (Logs.Src.list ());
  Logs.set_reporter (reporter_with_ts ~dst:Format.std_formatter ())

let key = X509.Private_key.generate ~bits:2048 `RSA

let ca, cert =
  let subject =
    [
      X509.Distinguished_name.(
        Relative_distinguished_name.singleton (CN "Miragevpn snakeoil"));
    ]
  in
  let digest = `SHA256 in
  let csr = X509.Signing_request.create ~digest subject key |> Result.get_ok in
  let pubkey = (X509.Signing_request.info csr).public_key in
  let extensions =
    let open X509.Extension in
    let auth =
      (Some (X509.Public_key.id pubkey), X509.General_name.empty, None)
    in
    singleton Authority_key_id (false, auth)
    |> add Subject_key_id (false, X509.Public_key.id pubkey)
    |> add Basic_constraints (true, (true, None))
    |> add Key_usage
         ( true,
           [
             `Key_cert_sign;
             `CRL_sign;
             `Digital_signature;
             `Content_commitment;
             `Key_encipherment;
           ] )
    |> add Ext_key_usage (true, [ `Server_auth ])
  in
  let valid_from = now () in
  let valid_until =
    Ptime.add_span valid_from (Ptime.Span.of_int_s 60) |> Option.get
  in
  let cert =
    match
      X509.Signing_request.sign csr ~valid_from ~valid_until ~digest ~extensions
        key subject
    with
    | Ok cert -> cert
    | Error e ->
        Format.kasprintf failwith "cert error %a"
          X509.Validation.pp_signature_error e
  in
  (cert, cert)

let minimal_config =
  let open Config in
  empty
  (* from {!Miragevpn.Config.Defaults.client_config} *)
  |> add Ping_interval `Not_configured
  |> add Ping_timeout (`Restart 120)
  |> add Renegotiate_seconds 3600
  |> add Bind (Some (None, None)) (* TODO default to 1194 for servers? *)
  |> add Handshake_window 60 |> add Transition_window 3600 |> add Tls_timeout 2
  |> add Resolv_retry `Infinite |> add Auth_retry `None
  |> add Connect_timeout 120
  |> add Connect_retry_max `Unlimited
  |> add Proto (None, `Tcp None)
  |> add Auth `SHA1
  (* Minimal contents of actual config file: *)
  |> add Cipher `AES_256_CBC
  |> add Data_ciphers [ `AES_128_GCM; `AES_256_GCM; `CHACHA20_POLY1305 ]
  |> add Tls_mode `Client
  |> add Auth_user_pass ("testuser", "testpass")
  |> add Remote [ (`Ip (Ipaddr.of_string_exn "10.0.0.1"), 1194, `Tcp) ]
  |> add Tls_auth tls_auth |> add Ca [ ca ]

let minimal_server_config =
  let open Config in
  empty
  (* from {!Miragevpn.Config.Defaults.client_config} *)
  |> add Ping_interval `Not_configured
  |> add Ping_timeout (`Restart 120)
  |> add Renegotiate_seconds 3600
  |> add Bind (Some (None, None)) (* TODO default to 1194 for servers? *)
  |> add Handshake_window 60 |> add Transition_window 3600 |> add Tls_timeout 2
  |> add Resolv_retry `Infinite |> add Auth_retry `None
  |> add Connect_timeout 120
  |> add Connect_retry_max `Unlimited
  |> add Proto (None, `Tcp None)
  |> add Auth `SHA1
  (* Minimal contents of actual config file: *)
  |> add Cipher `AES_256_CBC
  |> add Data_ciphers [ `AES_128_GCM; `AES_256_GCM; `CHACHA20_POLY1305 ]
  |> add Tls_mode `Server
  |> add Server (Ipaddr.V4.Prefix.of_string_exn "10.0.1.0/24")
  |> add Tls_auth tls_auth |> add Ca [ ca ] |> add Tls_cert cert
  |> add Tls_key key

let[@ocaml.warning "-8"] initial_client, inital_client_outs, _application, None
    =
  let pre_connect =
    match Engine.client minimal_config ts now Mirage_crypto_rng.generate with
    | Ok (s, _) -> s
    | Error (`Msg e) -> Format.ksprintf failwith "Client config error: %s" e
  in
  Engine.handle pre_connect `Connected |> Result.get_ok

let initial_server =
  let server =
    match
      Engine.server minimal_server_config ts now Mirage_crypto_rng.generate
    with
    | Ok (s, _, _) -> s
    | Error (`Msg e) -> Format.ksprintf failwith "Server config error: %s" e
  in
  Engine.new_connection server

let established_client, establish_server =
  let drain role state inputs =
    let state, outs =
      List.fold_left
        (fun (state, outs) input ->
          match Engine.handle state (`Data input) with
          | Ok (state, outs', _application, None) ->
              Format.eprintf "%s state @[<1>%a@]\n%!" role State.pp state;
              (state, outs' :: outs)
          | Ok (_, _, _, Some act) ->
              Format.kasprintf failwith "Unexpected action %a" State.pp_action
                act
          | Error e ->
              Format.kasprintf failwith "%s error: %a" role Engine.pp_error e)
        (state, []) inputs
    in
    let outs = List.concat (List.rev outs) in
    Printf.eprintf "Drained %d packets resulting in %d %s packets\n%!"
      (List.length inputs) (List.length outs) role;
    (state, outs)
  in
  let server, server_outs = drain "Server" initial_server inital_client_outs in
  let client, client_outs = drain "Client" initial_client server_outs in
  let server, server_outs = drain "Server" server client_outs in
  let client, client_outs = drain "Client" client server_outs in
  let server, server_outs = drain "Server" server client_outs in
  ignore server_outs;
  (client, server)
