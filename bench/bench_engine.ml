let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)
let now = Ptime_clock.now
let ts () = Mtime.Span.to_uint64_ns (Mtime_clock.elapsed ())

let tls_auth =
  ( None,
    Cstruct.create 64,
    Cstruct.create 64,
    Cstruct.create 64,
    Cstruct.create 64 )

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
  let is_not_taken _ = true in
  let drain role state inputs =
    let state, outs =
      List.fold_left
        (fun (state, outs) input ->
          match Engine.handle ~is_not_taken state (`Data input) with
          | Ok (state, outs', _application_data, None) ->
              (state, outs' :: outs)
          | Ok (state, outs', _application_data, Some _act) ->
              (* TODO: add argument whether an action is expected, and fail on
                 unexpected actions. *)
              (state, outs' :: outs)
          | Error e ->
              Format.kasprintf failwith "%s error: %a" role Engine.pp_error e)
        (state, []) inputs
    in
    let outs = List.concat (List.rev outs) in
    (state, outs)
  in
  let server, server_outs = drain "Server" initial_server inital_client_outs in
  let client, client_outs = drain "Client" initial_client server_outs in
  let server, server_outs = drain "Server" server client_outs in
  let client, client_outs = drain "Client" client server_outs in
  let server, server_outs = drain "Server" server client_outs in
  let client, client_outs = drain "Client" client server_outs in
  let server, server_outs = drain "Server" server client_outs in
  let client, client_outs = drain "Client" client server_outs in
  let server, server_outs = drain "Server" server client_outs in
  assert (server_outs = []);
  (client, server)

open Bechamel

let test_send_data =
  let staged =
    let data = Cstruct.create 1024 in
    Staged.stage @@ fun () ->
    match Engine.outgoing established_client data with
    | Ok _ -> ()
    | Error `Not_ready -> assert false
  in
  Test.make ~name:"encode data" staged

let test_receive_data =
  let staged =
    let data = Cstruct.create 1024 in
    let pkt =
      match Engine.outgoing establish_server data with
      | Ok (_state, pkt) -> pkt
      | Error `Not_ready -> assert false
    in
    Staged.stage @@ fun () ->
    match Engine.handle established_client (`Data pkt) with
    | Ok _ -> ()
    | Error _ -> assert false
  in
  Test.make ~name:"decode data" staged

let test_client =
  Test.make_grouped ~name:"Client" [
    test_send_data;
    test_receive_data;
  ]

let benchmark () =
  let ols =
    Analyze.ols ~bootstrap:0 ~r_square:true ~predictors:Measure.[| run |]
  in
  let instances =
    Toolkit.Instance.[ minor_allocated; major_allocated; monotonic_clock ]
  in
  let cfg =
    Benchmark.cfg ~limit:2000 ~quota:(Time.second 0.5) ~kde:(Some 1000) ()
  in
  let raw_results = Benchmark.all cfg instances test_client in
  let results =
    List.map (fun instance -> Analyze.all ols instance raw_results) instances
  in
  let results = Analyze.merge ols instances results in
  (results, raw_results)

let () =
  List.iter
    (fun v -> Bechamel_notty.Unit.add v (Measure.unit v))
    Toolkit.Instance.[ minor_allocated; major_allocated; monotonic_clock ]

let img (window, results) =
  Bechamel_notty.Multiple.image_of_ols_results ~rect:window
    ~predictor:Measure.run results

open Notty_unix

let () =
  let window =
    match winsize Unix.stdout with
    | Some (w, h) -> { Bechamel_notty.w; h }
    | None -> { Bechamel_notty.w = 80; h = 1 }
  in
  let results, _ = benchmark () in
  img (window, results) |> eol |> output_image
