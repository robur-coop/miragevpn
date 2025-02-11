let cipher_to_string = function
  | `AES_128_GCM -> "AES-128-GCM"
  | `AES_256_GCM -> "AES-256-GCM"
  | `CHACHA20_POLY1305 -> "CHACHA20-POLY1305"
  | `AES_256_CBC -> "AES-256-CBC"

let () = Mirage_crypto_rng_unix.use_default ()

let tls_auth =
  ( None,
    String.make 64 '\000',
    String.make 64 '\000',
    String.make 64 '\000',
    String.make 64 '\000' )

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
  let valid_from = Ptime_clock.now () in
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

let established cipher =
  let minimal_config =
    let open Miragevpn.Config in
    empty
    (* from {!Miragevpn.Config.Defaults.client_config} *)
    |> add Ping_interval `Not_configured
    |> add Ping_timeout (`Restart 120)
    |> add Renegotiate_seconds 3600
    |> add Handshake_window 60 |> add Transition_window 3600
    |> add Tls_timeout 2 |> add Resolv_retry `Infinite |> add Auth_retry `None
    |> add Connect_timeout 120
    |> add Connect_retry_max `Unlimited
    |> add Proto (None, `Tcp None)
    |> add Auth `SHA1
    (* Minimal contents of actual config file: *)
    |> add Cipher `AES_256_CBC
    |> add Data_ciphers [ `AES_128_GCM; `AES_256_GCM; `CHACHA20_POLY1305 ]
    |> add Tls_mode `Client
    |> add Auth_user_pass ("testuser", "testpass")
    |> add Remote [ (`Ip (Ipaddr.of_string_exn "10.0.0.1"), None, Some `Tcp) ]
    |> add Tls_auth tls_auth |> add Ca [ ca ] |> add Cipher cipher
    |> add Dev (`Tun, None)
  in
  let minimal_server_config =
    let open Miragevpn.Config in
    empty
    (* from {!Miragevpn.Config.Defaults.client_config} *)
    |> add Ping_interval `Not_configured
    |> add Ping_timeout (`Restart 120)
    |> add Renegotiate_seconds 3600
    |> add Handshake_window 60 |> add Transition_window 3600
    |> add Tls_timeout 2 |> add Resolv_retry `Infinite |> add Auth_retry `None
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
    |> add Tls_key key |> add Cipher cipher
    |> add Verify_client_cert `None
    |> add Dev (`Tun, None)
  in

  let[@ocaml.warning "-8"] ( initial_client,
                             [ inital_client_out ],
                             _application,
                             None ) =
    let pre_connect =
      match Miragevpn.client minimal_config with
      | Ok (s, _) -> s
      | Error (`Msg e) -> Format.ksprintf failwith "Client config error: %s" e
    in
    Miragevpn.handle pre_connect `Connected |> Result.get_ok
  in

  let initial_server =
    let is_not_taken _ = true in
    match
      Miragevpn.server ~really_no_authentication:true ~is_not_taken
        minimal_server_config
    with
    | Ok (s, _, _) -> s
    | Error (`Msg e) -> Format.ksprintf failwith "Server config error: %s" e
  in

  let drain role state inputs =
    let state, outs =
      List.fold_left
        (fun (state, outs) input ->
          match Miragevpn.handle state (`Data input) with
          | Ok (state, outs', _application_data, None) -> (state, outs' :: outs)
          | Ok (state, outs', _application_data, Some _act) ->
              (* TODO: add argument whether an action is expected, and fail on
                 unexpected actions. *)
              (state, outs' :: outs)
          | Error e ->
              Format.kasprintf failwith "%s error: %a" role Miragevpn.pp_error e)
        (state, []) inputs
    in
    let outs = List.concat (List.rev outs) in
    (state, outs)
  in
  let server, server_outs =
    match Miragevpn.new_connection initial_server inital_client_out with
    | Ok (state, outs, _application_data, _act_opt) -> (state, outs)
    | Error e ->
        Format.kasprintf failwith "server error: %a" Miragevpn.pp_error e
  in
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

let ciphers = [ `AES_256_CBC; `AES_128_GCM; `AES_256_GCM; `CHACHA20_POLY1305 ]

let test_send_data cipher =
  let staged =
    let established_client, _ = established cipher in
    let data = String.make 1024 '\000' in
    Staged.stage @@ fun () ->
    match Miragevpn.outgoing established_client data with
    | Ok _ -> ()
    | Error `Not_ready -> assert false
  in
  Test.make ~name:"encode data" staged

let test_receive_data cipher =
  let staged =
    let established_client, established_server = established cipher in
    let data = String.make 1024 '\000' in
    let pkt =
      match Miragevpn.outgoing established_server data with
      | Ok (_state, pkt) -> pkt
      | Error `Not_ready -> assert false
    in
    Staged.stage @@ fun () ->
    match Miragevpn.handle established_client (`Data pkt) with
    | Ok _ -> ()
    | Error err -> Format.kasprintf failwith "%a" Miragevpn.pp_error err
  in
  Test.make ~name:"decode data" staged

let test_client =
  Test.make_grouped ~name:"Client"
    (List.map
       (fun cipher ->
         Test.make_grouped ~name:(cipher_to_string cipher)
           [ test_send_data cipher; test_receive_data cipher ])
       ciphers)

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
