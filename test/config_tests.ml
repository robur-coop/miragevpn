
let a_x509_cert_payload ctx constructor str =
  Logs.debug (fun m -> m "x509 cert: %s" ctx);
  match X509.Certificate.decode_pem (Cstruct.of_string str) with
  | Ok cert -> Ok (constructor cert)
  | Error (`Msg msg) -> Error (Fmt.strf "%s: invalid certificate: %s" ctx msg)



let a_ca_payload str =
  let open Openvpn.Config in
  a_x509_cert_payload "CA" (fun c -> B(Ca,c)) str

let a_cert_payload str =
  let open Openvpn.Config in
  a_x509_cert_payload "cert" (fun c -> B(Tls_cert,c)) str

let a_key_payload str =
  let open Openvpn.Config in
  match X509.Private_key.decode_pem (Cstruct.of_string str) with
  | Ok key -> Ok (B (Tls_key, key))
  | Error (`Msg msg) -> Error ("no key found in x509 tls-key: " ^ msg)



let string_of_file filename =
    let ch = open_in ( ("sample-configuration-files/" ^ filename) ) in
    let s = really_input_string ch (in_channel_length ch) in
    close_in ch;
    s

let pmsg =
  Alcotest.testable (fun ppf (`Msg s) -> Fmt.pf ppf "Error @[<v>(%s)@]" s)
    (fun (`Msg a) (`Msg b) -> String.equal a b)

let conf_map = Alcotest.testable
    Openvpn.Config.pp Openvpn.Config.(equal eq)

let parse_noextern_client conf =
  Openvpn.Config.parse_client ~string_of_file:(fun path ->
      Rresult.R.error_msgf
        "this test suite does not read external files, \
         but a config asked for: %S" path) conf

let parse_noextern_server conf =
  Openvpn.Config.parse_server ~string_of_file:(fun path ->
      Rresult.R.error_msgf
        "this test suite does not read external files, \
         but a config asked for: %S" path) conf


let minimal_config =
  let open Openvpn.Config in
  empty
  (* from {!Openvpn.Config.Defaults.client_config} *)
  |> add Ping_interval `Not_configured
  |> add Ping_timeout (`Restart 120)
  |> add Renegotiate_seconds 3600
  |> add Bind (Some (None, None)) (* TODO default to 1194 for servers? *)
  |> add Handshake_window 60
  |> add Transition_window 3600
  |> add Tls_timeout 2
  |> add Resolv_retry `Infinite
  |> add Auth_retry `None
  |> add Connect_timeout 120
  |> add Connect_retry_max `Unlimited
  |> add Proto (None, `Udp)
  (* Minimal contents of actual config file: *)
  |> add Cipher "AES-256-CBC"
  |> add Tls_mode `Client
  |> add Auth_user_pass ("testuser","testpass")
  |> add Remote ([`Ip (Ipaddr.of_string_exn "10.0.0.1"), 1194, `Udp])

let ok_minimal_client () =
  (* verify that we can parse a minimal good config. *)
  let basic =
    {|tls-client
    cipher AES-256-CBC
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>
remote 10.0.0.1|} in
  Alcotest.(check (result conf_map pmsg)) "basic conf works"
    (Ok minimal_config)
    (parse_noextern_client basic)

let minimal_server_config =
  let open Openvpn.Config in
    let add_ok_b (b:(b,'a) result) t =
        Rresult.R.get_ok b |> function B (k,v) -> add k v t
    in
  empty
  |> add Dev (`Tun ,(Some "tunnel"))
  |> add Ping_interval `Not_configured
  |> add Cipher "AES-256-CBC"
  |> add Ping_timeout (`Restart 120)
  |> add Renegotiate_seconds 3600
  |> add Bind (Some (Some 1195, None))
  |> add Handshake_window 60
  |> add Transition_window 3600
  |> add Tls_timeout 2
  |> add Resolv_retry `Infinite
  |> add Auth_retry `None
  |> add Connect_timeout 120
  |> add Connect_retry_max `Unlimited
  |> add Proto (Some `Ipv4, `Tcp (Some `Server))
  |> add Tls_mode `Server
  |> add Server ((Ipaddr.V4.of_string_exn "10.89.0.0"), Ipaddr.V4.Prefix.of_string_exn "10.89.0.0/24")
  |> add_ok_b (a_cert_payload (string_of_file "server.public.certificate" ))
  |> add_ok_b (a_key_payload (string_of_file "server.secret.key" ))
  (*    | Tls_version_min : ([`V1_3 | `V1_2 | `V1_1 ] * bool) k *)
  (*  |> add Tls_version_min ( [`V1_2]* true) *)


let ok_minimal_server () =
  (* verify that we can parse a minimal good server config. *)
  let basic = string_of_file "minimal-server.cfg" in
  Alcotest.(check (result conf_map pmsg)) "basic server conf works"
    (Ok minimal_server_config)
    (parse_noextern_server basic)


let test_dev_type () =
  let tun0 =
    let open Openvpn.Config in
    minimal_config
    |> add Dev (`Tun, Some "tun0") in

  let implicit_dev_type_tun =
    Fmt.strf {|%a
dev tun0
|} Openvpn.Config.pp minimal_config |> parse_noextern_client in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev, implicit dev-type"
    (Ok tun0) implicit_dev_type_tun ;

  let explicit_dynamic_tun =
    (* here [dev-type] is implied, and the client should pick its own number
       for the tun device: *)
    Fmt.strf {|%a
dev tun
|} Openvpn.Config.pp minimal_config |> parse_noextern_client in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev tun specifying dynamic allocation"
    (Ok (minimal_config |> Openvpn.Config.add Dev (`Tun, None)))
    explicit_dynamic_tun ;

  let explicit_tun =
    (* this is interesting because it results in multiple
       dev-type stanzas since [dev tun0] implie [dev-type tun] *)
    Fmt.strf {|%a
dev tun0
dev-type tun
|} Openvpn.Config.pp minimal_config |> parse_noextern_client in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev and dev-type"
    (Ok tun0) explicit_tun ;

  let custom_name_tap =
    (* here we specify a custom name, which necessitates a [dev-type] *)
    Fmt.strf {|%a
dev-type tap
dev myvlan
|} Openvpn.Config.pp minimal_config |> parse_noextern_client in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev, implicit dev-type"
    (Ok (minimal_config |> Openvpn.Config.add Dev (`Tap, Some "myvlan")))
    custom_name_tap

let auth_user_pass_trailing_whitespace () =
  (* Seems to me that the OpenVPN upstream accepts this and we don't.
     It should also be tested if the upstream version strips prefixed/trailing
     whitespace from the user/pass/end-block lines. TODO.
  *)
  let common payload =
    "client\n"
    ^ "remote 127.0.0.1\n"
    ^ "auth-user-pass [inline]\n"
    ^ "<auth-user-pass>\n"
    ^ payload
    ^ "\n</auth-user-pass>"
    |> parse_noextern_client
  in
  let valid = "testuser\ntestpass" in
  let expected = common valid in
  Alcotest.(check (result conf_map pmsg))
    "accept Windows-style newlines after user/pass values"
    expected (common "testuser\r\ntestpass\r" ) ;

  Alcotest.(check (result conf_map pmsg))
    "reject empty username"
    (Error (`Msg ": auth-user-pass (byte 0): username is \
                  empty, expected on first line!"))
    (common "\r\ntestpass\n" ) ;

  Alcotest.(check (result conf_map pmsg))
    "reject empty password"
    (Error (`Msg ": auth-user-pass (byte 9): password is \
                  empty, expected on second line!"))
    (common "testuser\n" ) ;

  Alcotest.(check (result conf_map pmsg))
    "reject empty Windows-style password"
    (Error (`Msg ": auth-user-pass (byte 10): password is \
                  empty, expected on second line!"))
    (common "testuser\r\n\r" ) ;

    Alcotest.(check (result conf_map pmsg))
    "Accept password with special characters mapped to underscore"
    (common "testuser\nfoo_bar\n")
    (common "testuser\r\nfoo\x99bar\r\n" ) ;

  Alcotest.(check (result conf_map pmsg))
    "accept trailing whitespace in <auth-user-pass> blocks"
    expected (common (valid ^ "\n"))


let rport_precedence () =
  (* NOTE: at the moment this is expected to fail because we do not implement
     the rport directive correctly. TODO *)
  (* see https://github.com/roburio/openvpn/pull/12#issuecomment-581449319 *)
  let sample =
    {|
    tls-client
    cipher AES-256-CBC
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>

    remote 10.0.42.5
    remote 10.0.42.3 1194
    rport 1234
    remote 10.0.42.4
|} in
  let open Openvpn.Config in
  let sample = parse_client
      ~string_of_file:(fun _ -> Rresult.R.error_msg "oops")
      sample
  in
  let expected =
    {|
    tls-client
    cipher AES-256-CBC
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>

    remote 10.0.42.5 1234
    remote 10.0.42.3 1194
    rport 1234
    remote 10.0.42.4 1234
|}  |> parse_noextern_client
    |> function
    | Ok conf -> conf
    | Error `Msg msg ->
      raise (Invalid_argument ("Can't parse embedded config" ^ msg))
  in
  Alcotest.(check (result conf_map pmsg))
    "rport doesn't override explicits that coincide with the default"
    (Ok expected)
    (sample) ;
  let _ip1 = Ipaddr.of_string_exn "10.0.42.3" in
  let _ip2 = Ipaddr.of_string_exn "10.0.42.4" in
  let _ip3 = Ipaddr.of_string_exn "10.0.42.5" in
  () (* TODO check that the ports and remotes also match the written *)

let whitespace_after_tls_auth () =
  let expected = Openvpn.Config.add Tls_auth
      (None,
       Cstruct.create 64, Cstruct.create 64,
       Cstruct.create 64, Cstruct.create 64) minimal_config in
  let with_newlines =
    Fmt.strf {|%a
tls-auth [inline]
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
-----END OpenVPN Static key V1-----


</tls-auth>
|} Openvpn.Config.pp minimal_config
  in
  Alcotest.(check (result conf_map pmsg))
    "Allow whitespace after ----END of tls-auth"
    (Ok expected)
    (parse_noextern_client with_newlines)

let string_of_file filename =
  try
    let fh = open_in filename in
    let content = really_input_string fh (in_channel_length fh) in
    close_in_noerr fh ;
    content
  with _ -> Alcotest.failf "Error reading file %S" filename

let config_dir = "sample-configuration-files/"

let parse_client_configuration name () =
  Unix.chdir config_dir;
  Fun.protect ~finally:(fun () -> Unix.chdir "..")
    (fun () ->
       let data = string_of_file name in
       match
         Openvpn.Config.parse_client
           ~string_of_file:(fun n -> Ok (string_of_file n))
           data
       with
       | Ok _ -> ()
       | Error (`Msg err) -> Alcotest.failf "Error parsing %S: %s" name err)

let crowbar_fuzz_config () =
  Crowbar.add_test ~name:"Fuzzing doesn't crash Config.parse_client"
    [Crowbar.bytes] (fun s ->
        try Crowbar.check (ignore @@ parse_noextern_client s ; true)
        with _ -> Crowbar.bad_test ()
      )

let tests = [
  "minimal client config", `Quick, ok_minimal_client ;
  "minimal server config", `Quick, ok_minimal_server ;
  "test [dev] and [dev-type]", `Quick, test_dev_type ;
  "auth-user-pass trailing whitespace", `Quick,
  auth_user_pass_trailing_whitespace ;
  "rport precedence", `Quick, rport_precedence ;
  "trailing whitespace after <tls-auth>", `Quick,
  whitespace_after_tls_auth ;
  "parsing sample client.conf", `Quick,
  parse_client_configuration "client.conf" ;
  "parsing sample tls-home.conf", `Quick,
  parse_client_configuration "tls-home.conf" ;
  "parsing sample IPredator-CLI-Password.conf", `Quick,
  parse_client_configuration "IPredator-CLI-Password.conf" ;
  "crowbar fuzzing", `Slow, crowbar_fuzz_config ;
]
