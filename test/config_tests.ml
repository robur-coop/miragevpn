let pmsg =
  Alcotest.testable (fun ppf (`Msg s) -> Fmt.pf ppf "Error @[<v>(%s)@]" s)
    (fun (`Msg a) (`Msg b) -> String.equal a b)

let conf_map = Alcotest.testable
    Openvpn.Config.pp Openvpn.Config.(equal eq)

let parse_noextern conf =
  Openvpn.Config.parse_client ~string_of_file:(fun path ->
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
  |> add Tls_mode `Client
  |> add Auth_user_pass ("testuser","testpass")
  |> add Remote [`Ip (Ipaddr.of_string_exn "10.0.0.1"), 1194, `Udp]


let ok_minimal_client () =
  (* verify that we can parse a minimal good config. *)
  let basic =
    {|tls-client
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>
remote 10.0.0.1|} in
  Alcotest.(check (result conf_map pmsg)) "basic conf works"
    (Ok minimal_config)
    (parse_noextern basic)

let test_dev_type () =
  let tun0 =
    let open Openvpn.Config in
    minimal_config
    |> add Dev (`Tun, Some "tun0") in

  let implicit_dev_type_tun =
    Fmt.strf {|%a
dev tun0
|} Openvpn.Config.pp minimal_config |> parse_noextern in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev, implicit dev-type"
    (Ok tun0) implicit_dev_type_tun ;

  let explicit_dynamic_tun =
    (* here [dev-type] is implied, and the client should pick its own number
       for the tun device: *)
    Fmt.strf {|%a
dev tun
|} Openvpn.Config.pp minimal_config |> parse_noextern in
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
|} Openvpn.Config.pp minimal_config |> parse_noextern in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev and dev-type"
    (Ok tun0) explicit_tun ;

  let custom_name_tap =
    (* here we specify a custom name, which necessitates a [dev-type] *)
    Fmt.strf {|%a
dev-type tap
dev myvlan
|} Openvpn.Config.pp minimal_config |> parse_noextern in
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
    |> parse_noextern
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
    "accept trailing whitespace in <auth-user-pass> blocks"
    expected (common (valid ^ "\n"))


let rport_precedence () =
  (* NOTE: at the moment this is expected to fail because we do not implement
     the rport directive correctly. TODO *)
  (* see https://github.com/roburio/openvpn/pull/12#issuecomment-581449319 *)
  let sample =
    {|
    tls-client
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
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>

    remote 10.0.42.5 1234
    remote 10.0.42.3 1194
    rport 1234
    remote 10.0.42.4 1234
|} |> parse_noextern |> Rresult.R.get_ok
  in
  Alcotest.(check (result conf_map pmsg))
    "rport doesn't override explicits that coincide with the default"
    (Ok expected)
    (sample) ;
  let _ip1 = Ipaddr.of_string_exn "10.0.42.3" in
  let _ip2 = Ipaddr.of_string_exn "10.0.42.4" in
  let _ip3 = Ipaddr.of_string_exn "10.0.42.5" in
  () (* TODO check that the ports and remotes also match the written *)

let crowbar_fuzz_config () =
  Crowbar.add_test ~name:"Fuzzing doesn't crash Config.parse_client"
    [Crowbar.bytes] (fun s ->
        try Crowbar.check (ignore @@ parse_noextern s ; true)
        with _ -> Crowbar.bad_test ()
      )

let tests = [
  "minimal client config", `Quick, ok_minimal_client ;
  "test [dev] and [dev-type]", `Quick, test_dev_type ;
  "auth-user-pass trailing whitespace", `Quick,
  auth_user_pass_trailing_whitespace ;
  "rport precedence", `Quick, rport_precedence ;
  "crowbar fuzzing", `Slow, crowbar_fuzz_config ;
]
