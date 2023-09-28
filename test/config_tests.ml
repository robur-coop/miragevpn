let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Infix = struct
  let ( >>= ) = Result.bind
  let ( >>| ) x f = Result.map f x
end

let a_ca_payload str =
  let open Miragevpn.Config in
  match X509.Certificate.decode_pem_multiple (Cstruct.of_string str) with
  | Ok certs -> B (Ca, certs)
  | Error (`Msg msg) -> Alcotest.failf "ca: invalid certificate(s): %s" msg

let a_cert_payload str =
  let open Miragevpn.Config in
  match X509.Certificate.decode_pem (Cstruct.of_string str) with
  | Ok cert -> B (Tls_cert, cert)
  | Error (`Msg msg) -> Alcotest.failf "cert: invalid certificate: %s" msg

let a_key_payload str =
  let open Miragevpn.Config in
  match X509.Private_key.decode_pem (Cstruct.of_string str) with
  | Ok key -> B (Tls_key, key)
  | Error (`Msg msg) -> Alcotest.failf "no key found in x509 tls-key %s" msg

let a_inline_payload str =
  let rec content acc collect = function
    | [] -> List.rev acc
    | hd :: tl when collect ->
        if Astring.String.is_prefix ~affix:"-----END" hd then
          content acc false tl
        else content (hd :: acc) true tl
    | hd :: tl ->
        if Astring.String.is_prefix ~affix:"-----BEGIN" hd then
          content acc true tl
        else content acc false tl
  in
  let data = content [] false (Astring.String.cuts ~sep:"\n" str) in
  let cs = Cstruct.of_hex (Astring.String.concat ~sep:"" data) in
  if Cstruct.length cs = 256 then
    Cstruct.(sub cs 0 64, sub cs 64 64, sub cs 128 64, sub cs (128 + 64) 64)
  else
    Alcotest.failf "wrong size %d, need exactly 256 bytes" (Cstruct.length cs)

let string_of_file filename =
  let config_dir = "sample-configuration-files" in
  let file = Filename.concat config_dir filename in
  try
    let fh = open_in file in
    let content = really_input_string fh (in_channel_length fh) in
    close_in_noerr fh;
    content
  with _ -> Alcotest.failf "Error reading file %S" file

let pmsg =
  Alcotest.testable
    (fun ppf (`Msg s) -> Fmt.pf ppf "Error @[<v>(%s)@]" s)
    (fun (`Msg a) (`Msg b) -> String.equal a b)

let conf_map = Alcotest.testable Miragevpn.Config.pp Miragevpn.Config.(equal eq)

let parse_noextern_client conf =
  Miragevpn.Config.parse_client
    ~string_of_file:(fun path ->
      error_msgf
        "this test suite does not read external files, but a config asked for: \
         %S"
        path)
    conf

let add_b (Miragevpn.Config.B (k, v)) t = Miragevpn.Config.add k v t

let minimal_config =
  let open Miragevpn.Config in
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
  |> add Proto (None, `Udp)
  (* Minimal contents of actual config file: *)
  |> add Cipher "AES-256-CBC"
  |> add Tls_mode `Client
  |> add Auth_user_pass ("testuser", "testpass")
  |> add Remote [ (`Ip (Ipaddr.of_string_exn "10.0.0.1"), 1194, `Udp) ]

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
remote 10.0.0.1|}
  in
  Alcotest.(check (result conf_map pmsg))
    "basic conf works" (Ok minimal_config)
    (parse_noextern_client basic)

let test_dev_type () =
  let tun0 =
    let open Miragevpn.Config in
    minimal_config |> add Dev (`Tun, Some "tun0")
  in

  let implicit_dev_type_tun =
    Fmt.str {|%a
dev tun0
|} Miragevpn.Config.pp minimal_config
    |> parse_noextern_client
  in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev, implicit dev-type" (Ok tun0) implicit_dev_type_tun;

  let explicit_dynamic_tun =
    (* here [dev-type] is implied, and the client should pick its own number
       for the tun device: *)
    Fmt.str {|%a
dev tun
|} Miragevpn.Config.pp minimal_config
    |> parse_noextern_client
  in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev tun specifying dynamic allocation"
    (Ok (minimal_config |> Miragevpn.Config.add Dev (`Tun, None)))
    explicit_dynamic_tun;

  let explicit_tun_str =
    (* this is interesting because it results in multiple
       dev-type stanzas since [dev tun0] implie [dev-type tun] *)
    Fmt.str {|%a
dev tun0
dev-type tun
|} Miragevpn.Config.pp minimal_config
  in
  let explicit_tun = parse_noextern_client explicit_tun_str in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev and dev-type" (Ok tun0) explicit_tun;

  let custom_name_tap =
    (* here we specify a custom name, which necessitates a [dev-type] *)
    Fmt.str {|%a
dev-type tap
dev myvlan
|} Miragevpn.Config.pp minimal_config
    |> parse_noextern_client
  in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev, implicit dev-type"
    (Ok (minimal_config |> Miragevpn.Config.add Dev (`Tap, Some "myvlan")))
    custom_name_tap;

  let two_remotes_str =
    Fmt.str "%a" Miragevpn.Config.pp minimal_config
    ^ "\ndev tun0\ndev-type tun\nremote number1.org 11\nremote number2.org 22"
  in
  let two_remotes =
    minimal_config
    |> Miragevpn.Config.add Dev (`Tun, Some "tun0")
    |> Miragevpn.Config.add Remote
       @@ Miragevpn.Config.get Remote minimal_config
       @ [
           ( `Domain
               (Domain_name.(of_string_exn "number1.org" |> host_exn), `Any),
             11,
             `Udp );
           ( `Domain
               (Domain_name.(of_string_exn "number2.org" |> host_exn), `Any),
             22,
             `Udp );
         ]
  in
  Alcotest.(check (result conf_map pmsg))
    "ordering of remotes remains the same after dev-type (regression)"
    (Ok two_remotes)
    (two_remotes_str |> parse_noextern_client)

let auth_user_pass_trailing_whitespace () =
  (* Seems to me that the OpenVPN upstream accepts this and we don't.
     It should also be tested if the upstream version strips prefixed/trailing
     whitespace from the user/pass/end-block lines. TODO.
  *)
  let common payload =
    "client\n" ^ "remote 127.0.0.1\n" ^ "auth-user-pass [inline]\n"
    ^ "<auth-user-pass>\n" ^ payload ^ "\n</auth-user-pass>"
    |> parse_noextern_client
  in
  let valid = "testuser\ntestpass" in
  let expected = common valid in
  Alcotest.(check (result conf_map pmsg))
    "accept Windows-style newlines after user/pass values" expected
    (common "testuser\r\ntestpass\r");

  Alcotest.(check (result conf_map pmsg))
    "reject empty username"
    (Error
       (`Msg
         ": auth-user-pass (byte 0): username is empty, expected on first line!"))
    (common "\r\ntestpass\n");

  Alcotest.(check (result conf_map pmsg))
    "reject empty password"
    (Error
       (`Msg
         ": auth-user-pass (byte 9): password is empty, expected on second \
          line!"))
    (common "testuser\n");

  Alcotest.(check (result conf_map pmsg))
    "reject empty Windows-style password"
    (Error
       (`Msg
         ": auth-user-pass (byte 10): password is empty, expected on second \
          line!"))
    (common "testuser\r\n\r");

  Alcotest.(check (result conf_map pmsg))
    "Accept password with special characters mapped to underscore"
    (common "testuser\nfoo_bar\n")
    (common "testuser\r\nfoo\x99bar\r\n");

  Alcotest.(check (result conf_map pmsg))
    "accept trailing whitespace in <auth-user-pass> blocks" expected
    (common (valid ^ "\n"))

let rport_precedence () =
  (* NOTE: at the moment this is expected to fail because we do not implement
     the rport directive correctly. TODO *)
  (* see https://github.com/robur-coop/miragevpn/pull/12#issuecomment-581449319 *)
  let config =
    Miragevpn.Config.add Remote
      [
        (`Ip (Ipaddr.of_string_exn "10.0.42.5"), 1234, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.42.3"), 1194, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.42.4"), 1234, `Udp);
      ]
      minimal_config
  in
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
|}
  in
  let open Miragevpn.Config in
  let sample =
    parse_client ~string_of_file:(fun _ -> error_msgf "oops") sample
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
|}
    |> parse_noextern_client
    |> function
    | Ok conf -> conf
    | Error (`Msg msg) ->
        raise (Invalid_argument ("Can't parse embedded config" ^ msg))
  in
  let expected_remotes =
    [ "ip:10.0.42.5:1234"; "ip:10.0.42.3:1194"; "ip:10.0.42.4:1234" ]
  in
  Alcotest.(check (result conf_map pmsg))
    "rport doesn't override explicits that coincide with the default"
    (Ok expected) sample;
  Alcotest.(check (result conf_map pmsg))
    "rport doesn't override explicits that coincide with the default (config)"
    (Ok config) sample;
  Alcotest.(check (result conf_map pmsg))
    "rport doesn't override explicits that coincide with the default (expected)"
    (Ok config) (Ok expected);
  Alcotest.(check @@ result (list string) reject)
    "order of remotes stays correct" (Ok expected_remotes)
    (let open Infix in
     sample >>| fun sample ->
     get Remote sample
     |> List.map (function
          | `Ip ip, port, _ ->
              "ip:" ^ Ipaddr.to_string ip ^ ":" ^ string_of_int port
          | `Domain _, _, _ -> failwith ""));
  Alcotest.(check @@ result string reject)
    "serialized version stays correct"
    (Ok
       "remote 10.0.42.5 1234 udp4\n\
        remote 10.0.42.3 1194 udp4\n\
        remote 10.0.42.4 1234 udp4")
    (let open Infix in
     sample >>| fun sample ->
     Fmt.str "%a" pp (singleton Remote (get Remote sample)))

let whitespace_after_tls_auth () =
  let expected =
    Miragevpn.Config.add Tls_auth
      ( None,
        Cstruct.create 64,
        Cstruct.create 64,
        Cstruct.create 64,
        Cstruct.create 64 )
      minimal_config
  in
  let with_newlines =
    Fmt.str
      {|%a
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
|}
      Miragevpn.Config.pp minimal_config
  in
  Alcotest.(check (result conf_map pmsg))
    "Allow whitespace after ----END of tls-auth" (Ok expected)
    (parse_noextern_client with_newlines)

let remotes_in_order () =
  let basic =
    {|tls-client
    cipher AES-256-CBC
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>
remote 10.0.0.1
remote 10.0.0.2
remote 10.0.0.3
remote 10.0.0.4|}
  in
  let config =
    Miragevpn.Config.add Remote
      [
        (`Ip (Ipaddr.of_string_exn "10.0.0.1"), 1194, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.0.2"), 1194, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.0.3"), 1194, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.0.4"), 1194, `Udp);
      ]
      minimal_config
  in
  Alcotest.(check (result conf_map pmsg))
    "basic configuration with multiple remote works" (Ok config)
    (parse_noextern_client basic)

let remotes_in_order_with_port () =
  let basic =
    {|tls-client
    cipher AES-256-CBC
    auth-user-pass [inline]
    <auth-user-pass>
testuser
testpass
</auth-user-pass>
remote 10.0.0.1 1234
remote 10.0.0.2 1234
remote 10.0.0.3 1234
remote 10.0.0.4 1234|}
  in
  let config =
    Miragevpn.Config.add Remote
      [
        (`Ip (Ipaddr.of_string_exn "10.0.0.1"), 1234, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.0.2"), 1234, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.0.3"), 1234, `Udp);
        (`Ip (Ipaddr.of_string_exn "10.0.0.4"), 1234, `Udp);
      ]
      minimal_config
  in
  Alcotest.(check (result conf_map pmsg))
    "basic configuration with multiple remote works" (Ok config)
    (parse_noextern_client basic)

let parse_client_configuration ?config file () =
  let data = string_of_file file in
  let string_of_file n = Ok (string_of_file n) in
  match Miragevpn.Config.parse_client ~string_of_file data with
  | Error (`Msg err) -> Alcotest.failf "Error parsing %S: %s" file err
  | Ok conf -> (
      match config with
      | None -> ()
      | Some cfg ->
          Alcotest.check conf_map
            ("parsed configuration " ^ file ^ " matches provided one")
            cfg conf)

let minimal_ta_conf =
  let open Miragevpn.Config in
  let tls_auth =
    let a, b, c, d = a_inline_payload (string_of_file "ta.key") in
    (None, a, b, c, d)
  in
  minimal_config |> add Tls_auth tls_auth

let client_conf =
  let open Miragevpn.Config in
  let tls_auth =
    let a, b, c, d = a_inline_payload (string_of_file "ta.key") in
    (Some `Incoming, a, b, c, d)
  in
  minimal_config |> remove Auth_user_pass |> add Pull () |> add Tls_mode `Client
  |> add Dev (`Tun, None)
  |> add Proto (None, `Udp)
  |> add Remote
       [
         ( `Domain (Domain_name.(host_exn (of_string_exn "my-server-1")), `Any),
           1194,
           `Udp );
       ]
  |> add Resolv_retry `Infinite |> add Bind None |> add Persist_key ()
  |> add Persist_tun ()
  |> add_b (a_ca_payload (string_of_file "ca.crt"))
  |> add_b (a_cert_payload (string_of_file "client.crt"))
  |> add_b (a_key_payload (string_of_file "client.key"))
  |> add Remote_cert_tls `Server
  |> add Tls_auth tls_auth |> add Cipher "AES-256-CBC" |> add Verb 3

let tls_home_conf =
  let open Miragevpn.Config in
  minimal_config |> remove Auth_user_pass
  |> add Dev (`Tun, None)
  |> add Remote [ (`Ip (Ipaddr.of_string_exn "1.2.3.4"), 1194, `Udp) ]
  |> add Ifconfig
       (Ipaddr.of_string_exn "10.1.0.2", Ipaddr.of_string_exn "10.1.0.1")
  |> add_b (a_ca_payload (string_of_file "ca.crt"))
  |> add_b (a_cert_payload (string_of_file "client.crt"))
  |> add_b (a_key_payload (string_of_file "client.key"))
  |> add Cipher "AES-256-CBC" |> add Verb 3

let ipredator_conf =
  let ca =
    match
      X509.Certificate.decode_pem
      @@ Cstruct.of_string
           {|
-----BEGIN CERTIFICATE-----
MIIFJzCCBA+gAwIBAgIJAKee4ZMMpvhzMA0GCSqGSIb3DQEBBQUAMIG9MQswCQYD
VQQGEwJTRTESMBAGA1UECBMJQnJ5Z2dsYW5kMQ8wDQYDVQQHEwZPZWxkYWwxJDAi
BgNVBAoTG1JveWFsIFN3ZWRpc2ggQmVlciBTcXVhZHJvbjESMBAGA1UECxMJSW50
ZXJuZXR6MScwJQYDVQQDEx5Sb3lhbCBTd2VkaXNoIEJlZXIgU3F1YWRyb24gQ0Ex
JjAkBgkqhkiG9w0BCQEWF2hvc3RtYXN0ZXJAaXByZWRhdG9yLnNlMB4XDTEyMDgw
NDIxMTAyNVoXDTIyMDgwMjIxMTAyNVowgb0xCzAJBgNVBAYTAlNFMRIwEAYDVQQI
EwlCcnlnZ2xhbmQxDzANBgNVBAcTBk9lbGRhbDEkMCIGA1UEChMbUm95YWwgU3dl
ZGlzaCBCZWVyIFNxdWFkcm9uMRIwEAYDVQQLEwlJbnRlcm5ldHoxJzAlBgNVBAMT
HlJveWFsIFN3ZWRpc2ggQmVlciBTcXVhZHJvbiBDQTEmMCQGCSqGSIb3DQEJARYX
aG9zdG1hc3RlckBpcHJlZGF0b3Iuc2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCp5M22fZtwtIh6Mu9IwC3N2tEFqyNTEP1YyXasjf+7VNISqSpFy+tf
DsHAkiE9Wbv8KFM9bOoVK1JjdDsetxArm/RNsUWm/SNyVbmY+5ezX/n95S7gQdMi
bA74/ID2+KsCXUY+HNNUQqFpyK67S09A6r0ZwPNUDbLgGnmCZRMDBPCHCbiK6e68
d75v6f/0nY4AyAAAyqwAELIAn6sy4rzoPbalxcO33eW0fUG/ir41qqo8BQrWKyEd
Q9gy8tGEqbLQ+B30bhIvBh10YtWq6fgFZJzWP6K8bBJGRvioFOyQHCaVH98UjwOm
/AqMTg7LwNrpRJGcKLHzUf3gNSHQGHfzAgMBAAGjggEmMIIBIjAdBgNVHQ4EFgQU
pRqJxaYdvv3XGEECUqj7DJJ8ptswgfIGA1UdIwSB6jCB54AUpRqJxaYdvv3XGEEC
Uqj7DJJ8ptuhgcOkgcAwgb0xCzAJBgNVBAYTAlNFMRIwEAYDVQQIEwlCcnlnZ2xh
bmQxDzANBgNVBAcTBk9lbGRhbDEkMCIGA1UEChMbUm95YWwgU3dlZGlzaCBCZWVy
IFNxdWFkcm9uMRIwEAYDVQQLEwlJbnRlcm5ldHoxJzAlBgNVBAMTHlJveWFsIFN3
ZWRpc2ggQmVlciBTcXVhZHJvbiBDQTEmMCQGCSqGSIb3DQEJARYXaG9zdG1hc3Rl
ckBpcHJlZGF0b3Iuc2WCCQCnnuGTDKb4czAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBBQUAA4IBAQB8nxZJaTvMMoSG47jD2w31zt9o6nSx8XJKop/0rMMHKBe1QBUw
/n3clGwYxBW8mTnrXHhmJkwJzA0Vh525+dkF28E0I+DSigKUXEewIZtKjADYSxaG
M+4272enbJ86JeXUhN8oF9TT+LKgMBgtt9yX5o63Ek6QOKwovH5kemDOVJmwae9p
tXQEWfCPDFMc7VfSxS4BDBVinRWeMWZs+2AWeWu2CMsjcx7+B+kPbBCzfANanFDD
CZEQON4pEpfK2XErhOudKEJGCl7psH+9Ex//pqsUS43nVN/4sqydiwbi+wQuUI3P
BYtvqPnWdjIdf2ayAQQCWliAx9+P03vbef6y
-----END CERTIFICATE-----
|}
    with
    | Ok cert -> cert
    | Error (`Msg msg) -> Alcotest.failf "failed to parse IPredator CA %s" msg
  in
  let tls_auth =
    let a, b, c, d =
      a_inline_payload
        {|
-----BEGIN OpenVPN Static key V1-----
03f7b2056b9dc67aa79c59852cb6b35a
a3a15c0ca685ca76890bbb169e298837
2bdc904116f5b66d8f7b3ea6a5ff05cb
fc4f4889d702d394710e48164b28094f
a0e1c7888d471da39918d747ca4bbc2f
285f676763b5b8bee9bc08e4b5a69315
d2ff6b9f4b38e6e2e8bcd05c8ac33c5c
56c4c44dbca35041b67e2374788f8977
7ad4ab8e06cd59e7164200dfbadb942a
351a4171ab212c23bee1920120f81205
efabaa5e34619f13adbe58b6c83536d3
0d34e6466feabdd0e63b39ad9bb1116b
37fafb95759ab9a15572842f70e7cba9
69700972a01b21229eba487745c091dd
5cd6d77bdc7a54a756ffe440789fd39e
97aa9abe2749732b7262f82e4097bee3
-----END OpenVPN Static key V1-----|}
    in
    (None, a, b, c, d)
  in
  let host s = Domain_name.(host_exn (of_string_exn s)) in
  let open Miragevpn.Config in
  minimal_config |> add Pull ()
  |> add Dev (`Tun, Some "tun0")
  |> add Remote
       [
         (`Domain (host "pw.openvpn.ipredator.se", `Any), 1194, `Udp);
         (`Domain (host "pw.openvpn.ipredator.me", `Any), 1194, `Udp);
         (`Domain (host "pw.openvpn.ipredator.es", `Any), 1194, `Udp);
       ]
  |> add Bind None |> add Auth_retry `Nointeract
  |> add Auth_user_pass ("foo", "bar")
  |> add Ca [ca] |> add Tls_auth tls_auth
  |> add Remote_cert_tls `Server
  |> add Ping_interval (`Seconds 10)
  |> add Ping_timeout (`Restart 30)
  |> add Cipher "AES-256-CBC" |> add Persist_key () |> add Comp_lzo ()
  |> add Tun_mtu 1500 |> add Mssfix 1200 |> add Passtos () |> add Verb 3
  |> add Replay_window (512, 60)
  |> add Mute_replay_warnings ()
  |> add Ifconfig_nowarn ()
  |> add Tls_version_min (`V1_2, false)

let crowbar_fuzz_config () =
  Crowbar.add_test ~name:"Fuzzing doesn't crash Config.parse_client"
    [ Crowbar.bytes ] (fun s ->
      try
        Crowbar.check
          (ignore @@ parse_noextern_client s;
           true)
      with _ -> Crowbar.bad_test ())

let tests =
  [
    ("minimal client config", `Quick, ok_minimal_client);
    ("test [dev] and [dev-type]", `Quick, test_dev_type);
    ( "auth-user-pass trailing whitespace",
      `Quick,
      auth_user_pass_trailing_whitespace );
    ("rport precedence", `Quick, rport_precedence);
    ("trailing whitespace after <tls-auth>", `Quick, whitespace_after_tls_auth);
    ("remote entries are in order", `Quick, remotes_in_order);
    ("remote entries with port are in order", `Quick, remotes_in_order_with_port);
    ( "parsing configuration 'minimal-client'",
      `Quick,
      parse_client_configuration ~config:minimal_ta_conf "minimal-client.conf"
    );
    ( "parsing configuration 'client'",
      `Quick,
      parse_client_configuration ~config:client_conf "client.conf" );
    (* "parsing configuration 'static-home'", `Quick,
       parse_client_configuration "static-home.conf" ; -- secret static.key *)
    ( "parsing configuration 'tls-home'",
      `Quick,
      parse_client_configuration ~config:tls_home_conf "tls-home.conf" );
    ( "parsing configuration 'client-tcp-certauth-passauth'",
      `Quick,
      parse_client_configuration "client-tcp-certauth-passauth.conf" );
    ( "parsing configuration 'IPredator-CLI-Password'",
      `Quick,
      parse_client_configuration ~config:ipredator_conf
        "IPredator-CLI-Password.conf" );
    (* "parsing configuration 'wild-client'", `Quick,
       parse_client_configuration "wild-client.conf" ; -- verify-x509-name *)
    (* "parsing configuration 'windows-riseup-client'", `Quick,
       parse_client_configuration "windows-riseup-client.conf" ; -- tls-cipher *)
    ("crowbar fuzzing", `Slow, crowbar_fuzz_config);
  ]
