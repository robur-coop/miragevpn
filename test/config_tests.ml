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
        if String.starts_with ~prefix:"-----END" hd then content acc false tl
        else content (hd :: acc) true tl
    | hd :: tl ->
        if String.starts_with ~prefix:"-----BEGIN" hd then content acc true tl
        else content acc false tl
  in
  let data = content [] false (String.split_on_char '\n' str) in
  let cs = Cstruct.of_hex (String.concat "" data) in
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
  |> add Auth `SHA1
  (* Minimal contents of actual config file: *)
  |> add Cipher `AES_256_CBC
  |> add Data_ciphers [ `AES_128_GCM; `AES_256_GCM; `CHACHA20_POLY1305 ]
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

  (* issue 43 *)
  let tun_is_tunnel =
    (* here [dev-type] is implied *)
    Fmt.str {|%a
dev tunnel
|} Miragevpn.Config.pp minimal_config
    |> parse_noextern_client
  in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev tunnel implicitly specifying tun"
    (Ok (minimal_config |> Miragevpn.Config.add Dev (`Tun, Some "tunnel")))
    tun_is_tunnel;

  (* issue 85 *)
  let tun_is_tunmir =
    (* here [dev-type] is implied *)
    Fmt.str {|%a
dev tunmir
|} Miragevpn.Config.pp minimal_config
    |> parse_noextern_client
  in
  Alcotest.(check (result conf_map pmsg))
    "explicit dev tunmir implicitly specifying tun"
    (Ok (minimal_config |> Miragevpn.Config.add Dev (`Tun, Some "tunmir")))
    tun_is_tunmir;

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

let cert_key_mismatch () =
  let sample =
    "tls-client\n\
    \    cipher AES-256-CBC\n\
    \    remote 10.0.42.3\n\
    \    key server.key\n\
    \    cert client.crt"
  in
  let string_of_file n = Ok (string_of_file n) in
  match Miragevpn.Config.parse_client ~string_of_file sample with
  | Ok conf ->
      Alcotest.failf "Expected error, but got Ok %a" Miragevpn.Config.pp conf
  | Error (`Msg "not a valid client config: key and cert do not match") -> ()
  | Error (`Msg e) ->
      Alcotest.failf "Got error %S, expected \"key and cert do not match\"" e

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
  | Ok conf ->
      Option.iter
        (fun cfg ->
          Alcotest.check conf_map
            ("parsed configuration " ^ file ^ " matches provided one")
            cfg conf)
        config

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
  |> add Tls_auth tls_auth |> add Cipher `AES_256_CBC |> add Verb 3

let static_client_conf, inline_secret_direction =
  let k_a, k_b, k_c, k_d =
    a_inline_payload
      {|
-----BEGIN OpenVPN Static key V1-----
87055d27a5536ac72e129916f4287adb
fce68b7ef6d929539ea170ed0ddf6822
899f5dbe6aa5df17673c10d63bfe5221
a25824527c60187666406d92c18dfc3a
ec597ed09c5aaacc2256c2303e71e17e
ff995ce7760877abee1d400ea768ace6
3dcc7d0ef10f1f6d4df4822a78ebbf87
99e1ddcf2e206872235eb7a92fddd560
99654cb6d0d19dc099fdfe318382c5b8
f508feaf3818d8bb35d0afea0e609681
8d7eaf4dc8ee072188c414405d6a0ec7
079d4faaf8520e77eee535e4cc0c7785
5f70cc929d9b5fcbab6e939c088962e4
7fe05b2e4367c15ddf8f1824b7d772a6
668345bc7b2f847d03080abb59ff37f2
1f7c6528d77584af997c0779a1c7e36f
-----END OpenVPN Static key V1-----|}
  in
  let open Miragevpn.Config in
  let cfg =
    minimal_config |> remove Auth_user_pass |> remove Tls_mode
    |> add Dev (`Tun, None)
    |> add Proto (None, `Udp)
    |> add Remote [ (`Ip (Ipaddr.of_string_exn "1.2.3.4"), 1194, `Udp) ]
    |> add Verb 3
    |> add Ifconfig
         (Ipaddr.of_string_exn "10.1.0.2", Ipaddr.of_string_exn "10.1.0.1")
    |> add Secret (None, k_a, k_b, k_c, k_d)
  in
  (cfg, cfg |> add Secret (Some `Outgoing, k_a, k_b, k_c, k_d))

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
  |> add Cipher `AES_256_CBC |> add Verb 3

let tls_home_conf_with_cipher =
  let open Miragevpn.Config in
  tls_home_conf
  |> add Tls_cipher [ `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ]
  |> add Tls_ciphersuite [ `CHACHA20_POLY1305_SHA256 ]

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
  |> add Ca [ ca ] |> add Tls_auth tls_auth
  |> add Remote_cert_tls `Server
  |> add Ping_interval (`Seconds 10)
  |> add Ping_timeout (`Restart 30)
  |> add Cipher `AES_256_CBC |> add Persist_key () |> add Comp_lzo ()
  |> add Tun_mtu 1500 |> add Mssfix 1200 |> add Passtos () |> add Verb 3
  |> add Replay_window (512, 60)
  |> add Mute_replay_warnings ()
  |> add Ifconfig_nowarn ()
  |> add Tls_version_min (`TLS_1_2, false)

let parse_multiple_cas () =
  let file = "multi-ca-client.conf" in
  let data = string_of_file file in
  match
    Miragevpn.Config.parse_client data ~string_of_file:(fun s ->
        Ok (string_of_file s))
  with
  | Error (`Msg e) -> Alcotest.failf "Error parsing %S: %s" file e
  | Ok conf ->
      let cas = Miragevpn.Config.(get Ca) conf in
      Alcotest.(check int) "Exactly two CA certificates" 2 (List.length cas)

let parse_server_configuration ?config file () =
  let data = string_of_file file in
  let string_of_file n = Ok (string_of_file n) in
  match Miragevpn.Config.parse_server ~string_of_file data with
  | Error (`Msg err) -> Alcotest.failf "Error parsing %S: %s" file err
  | Ok conf ->
      Option.iter
        (fun cfg ->
          Alcotest.check conf_map
            ("parsed configuration " ^ file ^ " matches provided one")
            cfg conf)
        config

let client_tls_crypt_v2_conf =
  let open Miragevpn.Config in
  let tls_crypt_v2_client =
    (* these values were manually extracted and are probably not worth much *)
    let a =
      "\x96\xc1\x13\xdc\x5d\x93\xec\xc7\x3f\x80\x96\x00\x0d\xb0\x73\xf4\x2e\xf6\xe3\x6d\xb9\xa1\xbb\x5d\x67\x70\x95\xe2\x90\xfa\x32\x83\x5f\x25\x6f\x62\x95\x0b\xe7\x2b\x3d\x57\x3e\xe6\x6f\x72\xfe\x3e\x7a\xfd\x26\x79\xbf\x46\x26\x1f\xe6\x53\xc2\x5a\xd3\x1b\xf2\xd9"
    and b =
      "\x1a\x74\x8e\x1d\xe1\x99\xe4\x09\x90\x25\xcd\x3f\xc1\x6a\xe8\x62\x03\x91\x6d\xa7\x36\xc3\xe0\x5c\xf4\x38\x77\x4c\xbf\xb2\x60\xdd\x31\x26\x0b\x20\x6d\xec\xcf\x3f\xed\xd9\xc3\x91\xf7\xf5\x48\x46\xee\xda\x52\xfa\xd7\xda\xc3\xc4\x7c\x5d\x7e\xe8\xa4\x9d\xed\x37"
    and c =
      "\x52\x48\x59\x72\xe2\xcb\x57\xef\xf8\xea\x43\x64\xe9\x97\x6a\xd9\x10\x9f\x17\xb1\xc8\xc2\xc4\x0d\xf8\xff\x18\xe1\x9c\x61\xf5\xee\x29\x1f\x18\x27\x5f\x5c\xac\xcc\x3c\x00\xec\xfc\x22\x0f\xb1\xa6\x03\x29\x33\x44\x22\xec\x38\x38\x75\x08\x3a\x79\xa6\x28\xda\x03"
    and d =
      "\x06\x88\x66\x60\xb6\x89\x2c\x7e\xa7\x9f\xc7\x60\x0e\x38\xf9\x37\xfb\x4a\x9a\xd6\x6d\x2e\x30\xd4\x1e\xe6\xd6\x53\xfa\xbc\xea\xd7\xa9\x45\x31\x8e\xa2\x69\x7c\xba\x1f\x1d\xe7\x56\x68\x58\x23\x37\xd2\x44\xc6\xb0\xb6\x7f\x75\x60\x96\x33\x5c\xae\x68\x28\xe3\x59"
    and wkc =
      "\x3f\xd3\x14\x26\x8b\x69\xd6\x8f\xfe\xd9\x5f\xf4\x03\xc0\x0c\xc4\x07\x29\x0a\x0f\x29\xfe\x77\x92\xa5\xa0\x7a\xaa\xe1\x30\x02\xaf\x0d\x6e\x32\x58\x1f\xa9\x38\x84\x84\x87\x65\xf7\xe2\xfc\x9f\x5c\xe0\x30\x2a\xb5\xa5\xd0\x04\x24\x80\x66\x8c\x8b\xf3\xda\xce\x5a\x74\x37\x2a\xcd\x42\xec\xf2\x44\x4b\x32\xf0\x52\x72\x25\xda\x37\xc7\xd9\xf5\x2b\xd0\xe2\x5e\xa1\xf9\x78\xb9\xc4\x0a\x06\xf2\xa4\xa9\x39\xc1\x1c\x40\x4c\x7a\x10\xb6\x45\x9f\x90\x35\xd1\x1c\x2e\xf7\x8d\x12\x6f\x49\x17\x2d\x2b\x1a\x09\x46\xec\x35\xe1\x96\x22\x6a\x5d\x06\x33\x89\x7b\xfe\xae\xbb\x85\xef\xd3\xa1\xc2\x4b\xbb\xb0\xfb\x28\x4e\x0f\xc6\x86\x7f\x95\x6e\x54\x9e\x52\x27\x21\xa2\x65\x73\x89\x29\x00\x97\x98\x5e\xdf\x2e\x5a\x8c\x6c\xe5\xa8\x62\x20\x9a\x4f\x79\xab\x34\x0d\x04\xce\x69\x5f\x58\x20\x0a\x47\x29\xcf\x56\xab\x91\xee\x54\x60\xc0\xe7\x44\xea\x15\xcc\x2d\xe1\x91\x15\x73\xb1\xab\x43\xc9\x13\x8b\xd3\x9b\xd4\x49\xbb\x8b\xcb\xbe\x28\xc1\x9e\x0e\xec\x65\x7b\xbb\x19\xe4\x72\x53\xb0\xa2\xf5\x12\xc2\xaa\x0d\xe3\x09\x4f\xe7\xc6\x85\x73\x58\xef\x16\x15\x89\x98\xe9\xa0\xcb\xeb\x93\xfd\x6e\x7b\x67\xbd\x79\xb8\x80\x8b\x2d\x1f\x85\xa9\x80\x98\x6e\xc8\x37\xf7\xed\x09\x40\x93\x25\xed\xfc\xce\x2a\x87\x89\x23\x01\xe8\xb3\x54\x14\x01\x2b"
    in
    ( ( Cstruct.of_string a,
        Cstruct.of_string b,
        Cstruct.of_string c,
        Cstruct.of_string d ),
      Cstruct.of_string wkc,
      false )
  in
  client_conf |> remove Tls_auth |> add Tls_crypt_v2_client tls_crypt_v2_client

let server_tls_crypt_v2 () =
  let a =
    "\xe1\x30\xb6\x5c\x7a\xde\xbe\xdd\x7d\xed\x3b\xc1\xe6\xb1\x27\x06\xd8\x4e\xdb\x87\x88\xaf\xaa\x5d\xc7\x78\x5b\xba\xf3\xcf\xb8\xbc\x04\x00\x96\xb8\x5b\x25\xfb\x5b\x8e\xf3\xf9\xf4\x35\xa5\xc1\x98\x31\xfe\xa9\x9e\xfa\x58\xf6\xf4\xd5\x69\x15\x52\x1b\x92\xaa\xc7"
  and b =
    "\x63\xbf\x48\x32\xc2\x7f\x78\xcb\x88\xe0\xad\x2e\xa5\xa6\xac\xae\x28\xac\x0d\xa1\xde\x3c\xb4\x95\xa6\xf0\x01\xe3\xa1\xe1\x0c\x6a\x82\x99\xad\xd1\x3a\xe7\xa4\x5b\x41\x91\x6c\xea\xf2\x37\x7f\x7c\x46\x98\xab\x9a\xc5\x56\xea\x98\xe8\xff\x2d\xed\x4b\x59\x27\xf7"
  in
  let data = string_of_file "tls-crypt-v2-server.conf" in
  let string_of_file n = Ok (string_of_file n) in
  match Miragevpn.Config.parse ~string_of_file data with
  | Error (`Msg e) ->
      Alcotest.failf "Error parsing tls-crypt-v2-server.conf: %s" e
  | Ok conf ->
      let (a', b'), force_cookie =
        Miragevpn.Config.(get Tls_crypt_v2_server) conf
      in
      Alcotest.(check string)
        "first part of server key" a (Cstruct.to_string a');
      Alcotest.(check string)
        "second part of server key" b (Cstruct.to_string b');
      Alcotest.(check bool) "force-cookie" true force_cookie

let tests =
  [
    ("minimal client config", `Quick, ok_minimal_client);
    ("test [dev] and [dev-type]", `Quick, test_dev_type);
    ( "auth-user-pass trailing whitespace",
      `Quick,
      auth_user_pass_trailing_whitespace );
    ("rport precedence", `Quick, rport_precedence);
    ("cert key mismatch", `Quick, cert_key_mismatch);
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
    ( "parsing configuration 'static-home'",
      `Quick,
      parse_client_configuration ~config:static_client_conf "static-home.conf"
    );
    ( "parsing configuration 'static-home-inline-secret'",
      `Quick,
      parse_client_configuration ~config:static_client_conf
        "static-home-inline-secret.conf" );
    ( "parsing configuration 'static-home-inline-secret-no-secret-inline'",
      `Quick,
      parse_client_configuration ~config:static_client_conf
        "static-home-inline-secret-no-secret-inline.conf" );
    ( "parsing configuration 'inline-secret-direction'",
      `Quick,
      parse_client_configuration ~config:inline_secret_direction
        "inline-secret-direction.conf" );
    ( "parsing configuration 'inline-secret-direction-reverse'",
      `Quick,
      parse_client_configuration ~config:inline_secret_direction
        "inline-secret-direction-reverse.conf" );
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
    ("parsing configuration with multiple CAs", `Quick, parse_multiple_cas);
    ( "parsing configuration 'tls-crypt-v2-client.conf'",
      `Quick,
      parse_client_configuration ~config:client_tls_crypt_v2_conf
        "tls-crypt-v2-client.conf" );
    ("parsing server tls-crypt-v2 keys", `Quick, server_tls_crypt_v2);
    ( "parsing configuration 'wild-client-no-auth'",
      `Quick,
      parse_client_configuration "wild-client-no-auth.conf" );
    ( "parsing configuration 'wild-client'",
      `Quick,
      parse_client_configuration "wild-client.conf" );
    ( "parsing configuration 'windows-riseup-client'",
      `Quick,
      parse_client_configuration "windows-riseup-client.conf" );
    ( "parsing 'tls-home-with-cipher'",
      `Quick,
      parse_client_configuration ~config:tls_home_conf_with_cipher
        "tls-home-with-cipher.conf" );
    ( "parsing 'minimal-server'",
      `Quick,
      parse_server_configuration "minimal-server.conf" );
    ("parsing 'server'", `Quick, parse_server_configuration "server.conf");
    ( "parsing 'server-tcp'",
      `Quick,
      parse_server_configuration "server-tcp.conf" );
    ( "parsing 'server-tcp-certauth-passauth'",
      `Quick,
      parse_server_configuration "server-tcp-certauth-passauth.conf" );
    (* ( "parsing 'wild-server'",
       `Quick,
       parse_server_configuration
         "wild-server.conf" ); not there yet, needs: dev-node writepid ping-timer-rem client-config-dir *)
  ]

let tests = [ ("Config tests", tests) ]

let () =
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter ();
  Logs.(set_level @@ Some Debug);
  Alcotest.run "MirageVPN tests" tests
