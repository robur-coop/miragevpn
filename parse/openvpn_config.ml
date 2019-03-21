open Angstrom

let pp_line ppf x =
  let v = Fmt.pf in
  (match x with
      `Blank -> v ppf "#"
   | `Ca _ -> v ppf "ca"
   | `Cipher x -> v ppf "cipher %S" x
   | `Client -> v ppf "client"
   | `Comp_lzo -> v ppf "comp-lzo"
   | `Dev _name -> v ppf "dev _"
   | `Ifconfig_nowarn -> v ppf "ifconfig-nowarn"
   | `Auth_retry _ -> v ppf "auth-retry"
   | `Connect_retry _ -> v ppf "connect-retry"
   | `Auth_user_pass _ -> v ppf "auth-user-pass"
   | `Keepalive _ -> v ppf "keepalive _ _"
   | `Mssfix i -> v ppf "mssfix %d" i
   | `Passtos -> v ppf "passtos"
   | `Persist_key -> v ppf "persist-key"
   | `Pkcs12 _path -> v ppf "pkcs12 _"
   | `Remote_random -> v ppf "remote-random"
   | `Proto _ -> v ppf "proto"
   | `Proto_force _ -> v ppf "proto-force"
   | `Resolv_retry _ -> v ppf "resolv-retry"
   | `Socks_proxy _ -> v ppf "socks-proxy"
   | `Nobind -> v ppf "nobind"
   | `Bind -> v ppf "bind"
   | `Float -> v ppf "float"
   | `Tls_client -> v ppf "tls-client"
   | `Tls_auth _ -> v ppf "tls-auth _"
   | `TLS_min _ -> v ppf "tls-min _"
   | `Remote_cert_tls _ -> v ppf "remote-cert-tls _"
   | `Remote_cert_key_usage f -> v ppf "remote-cert-ku %0.4x" f
   | `Mute_replay_warnings -> v ppf "mute-replay-warnings"
   | `Tun_mtu mtu -> v ppf "tun-mtu %d" mtu
   | `Verb n -> v ppf "verb %d" n
    | `Inline (tag,content) -> v ppf "<%s>:%S" tag content
    | _ -> v ppf "x"
  )

let a_comment : unit t =
  (* TODO validate against openvpn behavior,
     - can a finished line like 'dev tun0' have a comment at the end?
     - can comments be prefixed by whitespace? *)
  ((char '#' <|> char ';') *>
   skip_many (skip @@ function '\n' -> false | _ -> true))

let a_whitespace_unit : unit t =
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let a_whitespace_or_comment : unit t =
    a_comment <|> a_whitespace_unit

let a_ign_whitespace = skip_many a_whitespace_or_comment
let a_ign_whitespace_no_comment = skip_many a_whitespace_unit

let a_whitespace = skip_many1 a_whitespace_or_comment

let a_number =
  take_while1 (function '0'..'9' -> true | _ -> false) >>= fun str ->
  match int_of_string str with
  | i when string_of_int i = str -> return i
  | _ -> fail (Fmt.strf "Invalid number: %S" str)
  | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_number_range min' max' =
  a_number >>= function | n when n <= max' && min' <= n -> return n
                        | n -> fail (Fmt.strf "Number out of range: %d" n)

let a_client = string "client" *> a_ign_whitespace *> return `Client

let a_dev =
  let a_device_name =
    choice [
      (string "tun" *> a_number_range 0 128 >>| fun x -> `Tun x) ;
      (string "tap" *> a_number_range 0 128 >>| fun x -> `Tap x) ;
      string "null" *> return `Null ;
    ]
  in
  string "dev" *> a_whitespace *> a_device_name

let a_proto =
  string "proto" *> a_whitespace *> choice [
    string "tcp" *> return `Tcp ;
    string "udp" *> return `Udp
  ] >>| fun prot -> `Proto prot

let a_proto_force =
  string "proto-force" *> a_whitespace *> choice [
    string "tcp" *> return `Tcp ;
    string "udp" *> return `Udp
  ] >>| fun prot -> `Proto_force prot


let a_resolv_retry =
  string "resolv-retry" *> a_whitespace *>
  choice [ string "infinite" *> return `Infinite
         ]

let a_filepath =
  choice [
    string "[inline]" *> return `Inline ;
    (take_while1 (function '\x00'..'\x1f' -> false
                         | _ -> true) >>| fun p -> `Path p) ;
  ]

let a_option_with_single_path name =
  string name *> a_whitespace *>
  a_filepath

let a_ca =
  a_option_with_single_path "ca"  >>| fun path -> `Ca path

let a_pkcs12 =
  a_option_with_single_path "pkcs12" >>| fun path -> `Pkcs12 path

let a_tls_auth =
  a_option_with_single_path "tls-auth"  >>| fun path -> `Tls_auth path

let a_auth_user_pass =
  a_option_with_single_path "auth-user-pass" >>| fun path ->
  `Auth_user_pass path

let a_auth_retry =
  string "auth-retry" *> a_whitespace *>
  choice [ string "nointeract" *> return `Nointeract ] >>| fun x ->
  `Auth_retry x

let a_socks_proxy =
  string "socks-proxy" *> a_whitespace *>
  take_till (function '\n'|'\t'|' ' -> false | _ -> true) >>= fun server ->
  ( (a_whitespace *> a_number_range 0 65535 >>= fun port ->
     ( (a_whitespace *> a_filepath >>| fun path -> (server, port, path))
       <|> return (server, port, `Path "stdin")
     )
    )
    <|> return (server, 1080, `Path "stdin")
  ) >>| fun x -> `Socks_proxy x

let a_flag =
  choice [
    string "bind" *> return `Bind ;
    string "nobind" *> return `Nobind ;
    string "float" *> return `Float ;
    string "remote-random" *> return `Remote_random ;
    string "tls-client" *> return `Tls_client ;
    string "persist-key" *> return `Persist_key ;
    string "comp-lzo" *> return `Comp_lzo ; (* TODO warn! *)
    string "passtos" *> return `Passtos ;
    string "mute-replay-warnings" *> return `Mute_replay_warnings ;
    string "ifconfig-nowarn" *> return `Ifconfig_nowarn ;
  ]

let a_remote_cert_tls =
  string "remote-cert-tls" *> a_whitespace *>
  choice [ string "server" *> return `Server
         ] >>| fun purpose -> `Remote_cert_tls purpose

let a_remote_cert_key_usage =
  string "remote-cert-ku" *> a_whitespace *>
  choice [ string "0x00a0" *> return 0x00a0 (* TODO parse hex stuff properly *)
         ] >>| fun purpose -> `Remote_cert_key_usage purpose

let a_tls_version_min =
  string "tls-version-min" *> a_whitespace *>
  choice [ string "1.3" *> return `v1_3 ;
           string "1.2" *> return `v1_2 ;
           string "1.1" *> return `v1_1 ;
         ] >>| fun v -> `TLS_min v

let a_entry_one_number name =
  string name *> a_whitespace *> a_number

let a_tun_mtu = a_entry_one_number "tun-mtu" >>| fun x -> `Tun_mtu x

let a_mssfix = a_entry_one_number "mssfix" >>| fun x -> `Mssfix x
(* TODO make a_mssfix use a_number_range *)

let a_entry_two_numbers name =
  a_entry_one_number name >>= fun x ->
  a_whitespace *> a_number >>| fun y -> x,y

let a_connect_retry =
  a_entry_two_numbers "connect-retry" >>| fun pair -> `Connect_retry pair

let a_keepalive =
  a_entry_two_numbers "keepalive" >>| fun pair -> `Keepalive pair

let a_verb =
  a_entry_one_number "verb" >>| fun x -> `Verb x

let a_cipher =
  string "cipher" *> a_whitespace *>
  take_while1 (function ' '|'\n'|'\t' -> false | _ -> true)
  >>| fun v -> `Cipher v

let a_inline =
  (* TODO strip trailing newlines inside block ?*)
  char '<' *> take_while1 (function 'a'..'z'|'-' ->true
                                            | _  ->false)
  <* char '>' <* char '\n' >>= fun tag ->
  take_till (function '<' -> true | _ -> false) >>= fun x ->
  return (`Inline (tag, x))
  <* char '<' <* char '/' <* string tag <* char '>'



(* TODO entries can sometimes be nested, like in <connection> blocks:
The following OpenVPN options may be used inside of  a  <connec‐
tion> block:

bind,  connect-retry,  connect-retry-max,  connect-timeout,  ex‐
plicit-exit-notify, float, fragment, http-proxy,  http-proxy-op‐
tion,  link-mtu,  local,  lport, mssfix, mtu-disc, nobind, port,
proto, remote, rport, socks-proxy, tun-mtu and tun-mtu-extra. *)

let a_config_entry : 'a t =
  a_ign_whitespace_no_comment *>
  Angstrom.choice [
    a_client ;
    (a_dev >>| fun name -> `Dev name) ;
    a_proto ;
    (a_resolv_retry >>| fun x -> `Resolv_retry x) ;
    a_tls_auth ;
    a_remote_cert_tls ;
    a_remote_cert_key_usage ;
    a_verb ;
    a_connect_retry ;
    a_auth_retry ;
    a_mssfix ;
    a_inline ;
    a_tls_version_min ;
    a_keepalive ;
    a_socks_proxy ;
    a_auth_user_pass ;
    a_tun_mtu ;
    a_cipher ;
    a_pkcs12 ;
    a_flag ;
    a_ca ;
    a_whitespace *> return `Blank ;
  ]


let into_lines config_str =
  let a_ign_ws = skip_many (skip @@ function '\n'|' ' | '\t' -> true
                                           | _ -> false) in
  config_str |> parse_string
  @@ fix (fun recurse ->
      (a_ign_ws *> a_config_entry <* a_ign_ws >>= fun entry ->
       commit *>
       ( ( a_ign_ws *> end_of_input *> return [entry])
         <|> ( List.cons entry <$> recurse)
       )
      )
      <|>
      ( (available >>| (min 100) >>= peek_string) >>= fun context ->
        pos >>= fun pos ->
        fail (Printf.sprintf "Error at byte offset %d: %S" pos context)
      )
    )
