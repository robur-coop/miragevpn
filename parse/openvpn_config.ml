open Angstrom

type inline_or_path = [ `Inline | `Path of string ]

module Conf_map = struct
  (*type server
  type client
    type any*)
  type flag = unit

  type 'a k =
    | Auth_retry : [`Nointeract] k
    | Auth_user_pass : inline_or_path k
    | Bind     : bool k
    | Ca       : X509.t k
    | Cipher   : string k
    | Comp_lzo : flag k
    | Float    : flag k
    | Keepalive : (int * int) k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Pull     : flag k
    | Remote : ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list k
    | Remote_random : flag k
    | Replay_window : (int * int) k
    | Tls_client    : flag k
    | Tls_auth_payload : (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tun_mtu : int k
    | Verb : int k

  module K = struct
    type 'a t = 'a k
    let pp ppf (_v: _ t) _a = Fmt.pf ppf "hello"
    let compare : type a b. a t -> b t -> (a,b) Gmap.Order.t = fun a b ->
      match Hashtbl.(compare (hash a) (hash b) ) with
      | 0 -> Obj.magic Gmap.Order.Eq (* GADT equality :-/ *)
      | x when x < 0 -> Lt
      | _ -> Gt
  end

  include Gmap.Make(K)
end

type line = [
  | `Auth_retry of [ `Nointeract ]
  | `Auth_user_pass of inline_or_path
  | `Bind
  | `Blank
  | `Ca of inline_or_path
  | `Cipher of string
  | `Client
  | `Comp_lzo
  | `Connect_retry of int * int
  | `Dev of [ `Null | `Tap of int | `Tun of int ]
  | `Float
  | `Ifconfig_nowarn
  | `Inline of string * string
  | `Keepalive of int * int
  | `Mssfix of int
  | `Mute_replay_warnings
  | `Nobind (* negation of `Bind *)
  | `Passtos
  | `Persist_key
  | `Pkcs12 of [ `Inline | `Path of string ]
  | `Proto of [ `Tcp | `Udp ]
  | `Proto_force of [ `Tcp | `Udp ]
  | `Remote of [`IP of Ipaddr.t | `Domain of Domain_name.t] * int
  | `Remote_cert_key_usage of int
  | `Remote_cert_tls of [ `Server ]
  | `Remote_random
  | `Replay_window of int * int
  | `Resolv_retry of [ `Infinite ]
  | `Socks_proxy of string * int * [ `Inline | `Path of string ]
  | `TLS_min of [ `v1_1 | `v1_2 | `v1_3 ]
  | `Tls_auth of [ `Inline | `Path of string ]
  | `Tls_client
  | `Tun_mtu of int
  | `Verb of int
]

let pp_line ppf (x : line) =
  let v = Fmt.pf in
  (match x with
   | `Blank -> v ppf "#"
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
   | `Inline (tag, content) -> v ppf "<%s>:%S" tag content
   | `Replay_window (_size, _duration) -> v ppf "replay-window _"
   | `Remote (_name, _port) -> v ppf "remote _"
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

(* TODO: "dev tun" is also valid, according to the manpage:
   "tunX - X can be omitted for a dynamic device" *)
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

let a_tls_auth_payload =
  let abort s = fail ("Invalid TLS AUTH HMAC key: " ^ s) in
  (string "-----BEGIN OpenVPN Static key V1-----\n"
   <|> abort "Missing Static key V1 -----BEGIN mark") *>
  many_till ( take_while (function | 'a'..'f'|'A'..'F'|'0'..'9' -> true
                                   | _ -> false)
              <* (end_of_line <|> abort "Invalid hex character") >>= fun hex ->
      try return (Cstruct.of_hex hex) with
      | Invalid_argument msg -> abort msg)
    (string "-----END OpenVPN Static key V1-----\n" <|>abort "Missing END mark")
  <* (end_of_input <|> abort "Data after -----END mark")
  >>= (fun lst ->
      let sz = Cstruct.lenv lst in
      if 256 = sz then return lst else
        abort @@ "Wrong size ("^(string_of_int sz)^"); need exactly 256 bytes")
  >>| Cstruct.concat >>| fun cs ->
  Cstruct.(sub cs 0        64,
           sub cs 64       64,
           sub cs 128      64,
           sub cs (128+64) 64)

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

let a_hex =
  let is_hex = function '0'..'9' | 'a'..'f' | 'A'..'F' -> true | _ -> false in
  (string "0x" *> take_while1 is_hex) >>= fun str ->
  match int_of_string ("0x" ^ str) with
  | i -> return i
  | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_remote_cert_key_usage =
  string "remote-cert-ku" *> a_whitespace *> a_hex >>| fun purpose ->
  `Remote_cert_key_usage purpose

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
  take_while1 (function ' '| '\n' | '\t' -> false | _ -> true)
  >>| fun v -> `Cipher v

let a_replay_window =
  let replay_window a b = `Replay_window (a, b) in
  lift2 replay_window
    (string "replay-window" *> a_whitespace *> a_number)
    (option 15 (a_whitespace *> a_number))

let a_ipv4_dotted_quad =
  take_while1 (function '0'..'9' |'.' -> true | _ -> false) >>= fun ip ->
  match Ipaddr.V4.of_string ip with
    | Error `Msg x -> fail (Fmt.strf "Invalid IPv4: %s: %S" x ip)
    | Ok ip -> return ip

let a_ipv6_coloned_hex =
  take_while1 (function '0'..'9' | ':' | 'a'..'f' | 'A'..'F' -> true
                                 | _ -> false) >>= fun ip ->
  match Ipaddr.V6.of_string ip with
  | Error `Msg x -> fail (Fmt.strf "Invalid IPv6: %s: %S" x ip)
  | Ok ip -> return ip

let a_domain_name =
  take_till (function '\x00'..'\x1f' | ' ' | '"' | '\'' -> true | _ -> false)
  >>= fun str -> match Domain_name.of_string str with
  | Error `Msg x -> fail (Fmt.strf "Invalid domain name: %s: %S" x str)
  | Ok x -> return x

(* TODO finish "remote [port] [proto]" by adding proto (tcp/udp/tcp4/tcp6/udp4/udp6)
   what are the semantics if proto and remote proto is provided? *)
let a_remote =
  let remote a b = `Remote (a, b) in
  lift2 remote
    (string "remote" *> a_whitespace *>
     choice [
       (a_ipv4_dotted_quad >>| fun i -> `IP (Ipaddr.V4 i)) ;
       (a_ipv6_coloned_hex >>| fun i -> `IP (Ipaddr.V6 i)) ;
       (a_domain_name >>| fun dns -> `Domain dns)
     ]
    )
    (option 1194 (a_whitespace *> a_number))

let a_inline =
  (* TODO strip trailing newlines inside block ?*)
  char '<' *> take_while1 (function 'a'..'z' |'-' -> true
                                             | _  -> false)
  <* char '>' <* char '\n' >>= fun tag ->
  take_till (function '<' -> true | _ -> false) >>= fun x ->
  return (`Inline (tag, x))
  <* char '<' <* char '/' <* string tag <* char '>'

(* TODO entries can sometimes be nested, like in <connection> blocks:
The following OpenVPN options may be used inside of  a  <connection> block:

bind,  connect-retry,  connect-retry-max,  connect-timeout,
explicit-exit-notify, float, fragment, http-proxy,  http-proxy-option,
link-mtu, local, lport, mssfix, mtu-disc, nobind, port,
proto, remote, rport, socks-proxy, tun-mtu and tun-mtu-extra. *)

let a_config_entry : 'a t =
  a_ign_whitespace_no_comment *>
  Angstrom.choice [
    a_client ;
    (a_dev >>| fun name -> `Dev name) ;
    a_proto ;
    a_proto_force ;
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
    a_replay_window ;
    a_remote ;
    a_pkcs12 ;
    a_flag ;
    a_ca ;
    a_whitespace *> return `Blank ;
  ]


let parse config_str : (line list, 'x) result=
  let a_ign_ws = skip_many (skip @@ function '\n'| ' ' | '\t' -> true
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

let parse_gadt : line list -> (Conf_map.t, 'err) result =
  (Ok Conf_map.empty) |> List.fold_left
    (fun acc line -> Rresult.R.bind acc (fun (acc:Conf_map.t) ->
         let ret k v = Ok (Conf_map.add k v acc) in
         let ok_add k v = Ok (Conf_map.update k (function
             | None -> Some [v]
             | Some old -> Some (v::old)
           ) acc)
         in
         let unit k = ret k () in
         match line with
         | `Auth_retry kind     -> ret Auth_retry kind
         | `Auth_user_pass kind -> ret Auth_user_pass kind
         | `Bind   -> ret Bind true
         | `Nobind -> ret Bind false
         | `Cipher str -> ret Cipher str
         | `Client     -> (* alias for --tls-client --pull *)
           Rresult.(unit Tls_client >>| Conf_map.add Pull ())
         | `Comp_lzo   -> unit Comp_lzo
         | `Float      -> unit Float
         | `Keepalive low_high -> ret Keepalive low_high
         | `Mssfix int -> ret Mssfix int
         | `Mute_replay_warnings -> unit Mute_replay_warnings
         | `Passtos    -> unit Passtos
         | `Remote host_port -> ok_add Remote host_port
         | `Remote_random -> unit Remote_random
         | `Replay_window low_high -> ret Replay_window low_high
         | `Tls_client -> unit Tls_client
         | `Tun_mtu i  -> ret Tun_mtu i
         | `Verb    i  -> ret Verb i
         | `Inline ("tls-auth", x) ->
           Rresult.R.(Angstrom.parse_string a_tls_auth_payload x
                      >>= ret Tls_auth_payload)
         | `Inline ("connection", str) ->
           Rresult.R.(Angstrom.parse_string a_remote str
                      >>= fun (`Remote peer) -> ok_add Remote peer)
         | `Inline ("ca", str) ->
           begin match X509.Encoding.Pem.parse (Cstruct.of_string str) with
             | ("CERTIFICATE", x)::[] ->
               begin match X509.Encoding.parse x with
               | Some cert -> ret Ca cert
               | None -> Error "CA: invalid certificate"
               end
             | exception Invalid_argument _ -> Error "CA: Error parsing PEM container"
             | _ -> Error "CA: PEM does not consist of a single certificate"
           end
         | `Blank
         | _ -> Ok acc
       )
    )

let is_valid_client_config t =
  Conf_map.mem Remote t (* has a Remote *)
  && Conf_map.mem Tls_client t
