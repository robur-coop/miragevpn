open Angstrom

module A = Angstrom

type 'a inline_or_path = [ `Need_inline of 'a | `Path of string * 'a ]

module Conf_map = struct
  (*type server
  type client
    type any*)
  type flag = unit

  type 'a k =
    | Auth_retry : [`Nointeract] k
    | Auth_user_pass : (string * string) k
    | Bind     : bool k
    | Ca       : X509.t k
    | Cipher   : string k
    | Comp_lzo : flag k
    | Connect_retry : (int * int) k
    | Dev      : [`Null | `Tun of int | `Tap of int] k
    | Float    : flag k
    | Ifconfig_nowarn : flag k
    | Keepalive : (int * int) k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Persist_key : flag k
    | Pull     : flag k
    | Proto    : [`Tcp | `Udp] k
    | Remote : ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list k
    | Remote_cert_tls : [`Server | `Client] k
    | Remote_random : flag k
    | Replay_window : (int * int) k
    | Resolv_retry : [`Infinite | `Seconds of int] k
    | Tls_auth : (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tls_client    : flag k
    | Tls_min : [`v1_3 | `v1_2 | `v1_1 ] k
    | Tun_mtu : int k
    | Verb : int k

  module K = struct
    type 'a t = 'a k
    let pp (type x) ppf (k: x t) (v:x) =
      let p () = Fmt.pf ppf in
      match k,v with
      | Auth_retry, `Nointeract -> p() "auth-retry nointeract"
      | Auth_user_pass, (user,pass) ->
        Fmt.pf ppf "auth-user-pass %S %S" user pass
      | Bind, bool -> p() "bind %b" bool
      | Ca, ca -> p() "ca # %s" (X509.common_name_to_string ca)
      | Cipher, cipher -> p() "cipher %s" cipher
      | Comp_lzo, () -> p() "comp-lzo # deprecated"
      | Connect_retry, (low,high) -> p() "connect-retry %d %d" low high
      | Dev, `Tap i -> p() "dev tap%d" i
      | Dev, `Tun i -> p() "dev tun%d" i
      | Dev, `Null -> p() "dev null"
      | Float, () -> p() "float"
      | Ifconfig_nowarn, () -> p() "ifconfig-nowarn"
      | Keepalive, (low,high) -> p() "keepalive %d %d" low high
      | Mssfix, int -> p() "mssfix %d" int
      | Mute_replay_warnings, () -> p() "mute-replay-warnings"
      | Passtos, () -> p() "passtos"
      | Persist_key, () -> p() "persist-key"
      | Proto, `Tcp -> p() "proto tcp"
      | Proto, `Udp -> p() "proto udp"
      | Pull, () -> p() "pull"
      | Remote, lst ->
        p() "remote @[<v>%a@]"
          Fmt.(list ~sep:(unit" ") @@ pair ~sep:(unit ":")
                 (fun ppf -> function
                    | `Domain name -> Domain_name.pp ppf name
                    | `IP ip -> Ipaddr.pp ppf ip)
                 int (*port*)) lst
      | Remote_cert_tls, `Server -> p() "remote-cert-tls server"
      | Remote_cert_tls, `Client -> p() "remote-cert-tls client"
      | Remote_random, () -> p() "remote-random"
      | Replay_window, (low,high) -> p() "replay-window %d %d" low high
      | Resolv_retry, `Infinite -> p() "resolv-retry infinite"
      | Resolv_retry, `Seconds i -> p() "resolv-retry %d" i
      | Tls_auth, (a,b,c,d) ->
        p() "tls-auth @[<v>%a@ %a@ %a@ %a@]"
          Cstruct.hexdump_pp a
          Cstruct.hexdump_pp b
          Cstruct.hexdump_pp c
          Cstruct.hexdump_pp d
      | Tls_client, () -> p() "tls-client"
      | Tls_min, ver -> p() "tls-min %s" (match ver with
          | `v1_3 -> "1.3" | `v1_2 -> "1.2" | `v1_1 -> "1.1")
      | Tun_mtu, int -> p() "tun-mtu %d" int
      | Verb, int -> p() "verb %d" int

    let compare : type a b. a t -> b t -> (a,b) Gmap.Order.t = fun a b ->
      match Hashtbl.(compare (hash a) (hash b) ) with
      | 0 -> Obj.magic Gmap.Order.Eq (* GADT equality :-/ *)
      | x when x < 0 -> Lt
      | _ -> Gt
  end

  include Gmap.Make(K)

  let is_valid_client_config t =
    let ensure_mem k err = if mem k t then Ok () else Error err in
    let open Rresult in
    R.reword_error (fun err -> "not a valid client config: " ^  err)
      ( ensure_mem Remote "does not have a remote"  >>=fun()->
        ensure_mem Tls_client "is not a TLS client" >>=fun()->
        ensure_mem Auth_user_pass "does not have user/password"
        (* ^-- TODO or has client certificate ? *)
        >>= fun () ->
        (if mem Remote_cert_tls t && get Remote_cert_tls t <> `Server then
           Error "remote-cert-tls is not SERVER?!" else Ok ())
      )
end

open Conf_map

type line = [
  | `Entries of b list
  | `Entry of b
  | `Blank
  | `Inline of string * string
  | `Proto_force of [ `Tcp | `Udp ]
  | `Remote_cert_key_usage of int
  | `Socks_proxy of string * int * [ `Inline | `Path of string ]
  | [`Ca | `Pkcs12 | `Tls_auth | `Auth_user_pass] inline_or_path
]

let pp_line ppf (x : line) =
  let v = Fmt.pf in
  (match x with
   | `Entries _ -> v ppf "entries TODO"
   | `Entry _ -> v ppf "entry TODO"
   | `Blank -> v ppf "#"
   | `Proto_force _ -> v ppf "proto-force"
   | `Socks_proxy _ -> v ppf "socks-proxy"
   | `Remote_cert_key_usage f -> v ppf "remote-cert-ku %0.4x" f
   | `Inline (tag, content) -> v ppf "<%s>:%S" tag content
   | `Path (fn, _) -> v ppf "inline-or-path: %s" fn
   | `Need_inline _ -> v ppf "inline-or-path: inline"
  )

let a_comment =
  (* TODO validate against openvpn behavior,
     - can a finished line like 'dev tun0' have a comment at the end?
     - can comments be prefixed by whitespace? *)
  ((char '#' <|> char ';') *>
   skip_many (skip @@ function '\n' -> false | _ -> true))

let a_whitespace_unit =
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let a_whitespace_or_comment =
    a_comment <|> a_whitespace_unit

let a_ign_whitespace = skip_many a_whitespace_or_comment
let a_ign_whitespace_no_comment = skip_many a_whitespace_unit

let a_whitespace = skip_many1 a_whitespace_or_comment

let not_control_char = function '\x00'..'\x1f'|'\x7f' -> false | _ -> true

let a_line predicate = take_while predicate <* (end_of_line <|> end_of_input)

let a_number =
  take_while1 (function '0'..'9' -> true | _ -> false) >>= fun str ->
  match int_of_string str with
  | i when string_of_int i = str -> return i
  | _ -> fail (Fmt.strf "Invalid number: %S" str)
  | exception _ -> fail (Fmt.strf "Invalid number: %S" str)

let a_number_range min' max' =
  a_number >>= function | n when n <= max' && min' <= n -> return n
                        | n -> fail (Fmt.strf "Number out of range: %d" n)

let a_client =
  (* alias for --tls-client --pull *)
  string "client" *> a_ign_whitespace *>
  return (`Entries [ B (Tls_client,()) ; B (Pull,()) ])

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
  ] >>| fun prot -> `Entry (B(Proto,prot))

let a_proto_force =
  string "proto-force" *> a_whitespace *> choice [
    string "tcp" *> return `Tcp ;
    string "udp" *> return `Udp
  ] >>| fun prot -> `Proto_force prot


let a_resolv_retry =
  string "resolv-retry" *> a_whitespace *>
  choice [ string "infinite" *> return `Infinite ;
           a_number >>= fun i -> return (`Seconds i)
         ] >>| fun i -> `Entry (B(Resolv_retry,i))

let a_filepath kind =
  choice [
    string "[inline]" *> return (`Need_inline kind);
    (take_while1 (function '\x00'..'\x1f' -> false
                         | _ -> true) >>| fun p -> `Path (p,kind)) ;
  ]

let a_option_with_single_path name kind =
  string name *> a_whitespace *>
  a_filepath kind

let a_ca = a_option_with_single_path "ca" `Ca

let a_ca_payload str =
  match X509.Encoding.Pem.parse (Cstruct.of_string str) with
  | ("CERTIFICATE", x)::[] ->
    begin match X509.Encoding.parse x with
      | Some cert -> Ok cert
      | None -> Error "CA: invalid certificate"
    end
  | exception Invalid_argument _ ->
    Error "CA: Error parsing PEM container"
  | _ -> Error "CA: PEM does not consist of a single certificate"

let a_pkcs12 = a_option_with_single_path "pkcs12" `Pkcs12

let a_tls_auth = a_option_with_single_path "tls-auth" `Tls_auth

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
  a_option_with_single_path "auth-user-pass" `Auth_user_pass

let a_auth_user_pass_payload =
  (* To protect against a client passing a maliciously  formed  user‐
     name  or  password string, the username string must consist only
     of these characters: alphanumeric, underbar ('_'),  dash  ('-'),
     dot  ('.'), or at ('@').  The password string can consist of any
     printable characters except for CR or LF.  Any  illegal  charac‐
     ters in either the username or password string will be converted
     to underbar ('_').*)
  ( a_line (function '_'|'-'|'.'|'@'|'a'..'z'|'A'..'Z'|'0'..'9' -> true
                    | _ -> false) >>= fun user ->
    a_line not_control_char >>= fun pass ->
    end_of_input *> return (Auth_user_pass, (user,pass))
  ) <|> fail "reading user/password file failed"

let a_auth_retry =
  string "auth-retry" *> a_whitespace *>
  choice [ string "nointeract" *> return `Nointeract ] >>| fun x ->
  `Entry (B(Auth_retry,x))

let a_socks_proxy =
  string "socks-proxy" *> a_whitespace *>
  take_till (function '\n'|'\t'|' ' -> false | _ -> true) >>= fun server ->
  ( (a_whitespace *> a_number_range 0 65535 >>= fun port ->
     ( (a_whitespace *> a_filepath `Socks_proxy >>= function
         | `Path (path, `Socks_proxy) -> return (server, port, `Path path)
         | `Need_inline _ -> fail "socks-proxy not inlineable"
         )
       <|> return (server, port, `Path "stdin")
     )
    )
    <|> return (server, 1080, `Path "stdin")
  ) >>| fun x -> `Socks_proxy x

let a_flag =
  let r k v = return (B (k,v)) in
  choice [
    string "bind" *> r Bind true ;
    string "nobind" *> r Bind false ;
    string "float" *> r Float () ;
    string "remote-random" *> r Remote_random () ;
    string "tls-client" *> r Tls_client () ;
    string "persist-key" *> r Persist_key () ;
    string "comp-lzo" *> r Comp_lzo () ; (* TODO warn! *)
    string "passtos" *> r Passtos () ;
    string "mute-replay-warnings" *> r Mute_replay_warnings () ;
    string "ifconfig-nowarn" *> r Ifconfig_nowarn () ;
  ] >>| fun b -> `Entry b

let a_remote_cert_tls =
  string "remote-cert-tls" *> a_whitespace *>
  choice [ string "server" *> return `Server ;
           string "client" *> return `Client ;
         ] >>| fun purpose -> `Entry (B(Remote_cert_tls,purpose))

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
         ] >>| fun v -> `Entry (B(Tls_min,v))

let a_entry_one_number name =
  string name *> a_whitespace *> a_number

let a_tun_mtu = a_entry_one_number "tun-mtu" >>| fun x ->
  `Entry (B(Tun_mtu,x))

let a_mssfix = a_entry_one_number "mssfix" >>| fun x ->
  `Entry (B(Mssfix,x))
(* TODO make a_mssfix use a_number_range *)

let a_entry_two_numbers name =
  a_entry_one_number name >>= fun x ->
  a_whitespace *> a_number >>| fun y -> x,y

let a_connect_retry =
  a_entry_two_numbers "connect-retry" >>| fun pair ->
  `Entry (B (Connect_retry,pair))

let a_keepalive =
  a_entry_two_numbers "keepalive" >>| fun pair ->
  `Entry (B(Keepalive,pair))

let a_verb =
  a_entry_one_number "verb" >>| fun x -> `Entries [B (Verb, x)]

let a_cipher =
  string "cipher" *> a_whitespace *>
  take_while1 (function ' '| '\n' | '\t' -> false | _ -> true)
  >>| fun v -> `Entry (B(Cipher, v))

let a_replay_window =
  let replay_window a b = `Entry (B (Replay_window, (a, b))) in
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
  let remote a b = a, b in
  lift2 remote
    (string "remote" *> a_whitespace *>
     choice [
       (a_ipv4_dotted_quad >>| fun i -> `IP (Ipaddr.V4 i)) ;
       (a_ipv6_coloned_hex >>| fun i -> `IP (Ipaddr.V6 i)) ;
       (a_domain_name >>| fun dns -> `Domain dns)
     ]
    )
    (option 1194 (a_whitespace *> a_number))

let a_remote_entry = a_remote >>| fun (a,b) -> `Entry (B (Remote, [a,b]))

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

let a_config_entry : line A.t =
  a_ign_whitespace_no_comment *>
  Angstrom.choice [
    a_client ;
    (a_dev >>| fun name -> `Entry (B (Dev,name))) ;
    a_proto ;
    a_proto_force ;
    a_resolv_retry ;
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
    a_remote_entry ;
    a_pkcs12 ;
    a_flag ;
    a_ca ;
    a_whitespace *> return `Blank ;
  ]


let parse_internal config_str : (line list, 'x) result=
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

type parser_partial_state = line list * Conf_map.t
type parser_state = [`Done of Conf_map.t
                    | `Partial of parser_partial_state
                    | `Need_file of (string * parser_partial_state) ]
type parser_effect = [`File of string * string] option

let parse_next (effect:parser_effect) initial_state : (parser_state, 'err) result =
  let open Rresult in
  let rec loop (acc:Conf_map.t) : line list -> (parser_state,'b) result =
    function
    | (hd:line)::tl ->
      (* TODO should make sure not to override without conflict resolution,
         ie use addb_unless_bound and so on... *)
      let multib kv = loop (List.fold_left (fun acc b ->
          addb b acc) acc kv) tl in
      let multi lst = List.map (fun (k,v) -> B(k,v)) lst|> multib in
      let ret k v = multi [k,v] in
      let ok_add k v = loop (update k (function
          | None -> Some [v]
          | Some old -> Some (v::old)
        ) acc) tl in
      begin match hd with
        | `Path (wanted_name, kind) ->
          begin match effect with
            | Some `File (effect_name, contents) when
                String.equal effect_name wanted_name ->
              begin match kind with
                | `Auth_user_pass ->
                  parse_string a_auth_user_pass_payload contents
                  >>= fun (k,v) -> ret k v
                | `Ca -> a_ca_payload contents >>= ret Ca
                | `Tls_auth ->
                  parse_string a_tls_auth_payload contents >>= ret Tls_auth
                | _ -> Error "Unknown file type requested TODO"
              end
            | _ -> Ok (`Need_file (wanted_name, (hd::tl, acc)))
          end
      | `Inline ("tls-auth", x) ->
        parse_string a_tls_auth_payload x >>= ret Tls_auth
      | `Inline ("connection", str) ->
        parse_string a_remote str >>= ok_add Remote
      | `Inline ("ca", str) -> a_ca_payload str >>= ret Ca
      | `Blank -> loop acc tl
      | `Entry (B(k,v)) -> ret k v
      | `Entries lst -> multib lst
      | line ->
        Logs.warn (fun m -> m"ignoring unimplemented option: %a" pp_line line) ;
        loop acc tl
      end
    | [] -> Ok (`Done acc : parser_state)
  in
  match initial_state with
  | `Done _ as ret -> Ok ret (* already done*)
  | `Partial (lines, acc) -> loop acc lines
  | `Need_file (_fn, (lines, acc)) -> loop acc lines

let parse_begin config_str : (parser_state, 'err) result =
  let open Rresult in
  parse_internal config_str >>= fun lines ->
  parse_next None (`Partial (lines, empty))

let parse ~string_of_file config_str =
  let open Rresult in
  let rec loop = function
    | `Done conf -> Ok conf
    | `Partial _ as t -> parse_next None t >>= loop
    | `Need_file (fn, t) ->
      string_of_file fn >>= fun contents ->
      parse_next (Some (`File (fn, contents))) (`Partial t) >>= loop
  in
  parse_begin config_str >>= fun initial -> loop initial
