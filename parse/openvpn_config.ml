module Logs = (val Logs.(src_log @@ Src.create
                           ~doc:"Openvpn library's configuration module"
                           "ovpn.config") : Logs.LOG)
open Angstrom

module A = Angstrom

type inlineable = [ `Auth_user_pass | `Ca | `Connection | `Pkcs12 | `Tls_auth ]
let string_of_inlineable = function
  | `Auth_user_pass -> "auth-user-pass"
  | `Ca -> "ca"
  | `Connection -> "connection"
  | `Pkcs12 -> "pkcs12"
  | `Tls_auth -> "tls-auth"
type inline_or_path = [ `Need_inline of inlineable
                      | `Path of string * inlineable ]

module Conf_map = struct
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
    | Dhcp_disable_nbt: flag k
    | Dhcp_dns: Ipaddr.t list k
    | Dhcp_ntp: Ipaddr.t list k
    | Dhcp_domain: Domain_name.t k
    | Float    : flag k
    | Ifconfig : (Ipaddr.t * Ipaddr.t) k
    | Ifconfig_nowarn : flag k
    | Keepalive : (int * int) k
    | Mssfix   : int k
    | Mute_replay_warnings : flag k
    | Passtos  : flag k
    | Persist_key : flag k
    | Ping      : int k
    | Ping_exit : int k
    | Ping_restart : int k
    | Pull     : flag k
    | Proto    : [`Tcp | `Udp] k
    | Remote : ([`Domain of Domain_name.t | `IP of Ipaddr.t] * int) list k
    | Remote_cert_tls : [`Server | `Client] k
    | Remote_random : flag k
    | Replay_window : (int * int) k
    | Resolv_retry : [`Infinite | `Seconds of int] k
    | Route : ([`ip of Ipaddr.t | `net_gateway | `remote_host | `vpn_gateway]
               * Ipaddr.t option
               * [`ip of Ipaddr.t | `net_gateway | `remote_host
                 | `vpn_gateway] option
               * int option) k
    | Route_gateway : Ipaddr.t option k
    | Tls_auth : (Cstruct.t * Cstruct.t * Cstruct.t * Cstruct.t) k
    | Tls_client    : flag k
    | Tls_version_min : ([`v1_3 | `v1_2 | `v1_1 ] * bool) k
    | Topology : [`net30 | `p2p | `subnet] k
    | Tun_mtu : int k
    | Verb : int k

  module K = struct
    type 'a t = 'a k

    let compare : type a b. a t -> b t -> (a,b) Gmap.Order.t = fun a b ->
      (* ensure they're plain variant tags: *)
      let is_int x = Obj.(magic x |> is_int) in assert (is_int a && is_int b);
      match compare (Obj.magic a : int) (Obj.magic b) with
      | 0 -> Obj.magic Gmap.Order.Eq (* GADT equality :-/ *)
      | x when x < 0 -> Lt
      | _ -> Gt
  end

  include Gmap.Make(K)

  let is_valid_client_config t =
    let ensure_mem k err = if mem k t then Ok () else Error err in
    let ensure_not k err = if not (mem k t) then Ok () else Error err in
    let open Rresult in
    R.reword_error (fun err -> `Msg ("not a valid client config: " ^  err))
      ( ensure_mem Remote "does not have a remote"  >>=fun()->
        ensure_mem Tls_client "is not a TLS client" >>=fun()->
        ensure_not Comp_lzo "LZO compression is deprecated upstream, and not implemented in this library" >>=fun() ->
        ensure_mem Auth_user_pass "does not have user/password"
        (* ^-- TODO or has client certificate ? *)
        >>= fun () ->
        (if mem Cipher t && get Cipher t <> "AES-256-CBC" then
           Error "currently only supported Cipher is 'AES-256-CBC'"
         else Ok ()) >>=fun()->
        (if mem Remote_cert_tls t && get Remote_cert_tls t <> `Server then
           Error "remote-cert-tls is not SERVER?!" else Ok ())
      )

  let pp ppf t =
    let pp ppf (b:b) =
      let p () = Fmt.pf ppf in
      let B (k,v) = b in
      match k,v with
      | Auth_retry, `Nointeract -> p() "auth-retry nointeract"
      | Auth_user_pass, (user,pass) ->
        Fmt.pf ppf "auth-user-pass [inline]\n<auth-user-pass>\n%s\n%s\n</auth-user-pass>" user pass
      | Bind, true -> p() "bind"
      | Bind, false -> p() "nobind"
      | Ca, ca -> p() "ca [inline]\n# CN: %S\n<ca>\n%s</ca>"
                    (X509.common_name_to_string ca)
                    (X509.Encoding.Pem.Certificate.to_pem_cstruct1 ca
                     |> Cstruct.to_string)
      | Cipher, cipher -> p() "cipher %s" cipher
      | Comp_lzo, () -> p() "comp-lzo # deprecated"
      | Connect_retry, (low,high) -> p() "connect-retry %d %d" low high
      | Dev, `Tap i -> p() "dev tap%d" i
      | Dev, `Tun i -> p() "dev tun%d" i
      | Dev, `Null -> p() "dev null"
      | Dhcp_disable_nbt, () -> p() "dhcp-option disable-nbt"
      | Dhcp_domain, n -> p() "dhcp-option domain %a" Domain_name.pp n
      | Dhcp_ntp, ips ->
        Fmt.(list ~sep:(unit"@.") @@
             (fun ppf -> pf ppf "dhcp-option ntp %a" Ipaddr.pp )) ppf ips
      | Dhcp_dns, ips ->
        Fmt.(list ~sep:(unit"@.") @@
             (fun ppf -> pf ppf "dhcp-option dns %a" Ipaddr.pp)) ppf ips
      | Float, () -> p() "float"
      | Ifconfig, (local,remote) ->
        p() "ifconfig %a %a" Ipaddr.pp local Ipaddr.pp remote
      | Ifconfig_nowarn, () -> p() "ifconfig-nowarn"
      | Keepalive, (low,high) -> p() "keepalive %d %d" low high
      | Mssfix, int -> p() "mssfix %d" int
      | Mute_replay_warnings, () -> p() "mute-replay-warnings"
      | Passtos, () -> p() "passtos"
      | Persist_key, () -> p() "persist-key"
      | Ping, i -> p() "ping %d" i
      | Ping_exit, i -> p() "ping-exit %d" i
      | Ping_restart, i -> p() "ping-restart %d" i
      | Proto, `Tcp -> p() "proto tcp"
      | Proto, `Udp -> p() "proto udp"
      | Pull, () -> p() "pull"
      | Remote, lst ->
        Fmt.(list ~sep:(unit"@.") @@
             (fun ppf -> pf ppf "remote %a"@@
               pair ~sep:(unit " ")
                 (fun ppf -> function
                    | `Domain name -> Domain_name.pp ppf name
                    | `IP ip -> Ipaddr.pp ppf ip)
                 int (*port*))) ppf lst
      | Remote_cert_tls, `Server -> p() "remote-cert-tls server"
      | Remote_cert_tls, `Client -> p() "remote-cert-tls client"
      | Remote_random, () -> p() "remote-random"
      | Replay_window, (low,high) -> p() "replay-window %d %d" low high
      | Resolv_retry, `Infinite -> p() "resolv-retry infinite"
      | Resolv_retry, `Seconds i -> p() "resolv-retry %d" i
      | Route, (network,netmask,gateway,metric) ->
        let pp_addr ppf v = Fmt.pf ppf "%s" (match v with
            | `ip ip -> Ipaddr.to_string ip
            | `net_gateway -> "net_gateway"
            | `remote_host -> "remote_host"
            | `vpn_gateway -> "vpn_gateway") in
        p() "route %a %a %a %a"
          pp_addr network
          Fmt.(option ~none:(unit"default") Ipaddr.pp) netmask
          Fmt.(option ~none:(unit"default") pp_addr) gateway
          Fmt.(option ~none:(unit"default") int) metric
      | Route_gateway, v ->
        p() "route-gateway %a" Fmt.(option ~none:(unit"default") Ipaddr.pp) v
      | Tls_auth, (a,b,c,d) ->
        p() "tls-auth [inline]\n<tls-auth>\n%s\n%a\n%s\n</tls-auth>"
          "-----BEGIN OpenVPN Static key V1-----"
          Fmt.(array ~sep:(unit"\n") string)
          (match Cstruct.concat [a;b;c;d] |> Hex.of_cstruct with
           | `Hex h -> Array.init (256/16) (fun i -> String.sub h (i*32) 32))
          "-----END OpenVPN Static key V1-----"
      | Tls_client, () -> p() "tls-client"
      | Tls_version_min, (ver,or_highest) ->
        p() "tls-version-min %s%s" (match ver with
            | `v1_3 -> "1.3" | `v1_2 -> "1.2" | `v1_1 -> "1.1")
          (if or_highest then " or-highest" else "")
      | Topology, v -> p() "topology %s" (match v with
            `net30 -> "net30" | `p2p -> "p2p" | `subnet -> "subnet")
      | Tun_mtu, int -> p() "tun-mtu %d" int
      | Verb, int -> p() "verb %d" int
    in
    let minimized_t =
      if mem Tls_client t && mem Pull t then begin
        Fmt.pf ppf "client\n" ; remove Tls_client t |> remove Pull
      end else t
    in
    Fmt.(pf ppf "%a" (list ~sep:(unit"@.") pp) (bindings minimized_t))

end

open Conf_map

type line = [
  | `Entries of b list
  | `Entry of b
  | `Blank
  | `Inline of string * string
  | `Proto_force of [ `Tcp | `Udp ]
  | `Socks_proxy of string * int * [ `Inline | `Path of string ]
  | inline_or_path
]

let pp_line ppf (x : line) =
  let v = Fmt.pf in
  (match x with
   | `Entries _ -> v ppf "entries TODO"
   | `Entry _ -> v ppf "entry TODO"
   | `Blank -> v ppf "#"
   | `Proto_force _ -> v ppf "proto-force"
   | `Socks_proxy _ -> v ppf "socks-proxy"
   | `Inline (tag, content) -> v ppf "<%s>:%S" tag content
   | `Path (fn, _) -> v ppf "inline-or-path: %s" fn
   | `Need_inline _ -> v ppf "inline-or-path: Need_inline"
  )

let a_comment =
  (* MUST have # or ; at the first column of a line. *)
  ((char '#' <|> char ';') *>
   skip_many (skip @@ function '\n' -> false | _ -> true))

let a_whitespace_unit =
  skip (function | ' '| '\t' -> true
                 | _ -> false)

let a_single_param =
  (* Handles single-quoted or double-quoted, using backslash as escaping char.*)
  let rec escaped q acc : string Angstrom.t =
    let again = escaped q in
    let ret acc = return (String.concat "" (List.rev acc)) in
    peek_char >>= function
    | Some '\\' -> advance 1 >>= fun () -> any_char >>= (function
        | q2 when q=q2 -> again (String.make 1 q::acc)
        | c -> again (String.make 1 c::"\\"::acc))
    | Some q2 when q = q2 -> ret acc
    | Some c -> advance 1 >>= fun () -> again ((String.make 1 c)::acc)
    | None -> fail ("end of input while looking for matching "
                    ^ (String.make 1 q) ^" quote")
  in
  choice [
    char '\'' *> Angstrom.commit *> escaped '\'' [] <* char '\'' ;
    char '"' *> Angstrom.commit *> escaped '"' [] <* char '"' ;
    ( take_while (function ' '|'\t'|'\''|'"'|'\n' -> false | _ -> true)
      >>= fun v -> if String.(contains_from v (min 0 @@ length v) '\'')
                   || String.(contains_from v (min 0 @@ length v) '"')
      then fail "unquoted parameter contains quote"
      else return v) ;
  ]

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

let a_dev =
  Logs.warn (fun m ->
      m "TODO: 'dev tun' is also valid, according to the manpage: \
         'tunX - X can be omitted for a dynamic device'");
  let a_device_name =
    choice [
      (string "tun" *> a_number_range 0 128 >>| fun x -> `Tun x) ;
      (string "tap" *> a_number_range 0 128 >>| fun x -> `Tap x) ;
      string "null" *> return `Null ;
    ]
  in
  string "dev" *> a_whitespace *> a_device_name >>| fun name ->
  `Entry (B (Dev,name))

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
      | Some cert -> Ok (B (Ca, cert))
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
  B (Tls_auth,
     Cstruct.(sub cs 0        64,
              sub cs 64       64,
              sub cs 128      64,
              sub cs (128+64) 64))

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
    end_of_input *> return (B (Auth_user_pass, (user,pass)))
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
    string "pull" *> r Pull () ;
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
let _TODO = a_hex

let a_tls_version_min =
  string "tls-version-min" *> a_whitespace *>
  choice [ string "1.3" *> return `v1_3 ;
           string "1.2" *> return `v1_2 ;
           string "1.1" *> return `v1_1 ;
         ] >>= fun v ->
  choice [a_whitespace *> string "or-highest" *> return true ;
          a_ign_whitespace *> end_of_line *> return false ] >>| fun or_h ->
  `Entry (B(Tls_version_min,(v,or_h)))

let a_entry_one_number name =
  string name *> a_whitespace *> a_number

let a_ping =
  a_entry_one_number "ping" >>| fun n -> `Entry (B(Ping, n))

let a_ping_restart =
  a_entry_one_number "ping-restart" >>| fun n -> `Entry (B(Ping_restart, n))

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

let a_topology =
  string "topology" *> a_whitespace *>
  choice [
    string "net30" *> return `net30 ;
    string "p2p" *> return `p2p ;
    string "subnet" *> return `subnet ;
  ] >>| fun v -> `Entry (B( Topology, v))

let a_cipher =
  string "cipher" *> a_whitespace *>
  a_single_param >>| fun v -> `Entry (B(Cipher, v))

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

let a_ip =
  (a_ipv4_dotted_quad >>| fun v4 -> Ipaddr.V4 v4)
  <|> (a_ipv6_coloned_hex >>| fun v6 -> Ipaddr.V6 v6)

let a_domain_name =
  take_till (function '\x00'..'\x1f' | ' ' | '"' | '\'' -> true | _ -> false)
  >>= fun str -> match Domain_name.of_string str with
  | Error `Msg x -> fail (Fmt.strf "Invalid domain name: %s: %S" x str)
  | Ok x -> return x

let a_ifconfig =
  string "ifconfig" *>
  a_whitespace *> a_ip >>= fun local ->
  a_whitespace *> a_ip >>| fun remote ->
  `Entry (B(Ifconfig, (local,remote)))

(* TODO finish "remote [port] [proto]" by adding proto (tcp/udp/tcp4/tcp6/udp4/udp6)
   what are the semantics if proto and remote proto is provided? *)
let a_remote =
  let remote a b = B (Remote, [a,b]) in
  lift2 remote
    (string "remote" *> a_whitespace *>
     choice [
       (a_ipv4_dotted_quad >>| fun i -> `IP (Ipaddr.V4 i)) ;
       (a_ipv6_coloned_hex >>| fun i -> `IP (Ipaddr.V6 i)) ;
       (a_domain_name >>| fun dns -> `Domain dns)
     ]
    )
    (option 1194 (a_whitespace *> a_number))

let a_remote_entry = a_remote >>| fun b -> `Entry b

let a_network_or_gateway =
  choice [ (a_ip >>| fun ip -> `ip ip) ;
           (string "vpn_gateway" *> return `vpn_gateway) ;
           (string "net_gateway" *> return `net_gateway) ;
           (string "remote_host" *> return `remote_host) ]

let a_route =
  (* --route network/IP [netmask] [gateway] [metric] *)
  string "route" *> a_whitespace *> a_network_or_gateway >>= fun network ->
  let some x = Some x in

  option (some @@ Ipaddr.of_string_exn "255.255.255.255", None, None)
    ( (a_whitespace *>
       (((string "default" *> return
           (some @@ Ipaddr.of_string_exn "255.255.255.255"))
       ) <|> (a_ip >>| fun x -> some x))) >>= fun netmask ->
      option (None,None)
        (a_whitespace *>
         ((string "default" *>
           ((return None)) <|> (a_network_or_gateway >>| some))
         ) >>= fun gateway ->

         option None
           (a_whitespace *>
            ((string "default" *> return None) <|>
             (a_number_range 0 255 >>| fun n -> some n))
           ) >>| fun metric -> gateway,metric
        ) >>| (fun (gateway,metric) -> netmask,gateway,metric)
      (* <* end_of_input*)
    ) >>| fun (netmask,gateway,metric) ->
  `Entry (B (Route, (network,netmask,gateway,metric)))

let a_route_gateway =
  (string "route-gateway" *> a_whitespace) *>
  choice [
    (a_single_param >>= function "dhcp" -> return None
                               | _ -> fail "not 'dhcp'") ;
    (a_ip >>| fun x -> Some x) ] >>| fun x -> `Entry (B(Route_gateway,x))

let a_inline =
  (* TODO strip trailing newlines inside block ?*)
  char '<' *> take_while1 (function 'a'..'z' |'-' -> true
                                             | _  -> false)
  <* char '>' <* char '\n' >>= fun tag ->
  take_till (function '<' -> true | _ -> false) >>= fun x ->
  return (`Inline (tag, x))
  <* char '<' <* char '/' <* string tag <* char '>'

let a_dhcp_option =
  string "dhcp-option" *> a_whitespace *>
  a_single_param >>| String.lowercase_ascii >>= (function
      | "disable-nbt" -> return @@ B (Dhcp_disable_nbt,())
      | "dns" -> a_whitespace *> a_ip >>| fun ip -> B (Dhcp_dns, [ip])
      | "domain" -> a_whitespace *> a_domain_name >>| fun d -> B(Dhcp_domain, d)
      | "ntp" -> a_whitespace *> a_ip >>| fun ip -> B (Dhcp_ntp, [ip])
      | _ -> fail "Unrecognized dhcp-option type")
  >>| fun b -> `Entry b

let a_not_implemented =
  (choice
     [ string "sndbuf" ;
       string "rcvbuf" ;
       string "ip-win32" ;
       string "socket-flags" ;
       string "remote-cert-ku" ;
       (* TODO: *)
       string "dhcp-option";
       string "redirect-gateway" ;
     ] <* a_whitespace >>= fun key ->
   take_while (function '\n' -> false | _ -> true) >>| fun rest ->
   Logs.warn (fun m ->m "IGNORING %S %S" key rest)
  ) *> A.many_till (skip (fun _ -> true)) end_of_line
  *> (*end_of_line *>*) return `Blank

let a_config_entry : line A.t =
  a_ign_whitespace_no_comment *>
  Angstrom.choice [
    a_client ;
    a_dev ;
    a_dhcp_option ;
    a_proto ;
    a_proto_force ;
    a_resolv_retry ;
    a_tls_auth ;
    a_remote_cert_tls ;
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
    a_ping ;
    a_ping_restart ;
    a_ifconfig ;
    a_topology ;
    a_route ;
    a_route_gateway ;
    a_topology ;
    a_not_implemented ;
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

let parse_inline str = let open Rresult in
  function
  | `Auth_user_pass ->
    (* TODO openvpn doesn't seem to allow inlining passwords, we do.. *)
    parse_string a_auth_user_pass_payload str
  | `Tls_auth -> parse_string a_tls_auth_payload str
  | `Connection ->
    (* TODO entries can sometimes be nested, like in <connection> blocks:
       The following OpenVPN options may be used inside of  a  <connection> block:
       bind,  connect-retry,  connect-retry-max,  connect-timeout,
       explicit-exit-notify, float, fragment, http-proxy,  http-proxy-option,
       link-mtu, local, lport, mssfix, mtu-disc, nobind, port,
       proto, remote, rport, socks-proxy, tun-mtu and tun-mtu-extra. *)
    parse_string a_remote str
  | `Ca -> a_ca_payload str
  | kind -> Error ("config-parser: not sure how to parse inline " ^
                   (string_of_inlineable kind))

let eq : eq = { f = fun k v v2 ->
    let eq = v = v2 in (*TODO non-polymorphic comparison*)
    begin if not eq then Logs.debug
          (fun m -> m "eq self-test: %a <> %a"
              pp (singleton k v)
              pp (singleton k v2))
        ; eq end }


let resolve_conflict (type a) t (k:a key) (v:a)
  : ((a key * a) option, 'a) result =
  let warn () =
    Logs.debug (fun m -> m "Configuration flag appears twice: %a"
                   pp (singleton k v)); Ok None in
  match find k t with
  | None -> Ok (Some (k,v))
  | Some v2 -> begin match k with
      (* idempotent, as most of the flags - not a failure, emit warn: *)
      | Tls_client -> warn () | Comp_lzo -> warn () | Float -> warn ()
      | Ifconfig_nowarn -> warn () | Mute_replay_warnings -> warn ()
      | Passtos -> warn () | Persist_key -> warn () | Pull -> warn ()
      | Remote_random -> warn ()
      (* adding wouldn't change anything: *)
      | _ when v = v2 -> (* TODO polymorphic comparison *)
        Logs.debug (fun m ->
            m "Config key %a was supplied multiple times with same value"
              pp (singleton k v)) ; Ok None
      (* can coalesce: *)
      | Dhcp_dns -> Ok (Some (Dhcp_dns, (get Dhcp_dns t @ v)))
      | Dhcp_ntp -> Ok (Some (Dhcp_ntp, (get Dhcp_ntp t @ v)))
      | Remote -> Ok (Some (Remote, (get Remote t @ v)))
      (* else: *)
      | _ -> Error (Fmt.strf "conflicting keys: %a not in %a"
                      pp (singleton k v) pp t)
    end

let resolve_add_conflict t (B(k,v)) =
  let open Rresult in
  resolve_conflict t k v >>| function
  | Some (k,v) -> add k v t | None -> t

let valid_server_options ~client:_ _server_t =
  Logs.err (fun m -> m "TODO valid_server_options is not implemented") ;
  Ok ()

let merge_push_reply ~client push_config =
  let will_accept (type a) (k:a key) (v:a) =
    match k,v with
    (* whitelist keys we are willing to accept from server: *)
    | Dhcp_disable_nbt, _ -> true
    | Dhcp_domain, _ -> true
    | Mssfix, _ -> true
    | Tls_client, _ -> true
    | Tun_mtu, _ -> true
    | Topology, _ -> true
    | Ping, _ -> true
    | Ping_restart, _ -> true
    (* TODO | Redirect_gateway, _ -> true *)

    (* TODO should verify IPs: *)
    | Dhcp_dns, _ -> true
    | Dhcp_ntp, _ -> true
    | Route, _ -> true
    | Route_gateway, _ -> true
    | _ -> false
  in
  (* let naughty_server = in *)
  let f (type a) (k:a key) (a:a option) (b:a option) =
    let oks v = Ok (Some v) in
    match k,(a:a option),(b:a option) with
    (* server didn't touch this key: *)
    | _, Some a, None -> oks a
    | _, None, None -> Ok None
    (* Client overrides list completely if set: *)
    (* TODO all keys with type 'a list k should probably be listed here,
       can we ensure that statically? *)
    | Dhcp_dns, Some a, Some _ -> oks a
    | Dhcp_ntp, Some a, Some _ -> oks a
    (* TODO | Route, Some a, _ -> a*)
    (* try to merge: *)
    | _, Some a, Some b ->
      begin match a, b with
        (* they're equal, use client version: *)
          _ when eq.f k a b -> oks a

        | _ when not (will_accept k b) ->
          Rresult.R.error_msgf "push-reply: won't accept %a"
            pp (singleton k b)

        (* at this point we need to merge them*)
        | a,b -> begin match resolve_conflict (singleton k a) k b with
            | Ok (Some (_,merged)) -> oks merged
            (* client takes precedence if merging fails: *)
            | _ -> oks a
          end
      end

    (* try to use server value: *)
    | _, None, Some v ->
      if will_accept k v
      then Ok b (* <-- use server version *)
      else Rresult.R.error_msgf "server pushed disallowed: %a"
          pp (singleton k v)
  in
  merge { f } client push_config

let parse_next (effect:parser_effect) initial_state : (parser_state, 'err) result =
  let open Rresult in
  let rec loop (acc:Conf_map.t) : line list -> (parser_state,'b) result =
    function
    | (hd:line)::tl ->
      (* TODO should make sure not to override without conflict resolution,
         ie use addb_unless_bound and so on... *)
      let multib kv =
        (List.fold_left (fun acc b ->
             acc >>= fun acc ->
          match resolve_add_conflict acc b with
          | Ok _ as next -> next
          | Error err ->
            Logs.debug (fun m -> m "%S : %a" err pp acc);
            Error err) (Ok acc) kv) >>= fun acc -> loop acc tl in
      let retb b = multib [b] in
      begin match hd with
        | `Path (wanted_name, kind) ->
          begin match effect with
            | Some `File (effect_name, content) when
                String.equal effect_name wanted_name ->
              (* TODO ensure returned B matches kind? *)
              R.reword_error (fun x -> "failed parsing provided file: " ^ x)
                (parse_inline content kind) >>= retb
            | Some `File (name, _) ->
              Error ("config-parser: got unrequested file contents for " ^ name)
            | None -> Ok (`Need_file (wanted_name, (hd::tl, acc)))
          end
        | `Need_inline kind ->
          let looking_for = string_of_inlineable kind in
          begin match List.partition (function
              | `Inline (kind2, _) -> String.equal looking_for kind2
              | _ -> false) tl with
          | `Inline (_, x)::inline_tl, other_tl ->
            Logs.debug (fun m -> m "consuming [inline] %s" looking_for);
            parse_inline x kind >>= resolve_add_conflict acc >>= fun acc ->
            loop acc (other_tl @ inline_tl)
          | [], _ ->
            (* TODO if we already have it in the map, we don't need to fail: *)
            Error ("not found: needed [inline]: " ^ looking_for)
          | _ -> Error "TODO List.partition was wrong"
          end
        | `Inline ("connection", x) ->
          parse_inline x `Connection >>= resolve_add_conflict acc >>= fun acc ->
          loop acc tl
        | `Inline (fname, _) ->
          (* Except for "connection" all blocks must be warranted by an
             [inline] value in a matching directive. If we have one, we move
             this block to the end of the list (since we -know- it's needed).
             If not, we ignore it after emitting an error: *)
          loop acc @@
          tl @ if List.exists (function
              | `Need_inline k when String.equal fname
                    (string_of_inlineable k)-> true
              | _ -> false) tl then [hd]
          else begin Logs.warn (fun m ->
              m "Inline block %S seems to be redundant" fname); [] end
        | `Blank -> loop acc tl
        | `Entry b -> retb b
        | `Entries lst -> multib lst
        | ( `Proto_force _
          | `Socks_proxy _) as line ->
          Logs.warn (fun m -> m"ignoring unimplemented option: %a"
                        pp_line line) ;
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

let parse ~string_of_file config_str : (Conf_map.t, [> Rresult.R.msg]) result =
  let open Rresult in
  let to_msg t = R.reword_error (fun s -> `Msg s) t in
  let rec loop = function
    | `Done conf -> Ok conf
    | `Partial _ as t -> parse_next None t |> to_msg >>= loop
    | `Need_file (fn, t) ->
      string_of_file fn >>= fun contents ->
      parse_next (Some (`File (fn, contents))) (`Partial t)
      |> to_msg >>= loop
  in
  parse_begin config_str |> to_msg >>= fun initial ->
  (loop initial : (_,[< R.msg]) result :> (_,[> R.msg]) result)

include Conf_map
