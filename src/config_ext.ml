let tls_ciphers config =
  (* update when ocaml-tls changes default ciphers *)
  let tls_default_ciphers13 =
    [
      `AES_128_GCM_SHA256;
      `AES_256_GCM_SHA384;
      `CHACHA20_POLY1305_SHA256;
      `AES_128_CCM_SHA256;
    ]
  and tls_default_ciphers =
    [
      `DHE_RSA_WITH_AES_256_GCM_SHA384;
      `DHE_RSA_WITH_AES_128_GCM_SHA256;
      `DHE_RSA_WITH_AES_256_CCM;
      `DHE_RSA_WITH_AES_128_CCM;
      `DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
      `ECDHE_RSA_WITH_AES_128_GCM_SHA256;
      `ECDHE_RSA_WITH_AES_256_GCM_SHA384;
      `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
      `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
      `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
      `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    ]
  in
  match (Config.find Tls_cipher config, Config.find Tls_ciphersuite config) with
  | Some c, None -> Some (c @ tls_default_ciphers13)
  | None, Some c ->
      Some (tls_default_ciphers @ (c :> Tls.Ciphersuite.ciphersuite list))
  | Some c, Some c' -> Some (c @ (c' :> Tls.Ciphersuite.ciphersuite list))
  | None, None -> None

let tls_version config =
  (* update when ocaml-tls supports new versions *)
  let tls_lowest_version = `TLS_1_0 and tls_highest_version = `TLS_1_3 in
  let lower_bound =
    match Config.find Tls_version_min config with
    | None -> None
    | Some (v, or_highest) ->
        if or_highest then Some tls_highest_version else Some v
  and upper_bound = Config.find Tls_version_max config in
  match (lower_bound, upper_bound) with
  | None, None -> None
  | Some a, Some b -> Some (a, b)
  | Some a, None -> Some (a, tls_highest_version)
  | None, Some b -> Some (tls_lowest_version, b)

let tls_auth config =
  match Config.find Tls_auth config with
  | None -> Error (`Msg "no tls auth payload in config")
  | Some (direction, _, hmac1, _, hmac2) ->
      let hmac_algorithm = Config.get Auth config in
      let hmac_len =
        let module H = (val Digestif.module_of_hash' hmac_algorithm) in
        H.digest_size
      in
      let a, b =
        match direction with
        | None -> (hmac1, hmac1)
        | Some `Incoming -> (hmac2, hmac1)
        | Some `Outgoing -> (hmac1, hmac2)
      in
      let s cs = String.sub cs 0 hmac_len in
      Ok { State.hmac_algorithm; my_hmac = s a; their_hmac = s b }

let secret config =
  match Config.find Secret config with
  | None -> Error (`Msg "no pre-shared secret found")
  | Some (dir, key1, hmac1, key2, hmac2) -> (
      let hmac_len =
        let module H = (val Digestif.module_of_hash' (Config.get Auth config))
        in
        H.digest_size
      in
      let hm cs = String.sub cs 0 hmac_len and cipher cs = String.sub cs 0 32 in
      match dir with
      | None -> Ok (cipher key1, hm hmac1, cipher key1, hm hmac1)
      | Some `Incoming -> Ok (cipher key2, hm hmac2, cipher key1, hm hmac1)
      | Some `Outgoing -> Ok (cipher key1, hm hmac1, cipher key2, hm hmac2))

let tls_crypt config =
  match (Config.find Tls_mode config, Config.find Tls_crypt config) with
  | None, Some _ -> assert false
  | _, None -> Error (`Msg "no tls-crypt payload in config")
  | Some `Client, Some kc ->
      Ok { State.my = Tls_crypt.client_key kc; their = Tls_crypt.server_key kc }
  | Some `Server, Some kc ->
      Ok { State.my = Tls_crypt.server_key kc; their = Tls_crypt.client_key kc }

let tls_crypt_v2_client config =
  match Config.find Tls_crypt_v2_client config with
  | None -> Error (`Msg "no tls-crypt-v2 payload in config")
  | Some (kc, wkc, force_cookie) ->
      Ok
        ( { State.my = Tls_crypt.client_key kc; their = Tls_crypt.server_key kc },
          wkc,
          force_cookie )

let control_crypto config =
  match
    ( tls_auth config,
      tls_crypt config,
      tls_crypt_v2_client config,
      secret config )
  with
  | Error e, Error _, Error _, Error _ -> Error e
  | Error _, Error _, Error _, Ok (my_key, my_hmac, their_key, their_hmac) ->
      (* in static key mode, only CBC is allowed *)
      assert (Config.get Cipher config = `AES_256_CBC);
      let keys =
        let keys =
          State.AES_CBC
            {
              my_key = Mirage_crypto.AES.CBC.of_secret my_key;
              my_hmac;
              their_key = Mirage_crypto.AES.CBC.of_secret their_key;
              their_hmac;
            }
        in
        { State.my_replay_id = 1l; their_replay_id = 1l; keys }
      in
      Ok (`Static keys)
  | Error _, Ok tls_crypt, _, _ -> Ok (`Tls_crypt (tls_crypt, None))
  | Error _, Error _, Ok (tls_crypt, wkc, _force_cookie), _ ->
      Ok (`Tls_crypt (tls_crypt, Some wkc))
  | Ok tls_auth, _, _, _ -> Ok (`Tls_auth tls_auth)

let ifconfig config =
  let address, netmask = Config.get Ifconfig config in
  Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address

let vpn_gateway config =
  match Config.find Dev config with
  | None | Some (`Tap, _) ->
      (* Must be tun *)
      assert false
  | Some (`Tun, _) ->
      if Config.mem Secret config then snd (Config.get Ifconfig config)
      else
        let cidr = ifconfig config in
        Ipaddr.V4.Prefix.first cidr

let route_gateway config =
  match Config.find Route_gateway config with
  | Some `Dhcp -> assert false (* we don't support this *)
  | Some (`Ip ip) -> ip
  | None -> vpn_gateway config

let ip_from_config config =
  let cidr = ifconfig config and gateway = route_gateway config in
  { State.cidr; gateway }

let server_ip config =
  let cidr = Config.get Server config in
  let network = Ipaddr.V4.Prefix.network cidr
  and ip = Ipaddr.V4.Prefix.address cidr in
  if not (Ipaddr.V4.compare ip network = 0) then (ip, cidr)
  else
    (* take first IP in subnet (unless server a.b.c.d/netmask) with a.b.c.d not being the network address *)
    let ip' = Ipaddr.V4.Prefix.first cidr in
    (ip', cidr)

let next_free_ip config is_not_taken =
  let cidr = Config.get Server config in
  let network = Ipaddr.V4.Prefix.network cidr in
  let server_ip = fst (server_ip config) in
  (* could be smarter than a linear search *)
  let rec isit ip =
    if Ipaddr.V4.Prefix.mem ip cidr then
      if
        (not (Ipaddr.V4.compare ip server_ip = 0))
        && (not (Ipaddr.V4.compare ip network = 0))
        && is_not_taken ip
      then
        let cidr' = Ipaddr.V4.Prefix.make (Ipaddr.V4.Prefix.bits cidr) ip in
        Ok (ip, cidr')
      else
        match Ipaddr.V4.succ ip with Ok ip' -> isit ip' | Error e -> Error e
    else Error (`Msg "all ips are taken")
  in
  isit (Ipaddr.V4.Prefix.first cidr)

let default_port = 1194
let default_proto = `Udp
let default_ip = `Any

let server_bind_port config =
  match Config.(find Lport config, Config.find Port config) with
  | None, None -> default_port
  | Some a, _ -> a
  | _, Some b -> b

let proto config =
  let proto_to_proto = function `Udp -> `Udp | `Tcp _ -> `Tcp in
  match Config.find Proto config with
  | None -> (default_ip, default_proto)
  | Some (Some ip, proto) ->
      ((ip :> [ `Any | `Ipv4 | `Ipv6 ]), proto_to_proto proto)
  | Some (None, proto) -> (default_ip, proto_to_proto proto)

let remotes config =
  let default_ip_version, default_proto = proto config in
  let default_port =
    match Config.(find Port config, find Rport config) with
    | None, None -> default_port
    | Some a, _ -> a
    | _, Some b -> b
  in
  match Config.(find Remote config, find Proto_force config) with
  | None, _ -> []
  | Some remotes, proto_force ->
      let f (_, _, p) =
        match proto_force with None -> true | Some x -> x = p
      in
      List.filter_map
        (fun (ip_or_dom, port, proto) ->
          let ip_or_dom =
            match ip_or_dom with
            | `Domain (h, `Any) when proto = None ->
                `Domain (h, default_ip_version)
            | x -> x
          in
          let port = Option.value ~default:default_port port
          and proto = Option.value ~default:default_proto proto in
          let remote = (ip_or_dom, port, proto) in
          if f remote then Some remote else None)
        remotes

let route_metric config =
  Config.find Route_metric config |> Option.value ~default:0

(** Returns (cidr, gateway, metric) list *)
let routes ~shares_subnet ~net_gateway ~remote_host config :
    (Ipaddr.V4.Prefix.t * Ipaddr.V4.t * int) list =
  let route_gateway = route_gateway config
  and default_metric = route_metric config in
  let[@coverage off] pp_network_or_gateway ppf = function
    | `Ip ip -> Ipaddr.V4.pp ppf ip
    | `Net_gateway -> Fmt.string ppf "net_gateway"
    | `Vpn_gateway -> Fmt.string ppf "vpn_gateway"
    | `Remote_host -> Fmt.string ppf "remote_host"
  in
  let resolve_network_or_gateway = function
    | `Ip ip -> Some ip
    | `Net_gateway -> net_gateway
    | `Vpn_gateway -> Some (vpn_gateway config)
    | `Remote_host -> remote_host
  in
  let default_and_remote_routes =
    match Config.find Redirect_gateway config with
    | None -> []
    | Some flags ->
        let remote_route =
          if
            List.mem `Local flags
            || (shares_subnet && List.mem `Auto_local flags)
          then []
          else
            match (remote_host, net_gateway) with
            | Some remote_host, Some net_gateway ->
                let remote_network = Ipaddr.V4.Prefix.of_addr remote_host in
                [ (remote_network, net_gateway, default_metric) ]
            | _ -> []
        in
        if List.mem `Def1 flags then
          ( Ipaddr.V4.Prefix.of_string_exn "0.0.0.0/1",
            route_gateway,
            default_metric )
          :: ( Ipaddr.V4.Prefix.of_string_exn "128.0.0.0/1",
               route_gateway,
               default_metric )
          :: remote_route
        else
          (Ipaddr.V4.Prefix.global, route_gateway, default_metric)
          :: remote_route
  in
  let routes =
    Config.find Route config |> Option.value ~default:[]
    |> List.filter_map (fun (network, netmask, gateway, metric) ->
           let gateway = Option.value ~default:(`Ip route_gateway) gateway in
           match
             ( resolve_network_or_gateway network,
               resolve_network_or_gateway gateway )
           with
           | Some network, Some gateway ->
               let netmask =
                 Option.value netmask ~default:Ipaddr.V4.broadcast
               in
               let metric = Option.value ~default:0 metric in
               let prefix =
                 Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address:network
               in
               Some (prefix, gateway, metric)
           | None, _ ->
               Config.Log.warn (fun m ->
                   m "Unable to resolve network %a; omitting route"
                     pp_network_or_gateway network);
               None
           | _, None ->
               Config.Log.warn (fun m ->
                   m "Unable to resolve gateway %a; omitting route"
                     pp_network_or_gateway gateway);
               None)
  in
  routes @ default_and_remote_routes
