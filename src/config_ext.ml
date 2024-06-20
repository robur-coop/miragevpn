type ip_config = { cidr : Ipaddr.V4.Prefix.t; gateway : Ipaddr.V4.t }

let pp_ip_config ppf { cidr; gateway } =
  Fmt.pf ppf "ip %a gateway %a" Ipaddr.V4.Prefix.pp cidr Ipaddr.V4.pp gateway

let ifconfig config =
  let address, netmask = Config.get Ifconfig config in
  Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address

let vpn_gateway config =
  match Config.find Dev config with
  | None | Some (`Tap, _) ->
      (* Must be tun *)
      assert false
  | Some (`Tun, _) ->
      let cidr = ifconfig config in
      Ipaddr.V4.Prefix.first cidr

let route_gateway config =
  match Config.find Route_gateway config with
  | Some `Dhcp -> assert false (* we don't support this *)
  | Some (`Ip ip) -> ip
  | None -> vpn_gateway config

let ip_from_config config =
  let cidr = ifconfig config and gateway = route_gateway config in
  { cidr; gateway }

let server_ip config =
  let cidr = Config.get Server config in
  let network = Ipaddr.V4.Prefix.network cidr
  and ip = Ipaddr.V4.Prefix.address cidr in
  if not (Ipaddr.V4.compare ip network = 0) then (ip, cidr)
  else
    (* take first IP in subnet (unless server a.b.c.d/netmask) with a.b.c.d not being the network address *)
    let ip' = Ipaddr.V4.Prefix.first cidr in
    (ip', cidr)

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
  let pp_network_or_gateway ppf = function
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
