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
let routes config : (Ipaddr.V4.Prefix.t * Ipaddr.V4.t * int) list =
  let default_gateway = route_gateway config
  and default_metric = route_metric config in
  let resolve_network_or_gateway = function
    | `Ip ip -> ip
    | `Net_gateway -> assert false
    | `Vpn_gateway -> vpn_gateway config
    | `Remote_host -> assert false
  in
  let default_route =
    match Config.find Redirect_gateway config with
    | None -> []
    | Some [] -> [ (Ipaddr.V4.Prefix.global, default_gateway, default_metric) ]
    | Some (`Def1 :: (_ : [ `Def1 ] list)) ->
        [
          ( Ipaddr.V4.Prefix.of_string_exn "0.0.0.0/1",
            default_gateway,
            default_metric );
          ( Ipaddr.V4.Prefix.of_string_exn "128.0.0.0/1",
            default_gateway,
            default_metric );
        ]
  in
  let routes =
    Config.find Route config |> Option.value ~default:[]
    |> List.map (fun (network, netmask, gateway, metric) ->
           let network = resolve_network_or_gateway network in
           let netmask = Option.value netmask ~default:Ipaddr.V4.broadcast in
           let gateway =
             match gateway with
             | Some gateway -> resolve_network_or_gateway gateway
             | None -> default_gateway
           in
           let metric = Option.value ~default:0 metric in
           let prefix =
             Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address:network
           in
           (prefix, gateway, metric))
  in
  routes @ default_route
