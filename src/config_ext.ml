type ip_config = { cidr : Ipaddr.V4.Prefix.t; gateway : Ipaddr.V4.t }

let pp_ip_config ppf { cidr; gateway } =
  Fmt.pf ppf "ip %a gateway %a" Ipaddr.V4.Prefix.pp cidr Ipaddr.V4.pp gateway

let ip_from_config config =
  match Config.(get Ifconfig config, get Route_gateway config) with
  | (V4 address, V4 netmask), `Ip (V4 gateway) ->
      let cidr = Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address in
      { cidr; gateway }
  | _ -> assert false

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
