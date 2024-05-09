(* mirage >= 4.5.0 & < 4.6.0 *)

open Mirage

let data_key = Key.(value @@ kv_ro ~group:"data" ())
let data = generic_kv_ro ~key:data_key "configuration"
let private_netif = netif ~group:"private" "private"
let private_ethernet = etif private_netif
let private_arp = arp private_ethernet
(* this is temporary until we find a better way *)
let ip = Runtime_arg.V4.network ~group:"private" (Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24")
let private_ipv4 = create_ipv4 ~group:"private" private_ethernet private_arp

let miragevpn_handler =
  let packages =
    let pin = "git+https://github.com/robur-coop/miragevpn.git" in
    [
      package "logs";
      package ~pin ~sublibs:[ "mirage" ] "miragevpn";
      package "mirage-kv";
      package ~min:"3.0.0" "mirage-nat";
      package ~min:"3.8.0" "mirage-runtime";
    ]
  and runtime_args = [ Runtime_arg.v ip ]
  in
  main ~runtime_args ~packages "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> stackv4v6 @-> network
   @-> ethernet @-> arpv4 @-> ipv4 @-> kv_ro @-> job)

let () =
  register "ovpn-nat"
    [
      miragevpn_handler $ default_random $ default_monotonic_clock
      $ default_posix_clock $ default_time
      $ generic_stackv4v6 default_network
      $ private_netif $ private_ethernet $ private_arp $ private_ipv4 $ data;
    ]
