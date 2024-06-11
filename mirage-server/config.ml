open Mirage

let data_key = Key.(value @@ kv_ro ~group:"data" ())
let data = generic_kv_ro ~key:data_key "configuration"

let miragevpn_handler =
  let packages =
    let pin = "git+https://github.com/robur-coop/miragevpn.git" in
    [
      package "logs";
      package ~pin ~sublibs:[ "mirage" ] "miragevpn";
      package "dns";
      package "dns-client";
      package "mirage-kv";
      package "mirage-nat";
      package "tcpip" ~sublibs:[ "stack-direct" ];
    ]
  and runtime_args = [
    runtime_arg ~pos:__POS__ "Unikernel.K.ipv4";
    runtime_arg ~pos:__POS__ "Unikernel.K.ipv4_gateway";
    runtime_arg ~pos:__POS__ "Unikernel.K.ipv4_only";
    runtime_arg ~pos:__POS__ "Unikernel.K.ipv6_only";
    runtime_arg ~pos:__POS__ "Unikernel.K.nat_table_size";
  ] in
  main ~runtime_args ~packages "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> network @-> ethernet @-> arpv4 @-> ipv6 @-> kv_ro @-> job)

let eth = etif default_network
let arp = arp eth
let ipv6 = create_ipv6 default_network eth
let () =
  register "ovpn-server"
    [
      miragevpn_handler $ default_random $ default_monotonic_clock
      $ default_posix_clock $ default_time
      $ default_network $ eth $ arp $ ipv6
      $ data;
    ]
