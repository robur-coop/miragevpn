(* mirage >= 4.8.0 & < 4.9.0 *)

open Mirage

let miragevpn_handler =
  let packages =
    let pin = "git+file://" ^ Filename.dirname (Sys.getcwd ()) ^ "#HEAD" in
    [
      package "logs";
      package ~pin ~sublibs:[ "mirage" ] "miragevpn";
      package "dns";
      package "dns-client";
      package "mirage-kv";
      package "mirage-nat";
      package "tcpip" ~sublibs:[ "stack-direct" ];
    ]
  in
  main ~packages "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> network @-> ethernet @-> arpv4 @-> ipv6 @-> block @-> job)

let block =
  Key.(if_impl is_solo5 (block_of_file "storage") (block_of_file "disk.img"))

let eth = ethif default_network
let arp = arp eth
let ipv6 = create_ipv6 default_network eth
let () =
  register "ovpn-server"
    [
      miragevpn_handler $ default_random $ default_monotonic_clock
      $ default_posix_clock $ default_time
      $ default_network $ eth $ arp $ ipv6
      $ block;
    ]
