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
    ]
  in
  foreign ~packages "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> stackv4v6 @-> kv_ro @-> job)

let () =
  register "ovpn-server"
    [
      miragevpn_handler $ default_random $ default_monotonic_clock
      $ default_posix_clock $ default_time
      $ generic_stackv4v6 default_network
      $ data;
    ]
