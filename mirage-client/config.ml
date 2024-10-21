(* mirage >= 4.7.0 & < 4.9.0 *)

open Mirage

let data_key = Key.(value @@ kv_ro ~group:"data" ())
let data = generic_kv_ro ~key:data_key "configuration"

let miragevpn_handler =
  let packages =
    let pin = "git+file://" ^ Filename.dirname (Sys.getcwd ()) in
    [
      package "logs";
      package ~pin ~sublibs:[ "mirage" ] "miragevpn";
      package "mirage-kv";
    ]
  in
  main ~packages "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> stackv4v6 @-> kv_ro @-> job)

let () =
  register "ovpn-client"
    [
      miragevpn_handler $ default_random $ default_monotonic_clock
      $ default_posix_clock $ default_time
      $ generic_stackv4v6 default_network
      $ data;
    ]
