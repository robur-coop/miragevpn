open Mirage

let data_key = Key.(value @@ kv_ro ~group:"data" ())
let data = generic_kv_ro ~key:data_key "configuration"

let openvpn_handler =
  let packages =
    let pin = "git+https://github.com/roburio/openvpn.git" in
    [
      package "logs" ;
      package ~pin ~sublibs:["mirage"] "openvpn";
      package "mirage-kv";
    ]
  in
  foreign
    ~packages
    "Unikernel.Main" (random @-> mclock @-> pclock @-> time @-> stackv4 @-> kv_ro @-> job)

let () =
  register "ovpn-client" [openvpn_handler $ default_random $ default_monotonic_clock $ default_posix_clock $ default_time $ generic_stackv4 default_network $ data ]
