(* mirage >= 4.6.0 & < 4.7.0 *)

open Mirage

let private_netif = netif ~group:"private" "private"
let private_ethernet = ethif private_netif
let private_arp = arp private_ethernet
(* this is temporary until we find a better way *)
let ip = Runtime_arg.V4.network ~group:"private" (Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24")
let private_ipv4 = create_ipv4 ~group:"private" private_ethernet private_arp

let nat = runtime_arg ~pos:__POS__ "Unikernel.K.nat"
let nat_table_size = runtime_arg ~pos:__POS__ "Unikernel.K.nat_table_size"

let miragevpn_handler =
  let packages =
    let pin = "git+https://github.com/robur-coop/miragevpn.git" in
    [
      package "logs";
      package ~pin ~sublibs:[ "mirage" ] "miragevpn";
      package "mirage-kv";
      package ~min:"3.0.0" "mirage-nat";
    ]
  and runtime_args = [ Runtime_arg.v ip ; nat ; nat_table_size ]
  in
  main ~runtime_args ~packages "Unikernel.Main"
    (random @-> mclock @-> pclock @-> time @-> stackv4v6 @-> network
   @-> ethernet @-> arpv4 @-> ipv4 @-> block @-> job)

let block =
  Key.(if_impl is_solo5 (block_of_file "storage") (block_of_file "disk.img"))

let stack = generic_stackv4v6 default_network

let enable_monitoring =
  let doc = Key.Arg.info
      ~doc:"Enable monitoring (syslog, metrics to influx, log level, statmemprof tracing)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"management"
       (netif ~group:"management" "management"))
    stack

let name =
  runtime_arg ~pos:__POS__
    {|let doc = Cmdliner.Arg.info ~doc:"Name of the unikernel"
        ~docs:Mirage_runtime.s_log [ "name" ]
      in
      Cmdliner.Arg.(value & opt string "a.ns.robur.coop" doc)|}

let monitoring =
  let monitor = Runtime_arg.(v (monitor None)) in
  let connect _ modname = function
    | [ _ ; _ ; stack ; name ; monitor ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
         | Some ip -> %s.create ip ~hostname:%s %s)"
        monitor modname name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~runtime_args:[ name ; monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_arg.(v (syslog None)) in
  let connect _ modname = function
    | [ _ ; stack ; name ; syslog ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
         | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%s ()))"
        syslog modname stack name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.4.0" "logs-syslog" ]
    ~runtime_args:[ name ; syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)

let optional_monitoring time pclock stack =
  if_impl
    (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    noop

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring) (syslog $ pclock $ stack) noop

let () =
  register "ovpn-router"
    [
      optional_syslog default_posix_clock management_stack;
      optional_monitoring default_time default_posix_clock management_stack;
      miragevpn_handler $ default_random $ default_monotonic_clock
      $ default_posix_clock $ default_time $ stack $ private_netif
      $ private_ethernet $ private_arp $ private_ipv4 $ block;
    ]
