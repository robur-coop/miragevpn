
open Lwt.Infix

let rec write_to_fd fd data =
  if Cstruct.len data = 0 then
    Lwt.return_unit
  else
    Lwt_unix.write fd (Cstruct.to_bytes data) 0 (Cstruct.len data) >>= fun written ->
    write_to_fd fd (Cstruct.shift data written)

let read_from_fd fd =
  let buf = Bytes.create 2048 in
  Lwt_unix.read fd buf 0 2048 >|= fun count ->
  let cs = Cstruct.of_bytes ~len:count buf in
  Logs.debug (fun m -> m "read %d bytes@.%a" count Cstruct.hexdump_pp cs) ;
  cs

let now () = Ptime_clock.now ()

let jump _ ip port =
  Lwt_main.run (
    let state, out = Openvpn.Engine.client now () in
    let s = ref state in
    let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
    Lwt_unix.connect fd (Lwt_unix.ADDR_INET (Ipaddr_unix.V4.to_inet_addr ip, port)) >>= fun () ->
    write_to_fd fd out >>= fun () ->
    read_from_fd fd >|= fun data ->
    Openvpn.Engine.handle !s now data) ;
  `Ok ()


let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let ip_c : Ipaddr.V4.t Arg.converter =
  let parse s =
      try
        `Ok (Ipaddr.V4.of_string_exn s)
      with
        Not_found -> `Error "failed to parse IP address"
  in
  parse, Ipaddr.V4.pp

let ip_address =
  let doc = "IP address to connect to" in
  Arg.(required & pos 0 (some ip_c) None & info [] ~doc ~docv:"IP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 1194 & info [ "port" ] ~doc ~docv:"PORT")

let cmd =
  Term.(ret (const jump $ setup_log $ ip_address $ port)),
  Term.info "openvpn_client" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
