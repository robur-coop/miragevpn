
open Lwt.Infix
open Openvpn

let rec write_to_fd fd data =
  if Cstruct.len data = 0 then
    Lwt.return (Ok ())
  else
    Lwt.catch (fun () ->
        Lwt_unix.write fd (Cstruct.to_bytes data) 0 (Cstruct.len data) >>= fun written ->
        write_to_fd fd (Cstruct.shift data written))
      (fun e ->
         Lwt.return (Error (`Msg (Fmt.strf "write error %s" (Printexc.to_string e)))))

let maybe_write_to_fd fd = function
  | None -> Lwt.return (Ok ())
  | Some x -> write_to_fd fd x

let read_from_fd fd =
  Lwt.catch (fun () ->
      let buf = Bytes.create 2048 in
      Lwt_unix.read fd buf 0 2048 >|= fun count ->
      let cs = Cstruct.of_bytes ~len:count buf in
      Logs.debug (fun m -> m "read %d bytes@.%a" count Cstruct.hexdump_pp cs) ;
      Ok cs)
    (fun e -> Lwt.return (Error (`Msg (Fmt.strf "read error %s" (Printexc.to_string e)))))

let now () = Ptime_clock.now ()

let read_file filename =
  Lwt_unix.stat filename >>= fun stats ->
  let buf = Bytes.create stats.Lwt_unix.st_size in
  Lwt_unix.openfile filename [O_RDONLY] 0 >>= fun fd ->
  let rec read_full ?(off = 0) size =
    if size - off = 0 then
      Lwt.return_unit
    else
      Lwt_unix.read fd buf off (size - off) >>= fun read ->
      read_full ~off:(off + read) size
  in
  read_full stats.Lwt_unix.st_size >>= fun () ->
  Lwt_unix.close fd >|= fun () ->
  Bytes.unsafe_to_string buf

let jump _ filename =
  Lwt_main.run (
    read_file filename >>= fun str ->
    match Openvpn_config.parse str with
    | Error s -> Logs.err (fun m -> m "error: %s" s) ; Lwt.fail_with "config parser"
    | Ok cfg ->
      match State.retrieve_host cfg with
      | Error () ->
        Logs.err (fun m -> m "couldn't find remote in config %s" str) ;
        Lwt.fail_with "couldn't find remote in config"
      | Ok (name, port) ->
        let res = Udns_client_lwt.create () in
        Udns_client_lwt.gethostbyname res (Domain_name.of_string_exn name) >>= function
        | Error _ ->
          Logs.err (fun m -> m "gethostbyname for %s returned an error" name) ;
          Lwt.fail_with "resolver error"
        | Ok ip ->
          Logs.info (fun m -> m "connecting to %a" Ipaddr.V4.pp ip) ;
          match Engine.client cfg now () with
          | Error () -> Lwt.fail_with "couldn't init client"
          | Ok (state, out) ->
            let s = ref state in
            let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
            Lwt_unix.connect fd (Lwt_unix.ADDR_INET (Ipaddr_unix.V4.to_inet_addr ip, port)) >>= fun () ->
            write_to_fd fd out >>= function
            | Error e -> Lwt.return (Error e)
            | Ok () -> read_from_fd fd >>= function
              | Error e -> Lwt.return (Error e)
              | Ok data -> match Engine.handle !s now data with
                | Error e -> Lwt.return (Error (`Msg (Fmt.strf "error %a" Engine.pp_error e)))
                | Ok (s', out) -> s := s' ; maybe_write_to_fd fd out)

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

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let cmd =
  Term.(term_result (const jump $ setup_log $ config)),
  Term.info "openvpn_client" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
