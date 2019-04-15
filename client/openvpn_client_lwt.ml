
open Lwt.Infix
open Openvpn

let rec write_to_fd fd data =
  if Cstruct.len data = 0 then
    Lwt_result.return ()
  else
    Lwt.catch (fun () ->
        Lwt_unix.write fd (Cstruct.to_bytes data) 0 (Cstruct.len data)
        >|= Cstruct.shift data >>= write_to_fd fd)
      (fun e ->
         Lwt_result.lift
           (Rresult.R.error_msgf "write error %s" (Printexc.to_string e)))

let maybe_write_to_fd fd = function
  | None -> Lwt_result.return ()
  | Some x -> write_to_fd fd x

let read_from_fd fd =
  Lwt_result.catch (
      let buf = Bytes.create 2048 in
      Lwt_unix.read fd buf 0 2048 >|= fun count ->
      let cs = Cstruct.of_bytes ~len:count buf in
      Logs.debug (fun m -> m "read %d bytes@.%a" count Cstruct.hexdump_pp cs) ;
      cs)
  |> Lwt_result.map_err (fun e ->
      Rresult.R.msgf "read error %s" (Printexc.to_string e))

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
    match
      let open Rresult.R.Infix in
      Openvpn_config.parse str >>= fun lines ->
      Openvpn_config.parse_gadt lines >>= fun config ->
      if Openvpn_config.is_valid_client_config config
      then Ok config else Error "invalid config"
    with
    | Error s -> Lwt.fail_with ("config parser: " ^ s)
    | Ok config ->
      begin match Openvpn_config.Conf_map.(get Remote config) with
        | (`IP ip, port) :: _ -> Lwt.return (ip, port)
        | (`Domain name, port) :: _ ->
          begin
            let res = Udns_client_lwt.create () in
            Udns_client_lwt.gethostbyname res name >>= function
            | Error `Msg x ->
              Logs.err (fun m -> m "gethostbyname for %a returned an error: %s"
                           Domain_name.pp name x) ;
              Lwt.fail_with "resolver error"
            | Ok ip -> Lwt.return (Ipaddr.V4 ip,port)
          end
        | [] -> Lwt.fail_with "no remote"
      end >>= fun (ip,port) ->
      Logs.info (fun m -> m "connecting to %a" Ipaddr.pp ip) ;
      begin match Engine.client config now () with
      | Error () -> Lwt.fail_with "couldn't init client"
      | Ok (state, out) ->
        let s = ref state
        and dom =
          Ipaddr.(Lwt_unix.(match ip with V4 _ -> PF_INET | V6 _ -> PF_INET6))
        and ip = Ipaddr_unix.to_inet_addr ip
        in
        let fd = Lwt_unix.(socket dom SOCK_STREAM 0) in
        Lwt_unix.(connect fd (ADDR_INET (ip, port))) >>= fun () ->
        let open Lwt_result in
        write_to_fd fd out >>= fun () ->
        let rec loop () =
          read_from_fd fd >>= fun b ->
          match Engine.(Rresult.R.error_to_msg ~pp_error (handle !s now b)) with
          | Error e -> fail e
          | Ok (s', out) -> s := s' ; maybe_write_to_fd fd out >>= loop
        in
        loop ()
      end
  ) (* <- Lwt_main.run *)

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let config =
  let doc = "Configuration file to use" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let cmd =
  Term.(term_result (const jump $ setup_log $ config)),
  Term.info "openvpn_client" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
