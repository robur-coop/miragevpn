open Lwt.Syntax

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let safe_close fd =
  Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

let write_to_fd fd data =
  let len = String.length data in
  let rec w fd data off =
    if len = off then Lwt_result.return ()
    else
      let* len =
        Lwt_unix.write fd (Bytes.unsafe_of_string data) off (len - off)
      in
      w fd data (len + off)
  in
  Lwt.catch
    (fun () -> w fd data 0)
    (fun e ->
      let+ () = safe_close fd in
      Error (`Msg (Fmt.str "TCP write error %a" Fmt.exn e)))

let read_from_fd fd =
  let open Lwt.Infix in
  Lwt_result.catch (fun () ->
      let bufsize = 2048 in
      let buf = Bytes.create bufsize in
      Lwt_unix.read fd buf 0 bufsize >>= fun count ->
      if count = 0 then failwith "end of file from server"
      else Logs.debug (fun m -> m "read %d bytes" count);
      Lwt.return (Bytes.sub_string buf 0 count))
  |> Lwt_result.map_error (fun e -> `Msg (Printexc.to_string e))

let transmit proto fd data =
  match proto with
  | `Tcp -> write_to_fd fd data
  | `Udp -> (
      let* r =
        Lwt_result.catch (fun () ->
            Lwt_unix.write fd
              (Bytes.unsafe_of_string data)
              0 (String.length data))
      in
      match r with
      | Ok len when String.length data <> len ->
          Lwt_result.fail (`Msg "wrote short UDP packet")
      | Ok _ -> Lwt_result.return ()
      | Error exn ->
          let+ () = safe_close fd in
          Error (`Msg (Fmt.str "UDP write error %a" Fmt.exn exn)))

let receive proto fd =
  let buf = Bytes.create 2048 in
  let* r =
    Lwt_result.catch (fun () ->
        Lwt_unix.recvfrom fd buf 0 (Bytes.length buf) [])
  in
  match (r, proto) with
  | Ok (0, _), `Tcp ->
      Logs.debug (fun m -> m "received end of file");
      let* () = safe_close fd in
      Lwt.return `Connection_failed
  | Ok (len, _), _ ->
      Logs.debug (fun m -> m "received %d bytes" len);
      Lwt.return (`Data (Bytes.sub_string buf 0 len))
  | Error exn, _ ->
      let* () = safe_close fd in
      (* XXX: emit `Connection_failed?! *)
      Logs.err (fun m -> m "Receive error %a" Fmt.exn exn);
      exit 3

let write_udp fd data =
  let open Lwt.Infix in
  Lwt.catch
    (fun () ->
      let len = String.length data in
      Lwt_unix.send fd (Bytes.unsafe_of_string data) 0 len [] >|= fun sent ->
      if sent <> len then
        Logs.warn (fun m ->
            m "UDP short write (length %d, written %d)" len sent);
      Ok ())
    (fun e ->
      safe_close fd >>= fun () ->
      Lwt_result.lift (error_msgf "UDP write error %s" (Printexc.to_string e)))

let read_udp =
  let open Lwt.Infix in
  let bufsize = 65535 in
  let buf = Bytes.create bufsize in
  fun fd ->
    Lwt_result.catch (fun () ->
        Lwt_unix.recvfrom fd buf 0 bufsize [] >>= fun (count, _sa) ->
        Logs.debug (fun m -> m "read %d bytes" count);
        Lwt.return (Some (Bytes.sub_string buf 0 count)))
    |> Lwt_result.map_error (fun e -> `Msg (Printexc.to_string e))

let string_of_file ~dir filename =
  let file =
    if Filename.is_relative filename then Filename.concat dir filename
    else filename
  in
  try
    let fh = open_in file in
    let content = really_input_string fh (in_channel_length fh) in
    close_in_noerr fh;
    Ok content
  with _ -> error_msgf "Error reading file %S" file

let reporter_with_ts ~dst () =
  let pp_tags f tags =
    let pp tag () =
      let (Logs.Tag.V (def, value)) = tag in
      Format.fprintf f " %s=%a" (Logs.Tag.name def) (Logs.Tag.printer def) value;
      ()
    in
    Logs.Tag.fold pp tags ()
  in
  let report src level ~over k msgf =
    let tz_offset_s = Ptime_clock.current_tz_offset_s () in
    let posix_time = Ptime_clock.now () in
    let src = Logs.Src.name src in
    let k _ =
      over ();
      k ()
    in
    msgf @@ fun ?header ?tags fmt ->
    Format.kfprintf k dst
      ("%a:%a %a [%s] @[" ^^ fmt ^^ "@]@.")
      (Ptime.pp_rfc3339 ?tz_offset_s ())
      posix_time
      Fmt.(option ~none:(any "") pp_tags)
      tags Logs_fmt.pp_header (level, header) src
  in
  { Logs.report }

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (reporter_with_ts ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log $ Fmt_cli.style_renderer () $ Logs_cli.level ())
