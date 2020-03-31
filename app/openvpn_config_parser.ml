open Rresult
open Openvpn.Config

let read_config_file fn =
  let string_of_file ~dir filename =
    let file =
      if Filename.is_relative filename then
        Filename.concat dir filename
      else
        filename
    in
    try
      let fh = open_in file in
      let content = really_input_string fh (in_channel_length fh) in
      close_in_noerr fh ;
      Ok content
    with _ -> Rresult.R.error_msgf "Error reading file %S" file
  in
  let dir, filename = Filename.(dirname fn, basename fn) in
  let string_of_file = string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> parse_client ~string_of_file str
  | Error _ as e -> e

let () =
  if not !Sys.interactive then begin
    Fmt_tty.setup_std_outputs () ;
    Logs.set_reporter (Logs_fmt.reporter());
    Logs.set_level (Some Logs.Debug) ;
    let fn = Sys.argv.(1) in
    match read_config_file fn with
    | Ok rules ->
      Fmt.pr "@[<v>%a@]\n" pp rules ;
      Logs.info (fun m -> m "Read %d entries!"
                    (cardinal rules)) ;
      begin match
          parse_client ~string_of_file:(fun _fn -> assert false)
            (Fmt.strf "%a" pp rules) with
      | Error `Msg s->
        Logs.err (fun m ->m "self-test failed to parse: %s" s);
        exit 2
      | Ok dogfood when equal eq rules dogfood -> ()
      | Ok _ -> Logs.err (fun m -> m "self-test failed"); exit 1
      end
    | Error `Msg s -> Logs.err (fun m -> m "%s" s)
  end
