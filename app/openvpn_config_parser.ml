open Miragevpn.Config

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let read_config_file fn parse =
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
  in
  let dir, filename = Filename.(dirname fn, basename fn) in
  let string_of_file = string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> parse ~string_of_file str
  | Error _ as e -> e

let alignment_header block_size =
  Printf.sprintf
    {|#############
# IMPORTANT:
#  This OpenVPN configuration file has been padded with the comment below to
#  ensure alignment on %u-byte boundaries for block device compatibility.
#  That is a requirement for the MirageOS unikernels.
#  If you modify it, please verify that the output of
#       wc -c THIS.FILE
#  is divisible by %u.
#############
|}
    block_size block_size

let pad_output block_size output =
  let rec pad acc = function
    | 0 -> acc
    | n ->
        let chunk = min n 77 in
        let next =
          "\n" (* subtract length of this (= 1) below: *)
          ^ String.make (chunk - 1) '#'
          ^ acc
        in
        pad next (n - chunk)
  in
  let initial_padding = "\n\n" in
  let alignment_header = alignment_header block_size in
  let ideal_size =
    String.length alignment_header (* at beginning, before padding *)
    + String.length initial_padding (* between padding and config contents *)
    + String.length output
  in
  let padding_size = block_size - (ideal_size mod block_size) in
  alignment_header ^ pad initial_padding padding_size ^ output

let jump () file mode block_size =
  let parse =
    match mode with `Client -> parse_client | `Server -> parse_server
  in
  match read_config_file file parse with
  | Ok rules -> (
      let outbuf = Buffer.create 2048 in
      Fmt.pf (Format.formatter_of_buffer outbuf) "@[<v>%a@]\n%!" pp rules;
      Fmt.pr "%s%!" (pad_output block_size (Buffer.contents outbuf));
      Logs.info (fun m -> m "Read %d entries!" (cardinal rules));
      (* The output was printed, now we generate a warning on stderr
       * if our self-testing fails: *)
      match
        parse ~string_of_file:(fun _fn -> assert false) (Buffer.contents outbuf)
      with
      | Error (`Msg s) ->
          Logs.err (fun m -> m "self-test failed to parse: %s" s);
          exit 2
      | Ok dogfood when equal eq rules dogfood -> ()
      | Ok _ ->
          Logs.err (fun m -> m "self-test failed");
          exit 1)
  | Error (`Msg s) -> Logs.err (fun m -> m "%s" s)

let setup_log style_renderer level =
  (* have to duplicate this because we need err_formatter *)
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Common.reporter_with_ts ~dst:Format.err_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log $ Fmt_cli.style_renderer () $ Logs_cli.level ())

let config =
  let doc = "Configuration file to parse" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"CONFIG")

let server =
  let doc = "The configuration is for a server" in
  Arg.(value & flag & info [ "server" ] ~doc)

let client =
  let doc =
    "The configuration is for a client - this is the default unless --server \
     is passed"
  in
  Arg.(value & flag & info [ "client" ] ~doc)

let mode =
  let f client server =
    match (client, server) with
    | true, true ->
        Printf.eprintf "Can't check both --server and --client\n%!";
        exit Cmd.Exit.cli_error
    | false, true -> `Server
    | (false | true), false -> `Client
  in
  Term.(const f $ client $ server)

let block_size =
  let pos_int =
    let ( let* ) = Result.bind in
    let parse s =
      let* v = Arg.(conv_parser int) s in
      if v <= 0 then Error (`Msg "Non-positive integer") else Ok v
    and print = Arg.(conv_printer int) in
    Arg.conv (parse, print) ~docv:"POSINT"
  in
  let doc = "The block size to align against" in
  Arg.(value & opt pos_int 512 & info [ "block-size" ] ~doc ~docv:"BLOCKSIZE")

let cmd =
  let term = Term.(const jump $ setup_log $ config $ mode $ block_size)
  and info = Cmd.info "openvpn-config-parser" ~version:"%%VERSION_NUM" in
  Cmd.v info term

let () = if not !Sys.interactive then exit (Cmd.eval cmd)
