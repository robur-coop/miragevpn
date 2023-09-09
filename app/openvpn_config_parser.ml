open Rresult
open Miragevpn.Config

let read_config_file fn =
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
    with _ -> Rresult.R.error_msgf "Error reading file %S" file
  in
  let dir, filename = Filename.(dirname fn, basename fn) in
  let string_of_file = string_of_file ~dir in
  match string_of_file filename with
  | Ok str -> parse_client ~string_of_file str
  | Error _ as e -> e

let alignment_header =
  {|#############
# IMPORTANT:
#  This OpenVPN configuration file has been padded with the comment below to
#  ensure alignment on 512-byte boundaries for block device compatibility.
#  That is a requirement for the MirageOS unikernels.
#  If you modify it, please verify that the output of
#       wc -c THIS.FILE
#  is divisible by 512.
#############
|}

let pad_output output =
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
  let ideal_size =
    String.length alignment_header (* at beginning, before padding *)
    + String.length initial_padding (* between padding and config contents *)
    + String.length output
  in
  let padding_size = 512 - (ideal_size mod 512) in
  alignment_header ^ pad initial_padding padding_size ^ output

let () =
  (* Testing code for pad_output: *)
  (*for i = 0 to 5000 do
    assert (let res = pad_output (String.make i 'a') in
            0 = String.length res mod 512)
    done ; ignore (exit 0) ;
  *)
  if not !Sys.interactive then (
    Fmt_tty.setup_std_outputs ();
    Logs.set_reporter (Logs_fmt.reporter ());
    Logs.set_level (Some Logs.Debug);
    let fn = Sys.argv.(1) in
    match read_config_file fn with
    | Ok rules -> (
        let outbuf = Buffer.create 2048 in
        Fmt.pf (Format.formatter_of_buffer outbuf) "@[<v>%a@]\n%!" pp rules;
        Fmt.pr "%s%!" (pad_output (Buffer.contents outbuf));
        Logs.info (fun m -> m "Read %d entries!" (cardinal rules));
        (* The output was printed, now we generate a warning on stderr
         * if our self-testing fails: *)
        match
          parse_client
            ~string_of_file:(fun _fn -> assert false)
            (Buffer.contents outbuf)
        with
        | Error (`Msg s) ->
            Logs.err (fun m -> m "self-test failed to parse: %s" s);
            exit 2
        | Ok dogfood when equal eq rules dogfood -> ()
        | Ok _ ->
            Logs.err (fun m -> m "self-test failed");
            exit 1)
    | Error (`Msg s) -> Logs.err (fun m -> m "%s" s))
