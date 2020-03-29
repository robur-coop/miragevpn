open Rresult
open Openvpn.Config

let read_config_file fn =
  let str fn =
    Logs.info (fun m -> m "Reading file %S" fn) ;
    let fd = try Unix.openfile fn [O_RDONLY] 0 with
      | Unix.Unix_error (Unix.ENOENT, "open", required_fn) ->
        Logs.err (fun m -> m "%S: Unable to open %S required"
                     fn required_fn);
        exit 1
    in
    let {Unix.st_size; _} = Unix.fstat fd in
    let buf = Bytes.create st_size in
    let rec loop remaining =
      let remaining =
        let read = Unix.read fd buf (st_size - remaining) remaining in
        remaining - read in
      if remaining = 0 then Unix.close fd else loop remaining
    in loop st_size ;
    Bytes.to_string buf
  in
  parse_server ~string_of_file:(fun fn -> Ok (str fn)) (str fn)


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
          parse_server ~string_of_file:(fun _fn -> assert false)
            (Fmt.strf "%a" pp rules) with
      | Error `Msg s->
        Logs.err (fun m ->m "self-test failed to parse: %s" s);
        exit 2
      | Ok dogfood when equal eq rules dogfood -> ()
      | Ok _ ->
        Logs.err (fun m -> m "self test failed"); exit 1 
      end
    | Error `Msg s -> Logs.err (fun m -> m "%s" s)
  end
