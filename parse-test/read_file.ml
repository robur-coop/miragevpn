open Rresult
open Openvpn_config

let read_config_file fn =
  let str fn =
    Printf.printf "Reading file %S\n" fn;
    let fd = Unix.openfile fn [O_RDONLY] 0 in
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
  parse ~string_of_file:(fun fn -> Ok (str fn)) (str fn)

let () =
  if not !Sys.interactive then
    Logs.set_reporter (Logs_fmt.reporter()); (* TODO colors? *)
    let fn = Sys.argv.(1) in
    match read_config_file fn with
    | Ok rules ->
      Fmt.pr "  @[<v>%a]" Conf_map.pp rules ;
      Printf.printf "Read %d entries!\n"
        (Conf_map.cardinal rules)
    | Error s -> Printf.printf "error: %s\n" s
