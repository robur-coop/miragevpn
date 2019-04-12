open Rresult

let read_config_file fn =
  Printf.printf "Reading %S\n" fn;
  let {Unix.st_size; _} = Unix.stat fn in
  let buf = Bytes.create st_size in
  let fd = Unix.openfile fn [O_RDONLY] 0 in
  ignore @@ Unix.read fd buf 0 st_size ;
  let str = Bytes.to_string buf in
  Openvpn_config.parse str

let () =
  if not !Sys.interactive then
    let fn = Sys.argv.(1) in
    match read_config_file fn with
    | Ok rules ->
      List.iteri (fun i line ->
          Fmt.pr "Entry %d: @[<v>%a@]@." (i+1)
            Openvpn_config.pp_line line
        ) rules;
      Printf.printf "Read %d entries!\n" (List.length rules)
    | Error s -> Printf.printf "error: %s\n" s
