open Rresult

let read_config_file fn =
  Printf.printf "Reading %S\n" fn;
  let str =
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
