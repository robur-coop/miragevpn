let () =
  let fd = Unix.openfile Sys.argv.(1) Unix.[ O_RDONLY ] 0 in
  let { Unix.st_size = len; _ } = Unix.fstat fd in
  let input =
    let b = Bytes.create len in
    (* "best effort": *)
    Bytes.sub_string b 0 (Unix.read fd b 0 len)
  in
  AflPersistent.run (fun () ->
      ignore
      @@ Miragevpn.Config.parse_client
           ~string_of_file:(fun _path -> Rresult.R.error_msg "")
           input)
