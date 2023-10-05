let () =
  let fd = Unix.openfile Sys.argv.(1) Unix.[ O_RDONLY ] 0 in
  let { Unix.st_size = len; _ } = Unix.fstat fd in
  let input =
    let buf = Bytes.create len in
    (* "best effort": *)
    let len = Unix.read fd buf 0 len in
    Bigstringaf.substring (Bytes.unsafe_to_string b) ~off:0 ~len
  in
  AflPersistent.run (fun () ->
      match Lzo.uncompress_with_buffer input with _ -> exit 0)
