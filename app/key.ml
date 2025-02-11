open Miragevpn

let now = Ptime_clock.now
let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let catch ~exn fn = try fn () with v -> exn v

let pp_key_hum ppf key =
  let cs = Tls_crypt.Key.to_octets key in
  let cipher_key = String.sub cs 0 64 in
  let hmac = String.sub cs 64 64 in
  Fmt.pf ppf "Cipher Key: @[<hov>%a@]\n%!"
    (Hxd_string.pp Hxd.default)
    cipher_key;
  Fmt.pf ppf "HMAC Key:   @[<hov>%a@]\n%!" (Hxd_string.pp Hxd.default) hmac

let tls_crypt_v2_server_key =
  let open Cmdliner in
  let parser str =
    if Sys.file_exists str then
      In_channel.with_open_bin str @@ fun ic ->
      let lines = Seq.of_dispenser (fun () -> In_channel.input_line ic) in
      let* server_key = Tls_crypt.V2_server.load ~lines in
      Ok (str, server_key)
    else error_msgf "%s does not exist" str
  in
  let pp ppf (filename, _) = Fmt.string ppf filename in
  Arg.conv ~docv:"<filename>" (parser, pp)

module Tls_crypt_v2_core = struct
  let generate_client_key g metadata server_key filename =
    let client_key = Tls_crypt.generate ~g () in
    let wkc = Tls_crypt.Wrapped_key.wrap ~key:server_key client_key metadata in
    let seq = Tls_crypt.save_tls_crypt_v2_client client_key wkc in
    Bos.OS.File.write_lines filename (List.of_seq seq)

  let generate_client_key g metadata server_key filename =
    match generate_client_key g metadata server_key filename with
    | Ok () -> `Ok ()
    | Error (`Msg msg) -> `Error (false, Fmt.str "%s." msg)

  let generate_server_key g filename =
    let server_key = Tls_crypt.V2_server.generate ~g () in
    let seq = Tls_crypt.V2_server.save server_key in
    Bos.OS.File.write_lines filename (List.of_seq seq)

  let generate_server_key g filename =
    match generate_server_key g filename with
    | Ok () -> `Ok ()
    | Error (`Msg msg) -> `Error (false, Fmt.str "%s." msg)
end

let setup_random_number_generator = function
  | None ->
      Mirage_crypto_rng_unix.use_default ();
      Mirage_crypto_rng.default_generator ()
  | Some (_, time) ->
      let time () = Int64.of_float (Ptime.to_float_s (time ())) in
      let g = Mirage_crypto_rng.create ~time (module Mirage_crypto_rng.Fortuna) in
      Mirage_crypto_rng.set_default_generator g;
      Mirage_crypto_rng.default_generator ()

let timer_for_random_number_generator =
  let parser str =
    match (Ptime.of_rfc3339 str, str) with
    | _, "now" -> Ok (None, Ptime_clock.now)
    | Ok (ptime, _tz, _), _ ->
        (* TODO(dinosaure): handle correctly [tz]. *)
        if Ptime.compare ptime (Ptime_clock.now ()) <= 0 then
          let span = Ptime.to_span ptime in
          let time () = Option.get (Ptime.sub_span (Ptime_clock.now ()) span) in
          Ok (Some span, time)
        else error_msgf ""
    | Error (`Msg msg), _ -> Error (`Msg msg)
    | Error (`RFC3339 (_, err)), _ -> error_msgf "%a" Ptime.pp_rfc3339_error err
    | _, int -> (
        let exn _ = error_msgf "" in
        catch ~exn @@ fun () ->
        let span = Ptime.Span.of_int_s (int_of_string int) in
        match Ptime.sub_span (Ptime_clock.now ()) span with
        | Some _ ->
            let time () =
              Option.get (Ptime.sub_span (Ptime_clock.now ()) span)
            in
            Ok (Some span, time)
        | None -> error_msgf "")
  in
  let pp ppf (span, _) =
    match span with
    | None -> Fmt.string ppf "now"
    | Some span -> Fmt.pf ppf "<since:%f>" (Ptime.Span.to_float_s span)
  in
  let doc =
    {doc|A timer can be specified to modify the behavior of the random number
         generator. By default, it can use the current elapsed time or the time
         that has elapsed since a specific date. In the latter case, the numbers
         generated are reproducible.|doc}
  in
  let open Cmdliner in
  Arg.(value & opt (some (conv (parser, pp))) None & info [ "rng" ] ~doc)

let term_random_number_generator =
  let open Cmdliner in
  Term.(const setup_random_number_generator $ timer_for_random_number_generator)

let metadata =
  let parser str =
    match (String.split_on_char ':' str, Ptime.of_rfc3339 str) with
    | "user" :: str, _ -> (
        match Base64.decode (String.concat ":" str) with
        | Ok str -> Ok (Tls_crypt.Metadata.user str)
        | Error (`Msg _) -> error_msgf "Invalid base64 user metadata")
    | "timestamp" :: str, _ -> (
        let exn _ = error_msgf "" in
        catch ~exn @@ fun () ->
        match Ptime.of_float_s (Float.of_string (String.concat ":" str)) with
        | Some ptime -> Ok (Tls_crypt.Metadata.timestamp ptime)
        | None -> error_msgf "")
    | _, Ok (ptime, _tz, _) -> Ok (Tls_crypt.Metadata.timestamp ptime)
    | str, _ -> Ok (Tls_crypt.Metadata.user (String.concat ":" str))
  in
  let pp = Tls_crypt.Metadata.pp_hum in
  let open Cmdliner in
  Arg.conv (parser, pp)

type ty = Client | Server

let ty =
  let open Cmdliner in
  let server =
    let doc = "Generate a tls-crypt-v2 key for the server." in
    (Server, Arg.info [ "server" ] ~doc)
  in
  let client =
    let doc =
      "Generate a tls-crypt-v2 key for the client (it requires the server \
       key). A $(i,metadata) can be attached to the key. "
    in
    (Client, Arg.info [ "client" ] ~doc)
  in
  Arg.(value & vflag Server [ server; client ])

let genkey g ty metadata server_key filename =
  match (ty, server_key) with
  | Server, _ -> Tls_crypt_v2_core.generate_server_key g filename
  | Client, Some (_filename, server_key) ->
      Tls_crypt_v2_core.generate_client_key g metadata server_key filename
  | Client, None ->
      `Error (true, "The server key is required to generate a client key.")

let term_genkey =
  let open Cmdliner in
  let server_key =
    let doc = "A tls-crypt-v2 server key." in
    let docv = "<filename>" in
    Arg.(
      value
      & opt (some tls_crypt_v2_server_key) None
      & info [ "key"; "server-key" ] ~doc ~docv)
  in
  let metadata =
    let default = Tls_crypt.Metadata.timestamp (Ptime_clock.now ()) in
    let doc =
      "Metadata which can be attached to a $(i,client) tls-crypt-v2 key. The \
       format is: $(b,'user:<base64-encoded-string>'), \
       $(b,'timestamp:<unix-timestamp>') or $(b,'<rfc3339-timestamp>')."
    in
    Arg.(value & opt metadata default & info [ "metadata" ] ~doc)
  in
  let output =
    let fpath = Arg.conv (Fpath.of_string, Fpath.pp) in
    let doc = "The output file where the tls-crypt-v2 will be stored." in
    Arg.(
      required & pos ~rev:true 0 (some fpath) None & info [] ~doc ~docv:"OUTPUT")
  in
  Term.(
    const genkey $ term_random_number_generator $ ty $ metadata $ server_key
    $ output)

let cmd_genkey =
  let open Cmdliner in
  let doc = "A tool to generate tls-crypt-v2 keys." in
  let man =
    [
      `S Manpage.s_description;
      `P "$(tname) is a simple tool to generate tls-crypt-v2 keys.";
    ]
  in
  Cmd.v (Cmd.info "miragevpn.key" ~doc ~man) Term.(ret term_genkey)

let () =
  let open Cmdliner in
  Cmd.(exit @@ eval cmd_genkey)
