let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let parse_noextern_client conf =
  Miragevpn.Config.parse_client
    ~string_of_file:(fun path ->
      error_msgf
        "this test suite does not read external files, but a config asked for: \
         %S"
        path)
    conf

let crowbar_fuzz_config () =
  Crowbar.add_test ~name:"Fuzzing doesn't crash Config.parse_client"
    [ Crowbar.bytes ] (fun s ->
      try
        Crowbar.check
          (ignore @@ parse_noextern_client s;
           true)
      with _ -> Crowbar.bad_test ())

let tests = [ ("crowbar fuzzing", `Slow, crowbar_fuzz_config) ]
let tests = [ ("Crowbar tests", tests) ]

let () =
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter ();
  Logs.(set_level @@ Some Debug);
  Alcotest.run "Crowbar tests" tests
