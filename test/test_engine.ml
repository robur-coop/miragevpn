let tests = [
  "Config_tests", Config_tests.tests ;
]

let () =
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter () ;
  Logs.(set_level @@ Some Debug);
  Alcotest.run "OpenVPN tests" tests
