let tests = [
  "Config_tests", Config_tests.tests ;
]

let () = Alcotest.run "OpenVPN tests" tests
