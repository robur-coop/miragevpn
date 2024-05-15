type cc_message = [ `Cc_restart | `Cc_halt | `Cc_exit ]

(* OpenVPN is sloppy in its parsing and considers it a valid message if the
   message just starts with {EXIT,HALT,RESTART}. We will not be as sloppy in
   our parsing. *)
let parse = function
  | "EXIT\000" -> Some `Cc_exit
  | "HALT\000" -> Some `Cc_halt
  | "RESTART\000" -> Some `Cc_restart
  | msg ->
      if String.starts_with msg ~prefix:"RESTART," then
        (* Ignoring message *)
        Some `Cc_restart
      else if String.starts_with msg ~prefix:"HALT," then
        (* Ignoring message *)
        Some `Cc_halt
      else None

let to_string = function
  | `Cc_restart -> "RESTART\000"
  | `Cc_halt -> "HALT\000"
  | `Cc_exit -> "EXIT\000"

let pp ppf = function
  | `Cc_restart -> Fmt.string ppf "restart"
  | `Cc_halt -> Fmt.string ppf "halt"
  | `Cc_exit -> Fmt.string ppf "exit"
