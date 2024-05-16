type cc_message =
  [ `Cc_restart of string option | `Cc_halt of string option | `Cc_exit ]

(* OpenVPN is sloppy in its parsing and considers it a valid message if the
   message just starts with {EXIT,HALT,RESTART}. We will not be as sloppy in
   our parsing. *)
let parse = function
  | "EXIT\000" -> Some `Cc_exit
  | "HALT\000" -> Some (`Cc_halt None)
  | "RESTART\000" -> Some (`Cc_restart None)
  | msg ->
      let get_message ~prefix msg =
        let idx_start = String.length prefix in
        let idx_end =
          String.index_from_opt msg idx_start '\000'
          |> Option.value ~default:(String.length msg)
        in
        String.sub msg idx_start (idx_end - idx_start)
      in
      if String.starts_with msg ~prefix:"RESTART," then
        (* NOTE: For now we don't parse flags *)
        let msg = get_message ~prefix:"RESTART," msg in
        Some (`Cc_restart (Some msg))
      else if String.starts_with msg ~prefix:"HALT," then
        let msg = get_message ~prefix:"HALT," msg in
        Some (`Cc_halt (Some msg))
      else None

let to_string = function
  | `Cc_restart None -> "RESTART\000"
  | `Cc_halt None -> "HALT\000"
  | `Cc_restart (Some msg) -> "RESTART," ^ msg "\000"
  | `Cc_halt (Some msg) -> "HALT," ^ msg ^ "\000"
  | `Cc_exit -> "EXIT\000"

let pp ppf = function
  | `Cc_restart None -> Fmt.string ppf "restart"
  | `Cc_halt None -> Fmt.string ppf "halt"
  | `Cc_restart (Some msg) -> Fmt.pf ppf "restart(%S)" msg
  | `Cc_halt (Some msg) -> Fmt.pf ppf "halt(%S)" msg
  | `Cc_exit -> Fmt.string ppf "exit"
