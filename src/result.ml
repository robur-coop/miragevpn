include Stdlib.Result

let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Syntax = struct
  let ( let* ) = bind
  let ( let+ ) x f = map f x
end
