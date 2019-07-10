(*
LZO01X-1(15)
  algorithm category: 01
  algorithm type:      X
  compression level:   1
  memory level:       15
*)

module Logs = (val Logs.(src_log @@ Src.create
                           "ovpn.lzo") : Logs.LOG)

type copy_trailing =
  (* Other implementations call this 's' or 'state'.
     It controls how many literal characters trailing a copy_block instruction
     to copy into the output.
  *)
  | Trailing_zero | Trailing_one
  | Trailing_two  | Trailing_three | Trailing_no_extra

let int_of_copy_trailing = function
  | Trailing_zero | Trailing_no_extra -> 0
  | Trailing_one -> 1
  | Trailing_two -> 2
  | Trailing_three -> 3

let copy_trailing_of_int d =
  match d land 0b11 with
  | 0 -> Trailing_zero
  | 1 -> Trailing_one
  | 2 -> Trailing_two
  | 3 -> Trailing_three
  | _ -> failwith "can never happen; guarded by & 3"

type copy_block = int * int * copy_trailing
type copy_literal = int * copy_trailing

let [@inline always] count_zeroes f =
  (* This function looks for a continuous stream zero-bytes
     and returns when the first non-zero byte is encountered.
     It is used to code long lengths for copy operations. *)
  let rec do_count count =
    `Read_byte (function
        | 0 ->
          let count = succ count in
          do_count count
        | non_zero -> f (count * 255 + non_zero))
  in do_count 0

let decode_instruction (prev_state:copy_trailing) c =
  let b = int_of_char c in
  match c, prev_state with

  (* 00..15 == x00 - 0F *)
  (* Depends on the number of literals copied by the last instruction.*)

  (* If last instruction did not copy any literal (state == Trailing_zero), this
     encoding will be a copy of 4 or more literal: *)
  | '\001'..'\015', Trailing_zero ->
    `Copy_literal (3 + b, Trailing_no_extra)
  | '\000', Trailing_zero ->
    count_zeroes (fun count ->
        let length = 3 + 15 + count in
        `Copy_literal ((length, Trailing_no_extra) : copy_literal))

  | '\000'..'\015', (Trailing_one | Trailing_two | Trailing_three) ->
    (* Last instruction copied between 1-3 literals
       Instruction is a copy of a 2-byte block from the dict
       within a 1kB distance.*)
    let d, state  = b lsr 2 , copy_trailing_of_int b in
    `Read_byte (fun h ->
        let distance = (h lsl 2) + d + 1 in
        `Copy_block (2, distance, state))

  | '\000'..'\015', Trailing_no_extra ->
    (* a copy of a 3-byte block from the dictionary in the 2k..3k distance *)
    `Read_byte (fun h ->
        let state = copy_trailing_of_int b in
        let distance = (h lsl 2) + (b lsr 2) + 2049 in
        `Copy_block (3, distance, state))


  | '\016'..'\031', _ (* x10 - 1F *) ->
    (* x10-x17 followed by 0,(0|1|2|3) always terminate the stream*)
    (* Copy of a large block within 16kB..48kB distance *)
    let with_length length =
      `Read_le16 (fun ds ->
          let state = copy_trailing_of_int ds in
          let distance =
            let h = (b land 8) lsr 3 in
            16384 + (h lsl 14) + (ds lsr 2) in
          begin match distance with
            | 16384 ->
              `End_of_stream (* still need to copy *)
            (*| 0xBFFF (* 49151 *) (* TODO if v=V1*) ->
              ignore @@ failwith "version disambiguation";
              (* version 1 only: *)
              (* followed by fourth byte *)
              `Read_byte (fun x ->
                let run_length = ((x lsl 3) lor l) + 4 in
                `Zeroes_if_v1_only run_length)*)
            | _ ->
              `Copy_block ((length, distance, state) : copy_block)
          end)
    in
    let l = b land 0b111 in
    if l = 0
    then count_zeroes (fun l -> with_length (2 + 7 + l))
    else with_length (2 + l)


  | '\032'..'\063', _ (* x20 - 3F *)->
    (* copy of 0-64 bytes within 16kb distance *)
    let with_length length =
      `Read_le16 (fun x ->
          let distance = succ (x lsr 2)  in
          `Copy_block (length, distance, copy_trailing_of_int x))
    in
    let l = b land 0b11111 in
    if l = 0
    then count_zeroes (fun l -> with_length (2 + 31 + l))
    else with_length (2 + l)

  | '\064'..'\127', _ (* x40 - 7F *)->
    (* Copy 3-4 bytes from dict within 2kB distance*)
    let length, d =
      3 + ((b lsr 5) land 1), (* 3 + ((b >> 5) & 1) *)
      (b lsr 2) land 0b111 in (*      (b >> 2) & 7  *)
    `Read_byte (fun h ->
        let distance = (h lsl 3) + d + 1 in
        `Copy_block (length, distance,
                     copy_trailing_of_int b))

  | '\128'..'\255', _ (* x80 - FF *)->
    (* Copy 5-8 bytes from block within 2kB distance *)
    let length, d, state =
      5 + ((b lsr 5) land 0b11), (*  5 + ((b>>5) & 3) *)
      ((b lsr 2) land 0b111),    (*       (b>>2) & 7  *)
      copy_trailing_of_int b in
    `Read_byte (fun h ->
        let distance = (h lsl 3) + d + 1 in
        `Copy_block (length, distance, state))

let decompress (input:string) =
  let out = Buffer.create 1500 in
  Logs.debug (fun m -> m "LZO input is %d bytes: %S"
                 (String.length input) input);
  let open Rresult in
  let rec handle_instruction inp = function
    | `End_of_stream -> Ok (Buffer.contents out)

    | `Copy_literal (len, state) ->
      Buffer.add_substring out input inp len ;
      let inp = inp + len in
      handle_instruction (succ inp)
        (decode_instruction state input.[inp])

    | `Copy_block (length, distance, state) ->
      let rec loop off rem =
        let taken = min rem (Buffer.length out - off) in
        if taken < 0 || rem < 0
        then Error "LZO: taken < 0 || rem < 0"
        else if taken = 0 then begin
          if rem = 0 then Ok () else  Error "LZO: rem <> 0"
        end else begin
          Buffer.add_string out (Buffer.sub out off taken) ;
          loop (off+taken) (rem-taken) end
      in loop (Buffer.length out - distance) length >>= fun () ->
      let trailing = int_of_copy_trailing state in
      Buffer.add_substring out input (inp) (trailing) ;
      let inp = inp + trailing in
      handle_instruction (succ inp)
        (decode_instruction state input.[inp])

    | `Read_byte f ->
      handle_instruction (succ inp)
        (f (int_of_char input.[inp]))

    | `Read_le16 f ->
      let i16 = Char.(code input.[inp] + (code input.[inp+1] lsl 8)) in
      handle_instruction (inp+2) (f i16)
  in
  begin match input.[0] with
    | '\016' (* x10 *) -> Error "LZO: 0x10: No dict available on first byte"

    | '\000'..'\017' (* x00..0F..11 *) ->
      (* parse as regular instruction: *)
      Ok (decode_instruction Trailing_zero input.[0])

    (* special decoding of first byte: *)
    | '\018' (* x12 *) -> Ok (`Copy_literal (1, Trailing_zero))
    | '\019' (* x13 *) -> Ok (`Copy_literal (2, Trailing_zero))
    | '\020' (* x14 *) -> Ok (`Copy_literal (3, Trailing_zero))
    | '\021' (* x15 *) -> Ok (`Copy_literal (4, Trailing_zero))
    | '\022'..'\255' (* x16 - FF *)  as b ->
      let length = int_of_char b - 17 in (* 5.. 239 *)
      Ok (`Copy_literal (length, Trailing_no_extra))
  end >>= handle_instruction 1 |> R.reword_error (fun s -> `Msg s)
