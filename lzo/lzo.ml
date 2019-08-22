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

(* While there are only two instructions in LZO, there are five possible
    effects of reading an instruction byte. This type definition covers those.
   Below each instruction the invariants to be proven before it can be safely
    executed are documented.
   For any instruction it must additionally be ensured that the string
    representation of your programming language permits allocating strings
   large enough to hold the output. LZO's maximum compression ratio is roughly
   255x the number of zeroes decoded in the count_zeroes function + 319.
   The variables are to be observed after the
    instruction decoding with the [inp] pointer initialized to point at the byte
   (following the instruction and any operands decoded so far): *)
type instruction =
  | Copy_literal of int * copy_trailing (* literal run from input *)
  (* Invariants:
     - len >= 1: nothing will construct this with 0 or negative len
     - inp + len < String.length input
     - TODO unclear if Copy_literal should preserve the trailing or reset it
     - TODO also unclear if Copy_literal should actually copy trailing stuff.
     - TODO seems like we only use Copy_literal no_extra and Copy_literal zero
  *)

  | Copy_block of int * int * copy_trailing (* looped run from dictionary *)
  (* Invariants:
     - length >= 2: nothing will construct with len less than 2.
     - distance > 0: or read past dictionary bounds
     - dictionary_size >= distance: or read past dictionary bounds
       (in this implementation dictionary_size = Buffer.length out)
     - String.length input - inp >= (int_of_copy_trailing state)
       (where [inp] is a pointer into [input])
  *)

  | End_of_stream (* finished *)
    (* Depending on your implementation you may want to return an error if
       [inp] < String.length input
    *)

  | Read_byte of (int -> (instruction, string) result) (* read extra operand *)
  (* Invariants:
     - inp +1  < String.length input
       (a single-byte operand will never result in End_of_stream, so you will
        need the byte at [inp] and the one following it, the next instruction)
  *)

  | Read_le16 of (int -> instruction) (* read extra operand *)
  (* Invariants:
     - inp + 1 < String.length input
     (in the case where End_of_stream, otherwise inp + 2)
  *)

let [@inline always] count_zeroes f =
  (* This function looks for a continuous stream zero-bytes
     and returns when the first non-zero byte is encountered.
     It is used to code long lengths for copy operations. *)
  (* There are four things to ensure here:
     1) in a valid literal run, the resulting number MUST be smaller than
        or equal to the total length of the input string minus 5:
        - (at least) 1 for this current instruction
        - (at least) 1 for this stream of operands
        - 3 for the End_of_stream marker
     2) the resulting number must be smaller than the remaining input stream
        minus 3 (for the End_of_stream marker).
     3) the calculation of the resulting number MUST NOT incur overflows:
     The largest number that gets add to this is from the
     \032..\063 Copy_block instruction, where it can add:
     2+31+31 = 32 + 32 = 64 bytes to the length.
     This means we must ensure that calculating
     64 + count*255 + non_zero does not overflow.
     This of course also implies that [count] itself MUST not overflow.
     The maximum value of non_zero + 64 is 255 + 64 = non_zero + 319
     The largest positive integer representable in OCaml is (2**30)-1,
     ie 1073741823.
     So to find the maximum number of non_zero octets we can read without
     overflowing: floor ((1073741823 - 319) / 255) = 4210750
  *)
  let rec do_count count =
    if count >= 4210750
    then Error "LZO: count_zeroes literal length would overflow"
    else
      Ok (Read_byte (function
          | 0 ->
            let count = succ count in
            do_count count
          | non_zero -> Ok (f (count * 255 + non_zero))))
  in do_count 0

let decode_instruction (prev_state:copy_trailing) c =
  let b = int_of_char c in
  match c, prev_state with

  (* 00..15 == x00 - 0F *)
  (* Depends on the number of literals copied by the last instruction.*)

  (* If last instruction did not copy any literal (state == Trailing_zero), this
     encoding will be a copy of (3+1) or more literal: *)
  | '\001'..'\015', Trailing_zero ->
    Ok (Copy_literal (3 + b, Trailing_no_extra))
  | '\000', Trailing_zero ->
    count_zeroes (fun count ->
        let length = 3 + 15 + count in
        Copy_literal (length, Trailing_no_extra))
  | '\000'..'\015', (Trailing_one | Trailing_two | Trailing_three) ->
    (* Last instruction copied between 1-3 literals
       Instruction is a copy of a 2-byte block from the dict
       within a [1;1024] distance.*)
    let d, state  = b lsr 2 , copy_trailing_of_int b in
    Ok (Read_byte (fun h ->
        let distance = (h lsl 2) + d + 1 in
        Ok (Copy_block (2, distance, state))))

  | '\000'..'\015', Trailing_no_extra ->
    (* copy of a 3-byte block from the dictionary in [2048;3072] distance *)
    Ok (Read_byte (fun h ->
        let state = copy_trailing_of_int b in
        let distance = (h lsl 2) + (b lsr 2) + 2049 in
        Ok (Copy_block (3, distance, state))))


  | '\016'..'\031', _ (* x10 - 1F *) ->
    (* x10-x17 followed by 0,(0|1|2|3) always terminate the stream*)
    (* Copy of a large block within [16384;49512] distance *)
    (* Independent of previous copy_trailing *)
    let with_length length =
      Read_le16 (fun ds ->
          let state = copy_trailing_of_int ds in
          let distance =
            let h = (b land 8) lsr 3 in
            16384 + (h lsl 14) + (ds lsr 2) in (* each of these add up to 16kB*)
          begin match distance with
            | 16384 ->
              End_of_stream (* still need to copy TODO what? *)
            (*| 0xBFFF (* 49151 *) (* TODO if v=V1*) ->
              ignore @@ failwith "version disambiguation";
              (* version 1 only: *)
              (* followed by fourth byte *)
              Read_byte (fun x ->
                let run_length = ((x lsl 3) lor l) + 4 in
                `Zeroes_if_v1_only run_length)*)
            | _ ->
              (Copy_block (length, distance, state))
          end)
    in
    let l = b land 0b111 in
    if l = 0
    then count_zeroes (fun l -> with_length (2 + 7 + l))
    else Ok (with_length (2 + l))


  | '\032'..'\063', _ (* x20 - 3F *)->
    (* copy of 2-64 bytes within 1..16384 distance *)
    let with_length length =
      Read_le16 (fun le16 ->
          let distance = succ (le16 lsr 2)  in
          Copy_block (length, distance, copy_trailing_of_int le16))
    in
    let l = b land 0b11111 in (* & 31 *)
    if l = 0
    then count_zeroes (fun l -> with_length (2 + 31 + l))
    else Ok (with_length (2 + l))

  | '\064'..'\255', _ (* x40 - FF *)->
    (* x40 .. 7F: Copy 3-4 bytes from dict within 1..2048 distance*)
    (* x80 .. FF: Copy 5-8 bytes from block within 1..2048 distance *)
    let length, d =
      let shift = (b lsr 7) lsl 1 in
      (* 3 + shift + ((b >> 5) & (shift+1)): *)
      3 + shift + ((b lsr 5) land (1 lor shift)),
      (b lsr 2) land 0b111 in (*      (b >> 2) & 7  *)
    Ok (Read_byte (fun h ->
        let distance = (h lsl 3) + d + 1 in
        Ok (Copy_block (length, distance,
                     copy_trailing_of_int b))))

let decompress (input:string) =
  let out = Buffer.create 1500 in
  Logs.debug (fun m -> m "LZO input is %d bytes: %S"
                 (String.length input) input);
  let open Rresult in
  ( (* Fail "gracefully" with large inputs on 32-bit platforms
       (this problem would go away in a streaming decompressor): *)
    let potential = Int64.(mul (of_int (String.length input)) 256L) in
    if potential < Int64.(of_int Sys.max_string_length)
    then Ok ()
    else R.error_msgf
        "LZO: You're using this module on a platform that will throw \
         exceptions when trying to allocate strings larger than %d. \
         This input could potentially expand to %Ld cause an exception when \
         the Buffer module fails to allocate a large string."
        Sys.max_string_length potential) >>= fun () ->
  let rec handle_instruction inp = function
    | End_of_stream when inp <> String.length input ->
      (* TODO: should we return [inp] in this case?*)
      Logs.warn (fun m -> m "LZO End_of_stream before end of input");
      Ok (Buffer.contents out)
    | End_of_stream -> Ok (Buffer.contents out)

    (* Bounds checking, for everything else we need at least 1 byte: *)
    | _ when inp >= String.length input ->
      Error ("Would read past input")

    | Copy_literal (len, _) when inp+len >= String.length input ->
      Error "Copy_literal would read past input bounds"

    | Copy_literal (len, state) ->
      ( if String.length input - inp < len
        then Error "Copy_literal would read past end of input"
        else Ok (Buffer.add_substring out input inp len)) >>= fun () ->
      let inp = inp + len in
      decode_instruction state input.[inp] >>= handle_instruction (succ inp)

    | Copy_block (length, distance, state) ->
      let trailing = int_of_copy_trailing state in
      ( if (distance > 0) && (Buffer.length out >= distance)
           && (String.length input - inp > trailing)
        then Ok ()
        else Error "Copy_block bounds check failed"
      ) >>= fun () ->
      let rec loop off rem =
        let taken = min rem (Buffer.length out - off) in
        if taken < 0 || rem < 0 || (taken = 0 && rem <> 0) then begin
          Error "LZO: TODO use math or whatever to prove this can't happen"
        end else if taken = 0 then begin
          Ok ()
        end else begin
          Buffer.add_string out (Buffer.sub out off taken) ;
          loop (off+taken) (rem-taken) end
      in loop (Buffer.length out - distance) length >>= fun () ->
      Buffer.add_substring out input (inp) (trailing) ;
      let inp = inp + trailing in
      decode_instruction state input.[inp] >>= handle_instruction (succ inp)

    | Read_byte f ->
      f (int_of_char input.[inp]) >>= handle_instruction (succ inp)

    | Read_le16 _ when succ inp >= String.length input ->
      Error "LZO: 16-bit operand fetch would read past end of input"
    | Read_le16 f ->
      let i16 = Char.(code input.[inp] + (code input.[inp+1] lsl 8)) in
      handle_instruction (inp+2) (f i16)
  in
  begin match input.[0] with
    | exception Invalid_argument _ -> Error "LZO.decompress on empty string"
    | '\016' (* x10 *) ->
      Error "LZO: 0x10: No dict at offset 0. We implement v0, is this LZOv1?"

    | '\000'..'\017' (* x00..0F..11 *) ->
      (* parse as regular instruction: *)
      decode_instruction Trailing_zero input.[0]

    (* special decoding of first byte: *)
    | '\018' (* x12 *) -> Ok (Copy_literal (1, Trailing_zero))
    | '\019' (* x13 *) -> Ok (Copy_literal (2, Trailing_zero))
    | '\020' (* x14 *) -> Ok (Copy_literal (3, Trailing_zero))
    | '\021' (* x15 *) -> Ok (Copy_literal (4, Trailing_zero))
    | '\022'..'\255' (* x16 - FF *)  as b ->
      let length = int_of_char b - 17 in (* 5.. 239 *)
      Ok (Copy_literal (length, Trailing_no_extra))
  end >>= handle_instruction 1 |> R.reword_error (fun s -> `Msg s)
