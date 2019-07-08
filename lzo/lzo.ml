(*
LZO01X-1(15)
  algorithm category: 01
  algorithm type:      X
  compression level:   1
  memory level:       15

*)

module Logs = (val Logs.(src_log @@ Src.create
                           "ovpn.lzo") : Logs.LOG)

let [@inline always] first_byte = function
  | '\016' (* x10 *) -> failwith "always invalid, no dict on first byte"
  | '\000'..'\017' (* x00..0F..11 *) ->
    (* not skipping byte *)
    `Regular_instruction_encoding

  | '\018' (* x12 *) -> `Copy_block (0, 0, 0)
  | '\019' (* x13 *) -> `Copy_block (0, 0, 1)
  | '\020' (* x14 *) -> `Copy_block (0, 0, 2)
  | '\021' (* x15 *) -> `Copy_block (0, 0, 3)
  | '\022'..'\255' (* x16 - FF *)  as b ->
    let length = int_of_char b - 17 in (* 5.. 239 *)
    `Copy_block (length, 0, 4) (* 4: no trailing *)

let [@inline always] count_zeroes f =
  (* This function looks for a continuous stream zero-bytes
     and returns when the first non-zero byte is encountered.
     It is used to code long lengths for copy operations.
  *)
  let rec do_count count =
    `Read_byte (function
        | 0 ->
          let count = succ count in
          do_count count
        | non_zero -> f (count * 255 + non_zero))
  in do_count 0

let decode_instruction prev_state c =
  let b = int_of_char c in
  Logs.debug (fun m -> m "decoding %#x(%d)\n" b b);
  match c, prev_state with

  (* 00..15 == x00 - 0F *)
  (* Depends on the number of literals copied by the last instruction.*)
  | '\001'..'\015', 0 ->
    let length = 3 + b
    and distance = 0
    and state = 4 in
    `Copy_block (length, distance, state)
  | '\000', 0 ->
    count_zeroes (fun count ->
        let length = 3 + 15 + count in
        `Copy_block (length, 0, 4))
  | '\000'..'\015', (1|2|3) ->
    (* Copy between 1-3 literals
       Instruction is a copy of a 2-byte block from the dict
       within a 1kB distance.
    *)
    let d, state  = b lsr 2 , b land 0b11 in
    (* always followed by one byte *)
    `Read_byte (fun h ->
        let distance = (h lsl 2) + d + 1 in
        `Copy_block (2, distance, state))
  | '\000'..'\015', 4 ->
    (* a copy of a 3-byte block from the dictionary in the 2k..3k distance *)
    let d,state = b lsr 2, b land 0b11 in
    `Read_byte (fun h ->
        let distance = (h lsl 2) + d + 2049 in
        `Copy_block (3, distance, state))
  | '\000'..'\015', _ ->
    failwith "00.15: invalid S is not 0-4)"

  | '\016'..'\031', _ (* x10 - 1F *) ->
    (* x10-x17 followed by 0,(0|1|2|3) always terminate the stream*)
    (* Copy of a block within 16kB..48kB distance *)
    let l = b land 0b111 in
    let with_length length =
      `Read_le16 (fun ds ->
          let d, state =
            (ds lsr 2), (ds land 0b11)
          in
          let distance =
            let h = (b land 8) lsr 3 in
            Logs.debug (fun m -> m "h=%d, d=%d\n" h d) ;
            16384 + (h lsl 14) + d in
          begin match distance with
            | 16384 -> `End_of_stream (* still need to copy *)
            (*| 0xBFFF (* 49151 *) (* TODO if v=V1*) ->
            ignore @@ failwith "version disambiguation";
              (* version 1 only: *)
              (* followed by fourth byte *)
              `Read_byte (fun x ->
                let run_length = ((x lsl 3) lor l) + 4 in
                `Zeroes_if_v1_only run_length)*)
            | _ -> `Copy_block (length, distance, state)
          end)
    in
    if l = 0 then
      count_zeroes (fun l -> with_length (2+7+l))
    else with_length (2+l)
  | '\032'..'\063', _ (* x20 - 3F *)->
    (* copy of small block within 16kb distance *)
    let l = b land 0b11111 in
    let with_length length =
      `Read_le16 (fun x ->
          let distance, state =
            succ (x lsr 2), x land 0b11 in
          `Copy_block (length, distance, state))
    in
    if l = 0
    then count_zeroes (fun l -> with_length (2+31+l))
    else with_length (2+l)
  | '\064'..'\127', _ (* x40 - 7F *)->
    let length, d, state =
      3 + ((b lsr 5) land 1),
      (b lsr 2) land 0b111, b land 0b11 in
    `Read_byte (fun h ->
        let distance = (h lsl 3) + d + 1 in
        `Copy_block (length, distance, state))
  | '\128'..'\255', _ (* x80 - FF *)->
    (* Copy 5-8 bytes from block within 2kB distance *)
    let length, d, state =
      5 + ((b lsr 5) land 0b11),
      ((b lsr 2) land 0b111),
      b land 0b11 in
    `Read_byte (fun h ->
        let distance = (h lsl 3) + d + 1 in
        `Copy_block (length, distance, state))

let decompress (input:string) =
  let out = Buffer.create (String.length input * 2) in
  Logs.debug (fun m -> m "input is %d bytes: %S\n" (String.length input) input);
  let handle_copy_block ~before ~next : _ -> (int*int*int, _) result =
    let copy_wrapped offset rem =
      let rec loop off rem =
      let taken = min rem (before-off) in
      assert (taken >= 0 && rem >= 0);
      if taken = 0 then begin
        if rem = 0 then () else loop offset rem
      end else begin
        Logs.debug (fun m -> m "--> take:%d[%d]: %S \n" taken off
                       (String.sub input off taken));
        Buffer.add_substring out input off taken ;
        loop (off+taken) (rem-taken) end
      in loop offset rem
    in
    function

    (* This copies substrings from the input buffer into the output buffer.
       [before] is the position of(before/TODO) the last instruction processed.
       [next] is the position after the last instruction
       (since some instructions take up several bytes).

       It receives a tuple of {length,distance,state}.

       [length] is the amount of characters to copy.
       [distance] is the amount of characters to skip (backwards) from [before].

       An interesting thing to note about this procedure is that
       when length > distance, we must loop.
       For instance: {len=32,dist=4} would result in the 4-byte substring at
       input.[before-4 .. before-1] being repeated 16 times.*)

    | (length, 0, 4) ->
      Logs.debug (fun m -> m "aCOPY %d,0,4 {next[%d] instr: %#x}\n"
                     length next (int_of_char input.[next+length]));
      Buffer.add_substring out input next length ;
      Ok (before, next+length, 4)
    | (length, distance, 4) ->
      (* TODO write unit test for this *)
      Logs.debug (fun m -> m "bCOPY %d,%d,4\n" length distance);
      copy_wrapped (before-distance) length ;
      Ok (before, next, 4)
    | (length, 0, (0|1|2|3 as state)) ->
      Logs.debug (fun m -> m "cCOPY %d,0,%d\n" length state);
      Buffer.add_substring out input next length ;
      Buffer.add_substring out input (next+length) (state+1) ;
      Ok (before, (next+state+1), state)
    | (length, distance, (0|1|2|3 as state)) ->
      let offset = before-distance in
      Logs.debug (fun m -> m "dCOPY %d,%d[%d:%d..%d],%d\n--> s:%S\n"
        length distance before (offset) (offset+length-1) state
        (String.sub input (next) (state)) ) ;
      copy_wrapped offset length ;
      Buffer.add_substring out input (next) (state) ;
      Ok (before, (next+state), state)
    | _, _, s ->
      failwith (Printf.sprintf "invalid state %d" s)
  in
  let open Rresult in
  let decode_stream orig_before orig_inp orig_state =
    let rec handle_instruction before inp = function
      | `Copy_block ((l,d,s) as operands) ->
        Logs.debug (fun m -> m "copy l=%d,d=%d,s=%d inp=%d\n%!" l d s inp);
        handle_copy_block ~before ~next:(inp) operands
        >>= fun (_before, inp, state) ->
        Logs.debug (fun m -> m "OUT(%d): %S\n_cp inp=%d{%#x}\n"
          (Buffer.length out)
          (Buffer.contents out) inp (int_of_char input.[inp]));
        handle_instruction inp (succ inp)
          (decode_instruction state input.[inp])
      | `End_of_stream -> Ok (Buffer.contents out)
      | `Zeroes_if_v1_only _ -> Error "is this v1??"
      | `Read_byte f ->
        Logs.debug (fun m -> m "__ i8[%d+%d]: %#x\n%!" inp before
          (int_of_char input.[inp]));
        f (int_of_char input.[inp])
        |> handle_instruction before (succ inp)
      | `Read_le16 f ->
        let i16 = int_of_char input.[inp]
                  + (int_of_char input.[inp+1] lsl 8) in
        Logs.debug (fun m -> m "__ i16[%d+%d]: %#x -> inp:%d\n"
                       inp before i16 (inp+2));
        f i16
        |> handle_instruction before (inp+2)
    in
    handle_instruction orig_before (succ orig_inp)
        (decode_instruction orig_state input.[orig_inp])
  in
  begin match first_byte input.[0] with
    | `Regular_instruction_encoding ->
      Logs.debug (fun m -> m "first is regular.\n");
      decode_stream 0 0 0
    | `Copy_block ((l,d,s) as operands) ->
      Logs.debug (fun m -> m "first COPY: (l=%d,d=%d,s=%d)\n" l d s);
      handle_copy_block ~before:0 ~next:1 operands
      >>= fun (before, inp, state) ->
      Logs.debug (fun m -> m "iBUF: %S -> inp:%d\n" (Buffer.contents out) inp);
      decode_stream before inp state
  end |> R.reword_error (fun s -> `Msg s)
