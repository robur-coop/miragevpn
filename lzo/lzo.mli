(** Decompression algorithm for LZO1x_15_compress from the LZO
    compression library, as used by OpenVPN.
*)

val decompress : string -> (string, [> `Msg of string]) result
(** [decompres compressed] is the LZO1x-decompressed
    [Ok decompressed]
    or [Error `Msg error_message].
    @raises Invalid_argument if an out-of-bounds write would have occurred. This is should not happen with valid data; please do send us any offending trigger strings.
*)

(** TL;DR the nonexistent specification:
   - LZO decompression works by parsing single-octet instructions inlined in the
     compressed stream.
   - Some instructions require extra operands (adjacent to the instruction in
     the compressed stream) to be read. [`Read_byte] and [`Read_le16].
   - There are two types of instructions: Copy_literal and Copy_block.
     - The first byte (= first instruction) is a special case.
   - [Copy_literal] copies a number of bytes (placed adjacent to the
     instruction and operands, on the right, in the compressed stream)
     to the output buffer.
   - [Copy_block] copies a number of bytes adjacent to (to the left of)
     the instruction from the dictionary to the output buffer.
     - In this implementation the "dictionary" and the "output buffer"
       are one and the same.
     - One of the operands to [Copy_block] is called "distance".
       This operand establishes the position of the leftmost byte to be copied,
       relative to the rightmost byte in the dictionary.
       Thus distance of 1 would refer to the last byte in the dictionary.
     - The "length" operand determines how many bytes to copy (left-to-right).
       If "length" would read past the end of the dictionary, the copying starts
       over from [dictionary_length - distance].
     - Example:
       Input: [{Copy_literal 5} A B C D E]
              [{Copy_block len=6 dist=2} {Copy_block len=5 dist=9}]
              [{Copy_literal 2} Y O {End of stream}]
       [Output state 1: A B C D E]
       [Output state 2: A B C D E | D E D E D E]
       [Output state 3: A B C D E | D E D E D E | C D E D E]
       [Output state 4: A B C D E | D E D E D E | C D E D E | Y O]
*)
