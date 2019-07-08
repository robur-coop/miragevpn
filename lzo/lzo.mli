(** Decompression algorithm for LZO1x_15_compress from the LZO
    compression library, as used by OpenVPN.
*)

val decompress : string -> (string, [> `Msg of string]) result
(** [decompres compressed] is the LZO1x-decompressed
    [Ok decompressed]
    or [Error `Msg error_message].
    @raises Invalid_argument if an out-of-bounds write would have occurred. This is should not happen with valid data; please do send us any offending trigger strings.
*)
