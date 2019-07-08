This directory contains an OCaml implementation of a decompressor
  for `lzo1x_1_15_compress` from the
  [LZO decompression library](http://www.oberhumer.com/opensource/lzo/).

```ocaml
val decompress : string -> (string, [> `Msg of string]) result
(** [decompres compressed] is the LZO1x-decompressed
    [Ok decompressed]
    or [Error `Msg error_message]
    @raises Invalid_argument if an out-of-bounds write would have occurred. This is should not happen with valid data; please do send us any offending trigger strings.
*)
```

# Test suite

The Alcotest test suite can be run with `dune runtest`.
It contains static known-good / known-bad cases either manually
 constructed or lifted from OpenVPN and `minilzo`.

# Fuzzing

The `minilzo-2.10` subdirectory contains the `minilzo` distribution by
Markus Franz Xaver Johannes Oberhumer
(under GPL license, see `minilzo-2.10/COPYING`).
**This is not used in the OCaml library, but for test case generation:**
The `testmini.c` program has been modified to produce random test cases
for the [Alcotest](TODO) test suite.
The `.ocamlinit` file in the directory makes `utop` load the relevant modules.
Usage:
```bash
make gcc
while ./testmini > test_case.ml && utop ; do : ; done
# If an error is caught (or exception is raised), you will be left in the utop
# shell with the offending test case in `test_case.ll`
```

# Other implementations and resources that may be of interest

- https://github.com/joyent/syslinux/blob/master/lzo/src/lzo1x_1o.c#L43
- https://github.com/ir193/python-lzo/blob/master/lzo.py
- https://github.com/shevek/lzo-java
- https://github.com/rasky/go-lzo/blob/master/decompress.go
- https://github.com/nemequ/lzo/blob/master/src/config1x.h
- https://github.com/jrmuizel/rust-lzo/blob/master/src/lzo1x_decompress_safe.rs
- https://bugzilla.redhat.com/show_bug.cgi?id=1131795
- https://www.mjmwired.net/kernel/Documentation/lzo.txt
- http://www.infradead.org/~mchehab/kernel_docs/unsorted/lzo.html
- https://github.com/dgelessus/old-lzo-ports/blob/master/java-lzo/org/lzo/Lzo1xDecompressor.java
- https://github.com/zzattack/MiniLZO/blob/master/MiniLZO/MiniLZO.cs
- https://www.codeproject.com/articles/16239/pure-c-minilzo-port

