#!/bin/sh -ex

eval `opam config env`

opam install mirage

cd mirage-client &&
mirage configure -t $MIRAGE_MODE && make depend && mirage build && mirage clean &&

cd ../mirage-nat &&
mirage configure -t $MIRAGE_MODE && make depend && mirage build && mirage clean
