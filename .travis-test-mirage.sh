#!/bin/sh -ex

eval `opam config env`

opam install mirage

export OPAMIGNOREPINDEPENDS=true

cd mirage-client &&
mirage configure -t $MIRAGE_MODE && make depend && mirage build && mirage clean &&

cd ../mirage-nat &&
mirage configure -t $MIRAGE_MODE && make depend && mirage build && mirage clean &&

cd ../mirage-server &&
mirage configure -t $MIRAGE_MODE && make depend && mirage build && mirage clean &&

cd ../mirage-router &&
mirage configure -t $MIRAGE_MODE && make depend && mirage build && mirage clean
