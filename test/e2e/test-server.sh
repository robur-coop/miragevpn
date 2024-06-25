#!/bin/sh

set -ex

if [ "$#" -ne 1 ]; then
	echo "usage: test-server.sh <tun-device>";
	exit 1
fi

for x in $(find . -name server.conf | grep -v static); do
	dir=$(dirname ${x})
	./miragevpn-server.sh $1 "$dir"
done
