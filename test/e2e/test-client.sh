#!/bin/sh

set -ex

if [ "$#" -ne 1 ]; then
	echo "usage: test-client.sh <tun-device>";
	exit 1
fi

for x in $(find . -name server.conf); do
	dir=$(dirname ${x})
	./miragevpn-client.sh $1 "$dir"
done
