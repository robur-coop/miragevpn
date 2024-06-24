#!/bin/sh

set -e

usage () {
	echo "$1 <tun-interface> <configuration-dir>"
	exit 1
}

if [ "$#" -ne 2 ]; then
	usage
fi

tun_interface="$1"
config_dir="$2"
server_config="${config_dir}/server.conf"
client_config="${config_dir}/client.conf"

# run openvpn server
pidfile="/tmp/miragevpn-e2e.pid"
openvpn --cd "$config_dir" --config "server.conf" --dev-type tun --dev "$tun_interface" --writepid "$pidfile" >/dev/null &

# kill openvpn server and report test status
cleanup () {
	cat "$pidfile" | xargs kill
	rm -f "$pidfile"
}
trap cleanup EXIT

sleep 0.5

# run miragevpn-client-notun
# NOTE: timeout as in FreeBSD 14 & GNU coreutils
timeout -k 30 10 ../../_build/default/app/miragevpn_client_notun.exe --test "$client_config" -v -v > /dev/null
