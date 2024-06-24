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

# later run the openvpn client
pidfile="/tmp/miragevpn-e2e.pid"

# kill openvpn client
cleanup () {
	cat "$pidfile" | xargs kill
	rm -f "$pidfile"
}
trap cleanup EXIT

(
	sleep 1
	openvpn --cd "$config_dir" --config "client.conf" --dev-type tun --dev "$tun_interface" --writepid "$pidfile" --script-security 2 --up ../client-up.sh  > /dev/null
) &

# run miragevpn server
# NOTE: timeout as in FreeBSD 14 & GNU coreutils
timeout -k 30 10 ../../_build/default/app/miragevpn_server_notun.exe --test "${server_config}" -v -v >/dev/null
