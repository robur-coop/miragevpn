## OpenVPN library purely in OCaml

OpenVPN creates secure point-to-point or site-to-site connections in routed or bridged configurations and remote access facilities.
It uses TLS to establish a (mutually) authenticated connection, over which material to derive the symmetric keys for packet encryption is exchanged.

The goal of this project is to provide:
- A pure library implementing the protocol logic, and the OpenVPN config file format to enable interoperabilty and a smooth transition for existing deployments.
- A [MirageOS](https://mirage.io) unikernel that acts as an OpenVPN client.

Our goal is not to implement the complete protocol, but rather a small useful subset with modern crypto and the latest key exchange methods, without deprecated or redundant features
(embodying the philosophy of [nqsb-tls](https://nqsb.io)).  An initial draft of the network setup is depicted in the diagram below:

![diagram](/diagrams/multi-stack.svg)

Since OpenVPN is not detailed in a protocol specificaton specified, apart from comments in the header files, we have written a specification document in Markdown, still work in progress:

  - [spec.md](https://git.robur.io/?p=openvpn-spec.git;a=blob_plain;f=spec.md;hb=HEAD)

Our OpenVPN configuration parser can be tested with an OpenVPN configuration file:

  - `./_build/default/app/openvpn_config_parser.exe my.openvpn.conf`

# Unix client `openvpn_client_lwt`

Included in this repository is a unix program that will connect to an
OpenVPN server, open a `tun` interface, and tunnel packets between
the two.

## Unix client on Linux

There are two ways to open `tun` interfaces:
1) Using a dynamically allocated interface (`dev tun`).
   In order to dynamically allocate a `tun` interface, the process will need
   privileges to do so. Either by running the client as `root` or with
   the `CAP_NET_ADMIN` privilege.
   You would then add `dev tun` to your configuration file.
2) Using a preallocated interface (`dev tunX`)
   This is the recommend configuration.
   To allocate such an interface for `tun5` you can use this command:
   ```shell
   sudo ip tuntap add mode tun user MYUSERNAME name tun5
   ```
   You would then add `dev tun5` to your configuration file.

```shell
dune build

# Bestowing the binary with CAP_NET_ADMIN if using dynamic tun allocation:
sudo setcap cap_net_admin=ep ./_build/default/app/openvpn_client_lwt.exe

./_build/default/app/openvpn_client_lwt.exe -v MY-CONFIG-FILE.CONF
```

# OpenVPN-compatible config parser

Our goal has been to implement a usable subset (as found in various
 real-world configuration files available to us during the implementation
 phase).

As far as possible we have strived to derive a representation that does not
 permit ambiguity or conflicting options to be present in the parsed config.
Consult the `type 'a k` declaration in `openvpn_config.mli` for more
 information.

This does not mean that conflicting options cannot be accepted from an on-disk
 configuration file, but rather that such conflicts are explicitly handled in
 the parser code (specifically in the `resolve_conflict` function).

## Supported config directives

Here is a list of configuration directives supported by this parser.

Directives that call for an external file to be read (or can be
 supplied inline with the `[inline]` stanza):
```
auth-user-pass FILE-PATH
ca FILE-PATH
cert FILE-PATH
connection FILE-PATH
key FILE-PATH
pkcs12 FILE-PATH

tls-auth FILE-PATH
tls-auth FILE-PATH 0
tls-auth FILE-PATH 1
# the 0/1 here is the keydirection: 0 for CN_OUTGOING; 1 for CN_INCOMING
```

Other supported directives:
```
nobind
bind
lport PORT
local HOSTNAME
local IP

cipher CIPHER

comp-lzo

dev null
dev tun
dev tap
dev tunNUMBER
dev tapNUMBER

dhcp-option disable-nbt
dhcp-option domain DOMAIN
dhcp-option ntp IP
dhcp-option dns IP

hand-window SECONDS
tran-window SECONDS

ping SECONDS
ping-exit SECONDS
ping-restart SECONDS

mssfix SIZE
link-mtu SIZE
tun-mtu SIZE

float
ifconfig-nowarn
mute-replay-warnings
passtos
persist-key
persist-tun
remote-random
auth-retry nointeract

proto tcp
proto tcp4
proto tcp4-server
proto tcp4-client
proto tcp6
proto tcp6-server
proto tcp6-client
proto udp
proto udp4
proto udp6

pull
client
tls-client
tls-server


remote-cert-tls server
remote-cert-tls client

reneg-bytes BYTES
reneg-pkts PACKET-COUNT
reneg-sec SECONDS
# renegotiate data channel key after N items sent or received
# TODO: is this (N > sent || N > received) or (N > sent+received) ?

replay-window LOW-SECONDS HIGH-SECONDS

connect-retry LOW-SECONDS HIGH-SECONDS
keepalive LOW-SECONDS HIGH-SECONDS

resolv-retry infinite
resolv-retry SECONDS

route-delay N-SECONDS W-SECONDS
# TODO describe these

route NETWORK [NETMASK [GATEWAY [METRIC]]]
# specification of network/netmask/gateway/metric is implemented.
# NETWORK: "net_gateway" or "remote_host" or or "vpn_gateway" or an IP address.
# NETMASK: "default" or CIDR format ("A.B.C.D/PREFIX")
# GATEWAY: "default" or an IP address.
# METRIC:  may be "default" or an integer between 0 and 255, inclusively.

route-gateway default
route-gateway dhcp
route-gateway IP

route-metric METRIC
# METRIC: may be "default" or an integer between 0 and 255, inclusively.

tls-version-min 1.1
tls-version-min 1.2
tls-version-min 1.3
tls-version-min 1.1 or-highest
tls-version-min 1.2 or-highest
tls-version-min 1.3 or-highest

topology net30
topology p2p
topology subnet

verb LEVEL
```

## Ignored directives

The following directives are ignored. Either because they were not deemed
 useful, or because we have not had a use for them yet:

```
inactive
ip-win32
rcvbuf
redirect-gateway
remote-cert-ku
rport
sndbuf
socket-flags

up
# string containing shell command to run ?

dh
# TODO path to a PEM file

port
# TODO influences Bind and Remote

socks-proxy

dhcp-option
# DHCP options not listed in "Supported directives" above are ignored.
```
