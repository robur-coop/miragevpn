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
  # the "direction" argument to tls-auth is not implemented
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


ping SECONDS
ping-exit SECONDS
ping-restart SECONDS

mssfix SIZE
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

reneg-sec SECONDS

replay-window LOW-SECONDS HIGH-SECONDS

connect-retry LOW-SECONDS HIGH-SECONDS
keepalive LOW-SECONDS HIGH-SECONDS

resolv-retry infinite
resolv-retry SECONDS

route
# specification of network/netmask/gateway/metric is implemented.

route-gateway default
route-gateway IP

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

socks-proxy

dhcp-option
# DHCP options not listed in "Supported directives" above are ignored.
```
