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
proto udp

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