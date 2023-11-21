## OpenVPN-compatible library purely in OCaml

MirageVPN creates secure point-to-point or site-to-site connections in routed or bridged configurations and remote access facilities.
It uses TLS to establish a (mutually) authenticated connection, over which material to derive the symmetric keys for packet encryption is exchanged.

The goal of this project is to provide:
- A pure library implementing the protocol logic, and the OpenVPN config file format to enable interoperabilty and a smooth transition for existing deployments.
- A [MirageOS](https://mirage.io) unikernel that acts as an OpenVPN-compatible client and server.

Our goal is not to implement the complete protocol, but rather a small useful subset with modern crypto and the latest key exchange methods, without deprecated or redundant features
(embodying the philosophy of [nqsb-tls](https://nqsb.io)).  An initial draft of the network setup is depicted in the diagram below:

![diagram](/diagrams/multi-stack.svg)

Since OpenVPN is not detailed in a protocol specificaton specified, apart from comments in the header files, we have written a specification document in Markdown, still work in progress:

  - [openvpn.md](https://git.robur.coop/robur/openvpn-spec/src/branch/main/openvpn.md)

Our OpenVPN configuration parser can be tested with an OpenVPN configuration file:

  - `./_build/default/app/openvpn_config_parser.exe my.openvpn.conf`

# Unix client `miragevpn_client_lwt`

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
sudo setcap cap_net_admin=ep ./_build/default/app/miragevpn_client_lwt.exe

./_build/default/app/miragevpn_client_lwt.exe -v MY-CONFIG-FILE.CONF
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

A notable difference from OpenVPN configuration parser is that we treat relative
 paths in a configuration file to be relative to the configuration file
 location, and not relative to the current working directory. OpenVPN supports
 a `--cd` argument, which we do not.

You can check compatibility with your configuration file by executing
```shell
dune build
./_build/default/app/openvpn_config_parser.exe MY-CONFIG-FILE.CONF
```

## Discrepancies between MirageVPN and OpenVPN

The "verify-x509-name <host> name" in OpenVPN checks by default only the
commonName of the subject in the X.509 certificate. MirageVPN validates the
provided host against the set of hostnames in the certificate, namely the union
of the commonName and the DNS entries in the SubjectAlternativeName extension.

## Funding

This project was funded in 2019 for six months by the [German federal ministry for education and research](https://www.bmbf.de) via the [Prototypefund](https://prototypefund.de) - the amount was 47500 EUR.

In 2023, we received funding from European Union in the Next Generation Internet project ([NGI assure](https://www.assure.ngi.eu/), via [NLnet](https://nlnet.nl). The scope was updating to the current protocol version (tls-crypt-v2 etc.), a QubesOS client, a server implementation, and more documentation. The amount was 49500 EUR.
