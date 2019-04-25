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

  - `./_build/default/parse-test/read_file.exe my.openvpn.conf`
