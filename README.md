## OpenVPN library purely in OCaml

OpenVPN create secure point-to-point or site-to-site connections in routed or bridged configurations and remote access facilities. It uses TLS to establish a (mutually) authenticated connection, over which material to derive the symmetric keys is exchanged.

The goal of this library is to provide a [MirageOS](https://mirage.io) unikernel that acts as a OpenVPN client, preserving the OpenVPN config file format to allow a smooth transition. Our goal is not completeness of the protocol, but to implement a small useful subset with modern crypto and the latest key exchange methods, no need to implement deprecated features (in a similar style as [nqsb-tls](https://nqsb.io)).  An initial draft of the network setup is depicted in the diagram below:

![diagram](/diagrams/multi-stack.svg)

Since OpenVPN is not specified, apart from comments in the header files, we started a specification document in markdown, still work in progress:

  - [spec.md](https://git.robur.io/?p=openvpn-spec.git;a=blob_plain;f=spec.md;hb=HEAD)

Our OpenVPN configuration parser can be tested with an OpenVPN configuration:

  - `./_build/default/parse-test/read_file.exe my.openvpn.conf`
