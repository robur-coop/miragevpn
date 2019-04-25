# OpenVPN MirageOS gateway setup

The purpose of this document is to describe the data flow of packets with an OpenVPN gateway.

We'll use the same terminology as in the diagram:

![diagram](/diagrams/multi-stack.svg)

Internal network: 10.38.2.1/24, ethernet 00-f0-0d-f0-0d-00
External network: 192.168.1.5/24, gateway is 192.168.1.1

## Tunnel setup

A TCP client connection from 192.168.1.5 to 1.2.3.4 port 1194 is established via the external network stack. This is a flow, which is read from and written to for all packets going via the tunnel.

## Receiving a packet on the internal network

On the internal network, the OpenVPN gateway forwards received packets via the tunnel. The internal stack consists of a generic Ethernet and ARP layer, but a slightly different IPv4 layer.

More detailed, a packet with Ethernet destination address equals 00-f0-0d-f0-0d-00 is handled by the internal stack. In the IPv4 layer (`Static_ipv4.input`), the destination IP address is checked: if it is 10.38.2.1, the respective local TCP/UDP/ICMP layers are used for handling the packet (which may lead to sending out replies).

If the IP address is somewhere else (and not broadcast or multicast or in the 10.38.2.0/24 network), this IP packet is transmitted via the OpenVPN tunnel (`Openvpn_mirage.send_data`), which involves: potential fragmentation, encryption, and transferring via the external stack: from 192.168.1.5 to 1.2.3.4 on the IP layer, to the ethernet address of 192.168.1.1 (the default gateway).

## Receiving a packet via OpenVPN

If a OpenVPN packet is received on the flow, `Openvpn_mirage.handle` is called, which decrypts the packet, and if it contains a data payload, this is passed to the internal stack. Depending on whether the destination IP address is 10.38.2.1 (in which case, the packet is processed by the internal stack) or some other IP in the 10.38.2.0/24 network - which leads to transmitting that packet to the respective IP address via the internal stack (using `Static_ipv4.write`, which uses its ARP cache to find the destination Ethernet address, and 00-f0-0d-f0-0d-00 as source Ethernet address).
