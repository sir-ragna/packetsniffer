from IPv4 import IPv4
from IPv4 import Unimplemented
from IPv4 import ErrorInvalidDatagram
from Ethernet import EthernetFrame
from UDP import UDP
from DHCP import DHCP

__author__ = 'Robbe Van der Gucht'

__description__ = """Attempt to partially implement some of the TCP/IP RFCs.

## Goals ##

- Sniffing and deconstruction of packets, identification of unique streams
- Do DHCP and ARP requests. Simulate NIC.
- Send custom packets

## RFCs ##

- ARP -  RFC-826
- IP - RFC-791
- IP over Ethernet - RFC-894
- Assigned numbers - RFC-790
- ICMP - RFC-792

### Type of Service field ###

Has a lot of RFCs, but doesn't seem to be too interesting. Might stick with a sane default.
At some point gets deprecated and replaced by something else.

- RFC-791
- RFC-1122
- RFC-1349
- RFC-2474
- RFC-3168 section 22 contains a historical overview

## Conventions ##

An (ethernet)frame is layer 2
An (IP)packet is layer 3
A (TCP)datagram is layer 4

Are used to differentiate between objects in code.
"""
