
from IPv4 import IPv4
from Ethernet import EthernetFrame

__author__ = 'Robbe Van der Gucht'

"""
Attempt to partially implement some of the TCP/IP RFCs.

## Goals ##

- Sniffing and deconstruction of packets, identification of unique streams
- Do DHCP and ARP requests. Simulate NIC.
- Send custom packets

## RFCs ##

- ARP -  RFC-826
- IP - RFC-791
- IP over Ethernet - RFC-894

## Conventions ##

An (ethernet)frame is layer 2
An (IP)packet is layer 3
A (TCP)datagram is layer 4

Are used to differentiate between objects in code.

"""