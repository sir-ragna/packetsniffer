
# packet sniffer #

Bare bones but functional.

    sudo python ethernetsniffer.py

## Linux only ##

I don't know the cross platform equivalent for `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))`.
If you do know the equivalent for other operating systems please let me know.

I only know it isn't possible on Windows without third party drivers like PCAP.
Might look into PCAP later.

## implemented ##

- ethernet
- IPv4
- UDP
- DHCP (partially)

## goal ##

Learn how TCP/IP works and can be implemented.

