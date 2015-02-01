
import socket, sys
from struct import *

# struct doc: http://docs.activestate.com/activepython/3.0/python/library/struct.html
# ethernet:  http://networksorcery.com/enp/protocol/ethernet.htm

class Ethernet_frame:
  """Ethernet 802.3 Packet format"""
  from socket import ntohs
  from struct import unpack

  def readable_mac(self, mac):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %(ord(mac[0]), ord(mac[1]), ord(mac[2]), ord(mac[3]), ord(mac[4]), ord(mac[5]))

  def __init__(self, raw):
    self.raw = raw
    self.ether_types = { 
      0x0800: "IPv4",
      0x86dd: "IPv6",
      0x0806: "ARP",
      0x8035: "RARP",
      0x809B: "AppleTalk",
      0x80F3: "AppleTalk ARP",
      0x8137: "NetWare IPX/SPX"
    }

    self.header = unpack('!6s6sH', raw[:14])
    self.dst_mac = self.header[0] # 6 bytes
    self.src_mac = self.header[1]
    self.e_type  = self.header[2] # 2 bytes 

  def __str__(self):
    s = ""
    s += "DESTINATION MAC %s\n" % self.readable_mac(self.dst_mac)
    s += "SOURCE MAC %s\n" % self.readable_mac(self.src_mac)
    s += "IP TYPE %s\n" % ("0x%.4x" % self.e_type)
    return s

class IPv4:
  """RFC 791
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Example Internet Datagram Header
  version:  4 bits
  IHL:  4 bits

    Internet Header Length is the length of the internet header in 32
    bit words, and thus points to the beginning of the data.  Note that
    the minimum value for a correct header is 5.

  Type of Service:  8 bits

    The Type of Service provides an indication of the abstract
    parameters of the quality of service desired.  These parameters are
    to be used to guide the selection of the actual service parameters
    when transmitting a datagram through a particular network.  Several
    networks offer service precedence, which somehow treats high
    precedence traffic as more important than other traffic (generally
    by accepting only traffic above a certain precedence at time of high
    load).  The major choice is a three way tradeoff between low-delay,
    high-reliability, and high-throughput.

      Bits 0-2:  Precedence.
      Bit    3:  0 = Normal Delay,      1 = Low Delay.
      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
      Bits   5:  0 = Normal Relibility, 1 = High Relibility.
      Bit  6-7:  Reserved for Future Use.

         0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                 |     |     |     |     |     |
      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
      |                 |     |     |     |     |     |
      +-----+-----+-----+-----+-----+-----+-----+-----+

  """
  TypeOfServicePrecedence = { 0b111: "Network Control",
                              0b110: "Internetwork Control",
                              0b101: "CRITIC/ECP",
                              0b100: "Flash Override",
                              0b011: "Flash",
                              0b010: "Immediate",
                              0b001: "Priority",
                              0b000: "Routine" }

# Converts a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %(ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
  return b

try :
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
  # socket.ntohs converts bytes from little endian(intel) to big endian(network)
except socket.error, msg:
  print("Socket could not be created. Error Code: %s\nMessage: %s\n" % (str(msg[0]), str(msg[1])))
  sys.exit(1)

while 1:
  ether_frame = s.recvfrom(65565)
                          # ^ 
                          # 65,535 <= max length of IPv4 packet
                          # + ethernet frame header
  #packet = s.recvfrom()
  packet = ether_frame[0]
  print("PACKET LENGTH: %d" % len(packet))
  #print(ether_frame)

  frm = Ethernet_frame(packet)
  print(str(frm))

  continue

  eth_length = 14  # 6 + 6 + 2 : dest-mac, src-mac, type

  eth_header = packet[:eth_length]
  eth = unpack('!6s6sH', eth_header)
  eth_protocol = socket.ntohs(eth[2])
  print("Destination MAC: %s" % eth_addr(eth[0]))
  print("Source MAC: %s" % eth_addr(eth[0]))
  print("Protocol: %d" % eth_protocol)

  if eth_protocol == 8: # IPv4
    # first 20 chars for IP Header
    ip_header = packet[eth_length: 20 + eth_length]

    iph = unpack('!BBHHHBBH4s4s', ip_header)
    # ! - big-endian (network std)
    # B - unsigned char (integer)
    # H - unsigned short(integer)
    # s - char[] (bytes)

    version_ihl = iph[0]
    print("VERSION_IHl: %s" % chr(version_ihl))
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    print("IPv4 - HEADER")
    print("Version: %d" % version)
    print("IP Header length: %d" % ihl)
    print("TTL: %d" % ttl)
    print("Source address: %s" % s_addr)
    print("Destination address: %s" % d_addr)
    print("Protocol: %d" % protocol)

    if protocol == 6: # TCP
      t = iph_length + eth_length
      tcp_header = packet[t:t+20]

      tcph = unpack('!HHLLBBHHH', tcp_header)

      source_port = tcph[0]
      dest_port = tcph[1]
      sequence = tcph[2]
      ack = tcph[3]
      doff_reserved = tcph[4]
      tcph_length = doff_reserved >> 4

      print("TCP - HEADER")
      print("Source port: %d" % source_port)
      print("Destination port: %d" % dest_port)
      print("Sequence number: %d" % sequence)
      print("Acknowledgement: %d" % ack)
      print("TCP Header Length: %d" % tcph_length)

      h_size = eth_length + iph_length + tcph_length * 4
      data_size = len(packet) - h_size

      data = packet[h_size:]

      print("Data: %s" % [" ".join("{:02x}".format(ord(c)) for c in data)])
    
    elif protocol == 1: ## ICMP
      u = iph_length + eth_length
      icmph_length = 4
      icmp_header = packet[u:u+4]

      icmph = unpack('!BBH', icmp_header)

      icmp_type = icmph[0]
      code = icmph[1]
      checksum = icmph[2]

      print("ICMP HEADER")
      print("Type: %d" % icmp_type)
      print("Code: %d" % code)
      print("Checksum: %d" % checksum)

      h_size = eth_length + iph_length + icmp_length
      data_size = len(packet) - h_size

      data = packet[h_size:]

      print("Data: %s" % [" ".join("{:02x}".format(ord(c)) for c in data)])

    elif protocol == 17: # UDP
      u = iph_length + eth_length
      udph_length = 8
      udp_header = packet[u:u+8]

      udph = unpack('!HHHH', udp_header)

      source_port = udph[0]
      dest_port = udph[1]
      length = udph[2]
      checksum = udph[3]

      print("DCPH HEADER")
      print("Source port: %d" % source_port)
      print("Destination port: %d" % dest_port)
      print("Length: %d" % length)
      print("Checksum: %d" % checksum)

      h_size = eth_length + iph_length + udph_length
      data_size = len(packet) - h_size

      data = packet[h_size:]

      print("Data: %s" % [" ".join("{:02x}".format(ord(c)) for c in data)])

    else:
      print("Unkown layer 4 protocol")
  else:
    print("Not IPv4 packet")
  print("=" * 80)


