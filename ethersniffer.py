
import socket, sys
from struct import *

# struct doc: http://docs.activestate.com/activepython/3.0/python/library/struct.html
# ethernet:  http://networksorcery.com/enp/protocol/ethernet.htm

class Invalid_datagram_exception(Exception):
  def __init__(self, msg):
    self.message = "Invalid datagram %s" % msg

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
  """
  from socket import ntohs, inet_ntoa
  from struct import unpack
  TypeOfServicePrecedence = { 0b111: "Network Control",
                              0b110: "Internetwork Control",
                              0b101: "CRITIC/ECP",
                              0b100: "Flash Override",
                              0b011: "Flash",
                              0b010: "Immediate",
                              0b001: "Priority",
                              0b000: "Routine" }
  def __init__(self, raw_datagram):
    vihl = unpack("!B", raw_datagram[:1]) # version + ip header length
    self.version = vihl[0] >> 4
    self.ihl     = vihl[0] & 0x0F # ihl => number of 32 bit words in header (max: 15)
    print("IHL: %d" % self.ihl)

    if self.ihl < 5: # less then minimum length
      raise Invalid_datagram_exception("IHL is less than minimum(5). IHL :: " + str(self.ihl))

    unpackstr = '!BBHHHBBH4s4s' # for ihl == 5
    # ! - big-endian (network std)
    # B - unsigned char   (int)    8 bits
    # H - unsigned short  (int)    16 bits
    # s - char[]          (bytes)  8[] bits

    if self.ihl == 5: # minimum
      ipheader = unpack(unpackstr, raw_datagram[:5 * 4]) # 5 * 4 bytes | 5 * 32 bits
      self.type_of_service = ipheader[1] # TODO: details page 12 RFC 791
      self.precedence = self.type_of_service >> 5
      self.total_length = ipheader[2]
      self.identification = ipheader[3]
      self.flags = ipheader[4] >> 13
      self.fragment_offset = (ipheader[4] << 3) >> 3
      self.time_to_live = ipheader[5]
      self.protocol = ipheader[6]
      self.header_checksum = ipheader[7]
      self.source_address = ipheader[8]      # IPs stored as bytes
      self.destination_address = ipheader[9]
    elif self.ihl > 5:
      # TODO implement IP datagrams headers longer than 20 bytes :-)
      raise Exception("Not implemented yet")

  def __str__(self):
    s = ""
    s += "Type of service: %d\n" % self.type_of_service
    s += "Total length: %d\n" % self.total_length
    s += "Identification %s\n" % hex(self.identification) # display as hex
    s += "ToS Precedence: %s\n" % self.TypeOfServicePrecedence[self.precedence]
    s += "Time to live: %d\n" % self.time_to_live
    s += "Protocol: %d\n" % self.protocol
    s += "Header checksum: %s\n" % hex(self.header_checksum)
    s += "Source IP: %s\n" % self.inet_ntoa(self.source_address)
    s += "Destination IP: %s\n" % self.inet_ntoa(self.destination_address)
    return s


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

  if frm.e_type == 0x0800:
    print("ETHERNET DATAGRAM")
    datagram = IPv4(packet[14:])
    print(str(datagram))

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



