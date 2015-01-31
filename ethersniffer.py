
import socket, sys
from struct import *

# struct doc: http://docs.activestate.com/activepython/3.0/python/library/struct.html
# ethernet:  http://networksorcery.com/enp/protocol/ethernet.htm

class ethernet_frame(object):
  """Ethernet 802.3 Packet format"""
  from socket import ntohs
  from struct import unpack

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
    self.dst_mac = header[0] # 6 bytes
    self.src_mac = header[1]
    self.e_type  = ntohs(eth[2]) # 2 bytes 

  def eth_addr(self, mac):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %(ord(mac[0]), ord(mac[1]), ord(mac[2]), ord(mac[3]), ord(mac[4]), ord(mac[5]))
    


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



