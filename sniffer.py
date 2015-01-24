
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP, inet_ntoa
import sys
from struct import *
import inspect

#host = socket.gethostbyname(socket.gethostname())
#host = '127.0.0.1'
#print( "Host: %s" % host )

try:
  soc = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
except socket.error, msg:
  print("Socket could not be created. Error Code: %s\nMessage: %s\n" % (str(msg[0]), str(msg[1])))
  sys.exit(1)


while 1:
  packet = soc.recvfrom(65565)
  packet = packet[0]

  ip_header = packet[0:20]
  # http://docs.activestate.com/activepython/3.0/python/library/struct.html
  #now unpack them :)
  iph = unpack('!BBHHHBBH4s4s' , ip_header)
  # ! - big-endian (network std)
  # B - unsigned char (integer)
  # H - unisnged short(integer)
  # s - char[] (bytes)

  version_ihl = iph[0]
  version = version_ihl >> 4
  ihl = version_ihl & 0xF

  iph_length = ihl * 4

  ttl = iph[5]
  protocol = iph[6]
  s_addr = inet_ntoa(iph[8]); # inet_ntoa converts an IPv4 address to a decimal dotted string
  d_addr = inet_ntoa(iph[9]);

  print("Version: %d" % version)
  print("IP Header Length: %d" % ihl)
  print("TTL: %d" % ttl)
  print("Source address: %s" % s_addr)
  print("Destination address: %s" %d_addr)
  print("Protocol: %d" % protocol)

  # if protocol == 6: take TCP header :-)
  tcp_header = packet[iph_length:iph_length+20]

  # unpack TCP header
  tcph = unpack('!HHLLBBHHH', tcp_header)

  source_port = tcph[0]
  dest_port = tcph[1]
  sequence = tcph[2]
  acknowledgement = tcph[3]
  doff_reserved = tcph[4]
  tcph_length = doff_reserved >> 4

  print("  Source Port: %d" % source_port)
  print("  Destination Port: %d" % dest_port)
  print("  Sequence Number: %d" % sequence)
  print("  Acknowledgement: %d" % acknowledgement)
  print("  TCP header length: %d" % tcph_length)
  
  h_size = iph_length + tcph_length * 4
  data_size = len(packet) - h_size

  data = packet[h_size:]

  print("\n [DATA] \n")
  print(data.encode('hex'))
  print("\n [END]  \n")
  




exit(0)
try:
        #print(inspect.getmembers(socket))

        # AF_UNIX  - inter process sockets on UNIX systems
        # AF_INET  - IPv4 socket
        # AF_INET6 - IPv6 socket
        s = socket.socket(socket.AF_PACKET,
                          socket.SOCK_RAW)
        s.bind(("wlan0", 0x0800))

        # Include IP headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # tells OS to reuse a socket even though it is still in TIME_WAIT state
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # recieve all packets (enable promiscious)
        #s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while 1:
                data = s.recvfrom(65565)
                print(data)

except:
  print("\n\nEXIT\n\n")

# disable promiscuous mode
#s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
