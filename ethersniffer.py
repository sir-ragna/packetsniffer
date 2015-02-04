
import socket, sys
import internet

# struct doc: http://docs.activestate.com/activepython/3.0/python/library/struct.html
# ethernet:  http://networksorcery.com/enp/protocol/ethernet.htm

# Converts a string of 6 characters of ethernet address into a dash separated hex string


try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
  # socket.ntohs converts bytes from little endian(intel) to big endian(network)
except socket.error, msg:
  print("Socket could not be created. Error Code: %s\nMessage: %s\n" % (str(msg[0]), str(msg[1])))
  sys.exit(1)

while 1:
  unit = s.recvfrom(65565)[0]
                          # ^ 
                          # 65,535 <= max length of IPv4 packet
                          # + ethernet frame header

  print("PACKET LENGTH: %d" % len(unit))

  ethframe = internet.EthernetFrame(unit)
  print(str(ethframe))

  if ethframe.e_type == 0x0800:
    print("ETHERNET DATAGRAM")
    datagram = internet.IPv4(unit[14:])
    print(str(datagram))




