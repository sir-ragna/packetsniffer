__author__ = 'Robbe Van der Gucht'


def readable_mac(mac):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac[0]), ord(mac[1]), ord(mac[2]),
                                              ord(mac[3]), ord(mac[4]), ord(mac[5]))


class EthernetFrame:
  """Ethernet 802.3 Packet format"""
  from struct import unpack
  from IPv4 import IPv4

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

    self.header = self.unpack('!6s6sH', raw[:14])
    self.dst_mac = self.header[0]  # 6 bytes
    self.src_mac = self.header[1]
    self.e_type = self.header[2]  # 2 bytes
    self.data = raw[14:]
    self.packet = None

    if self.ether_types[self.e_type] == "IPv4":
      self.packet = self.IPv4(self.data)

  def __str__(self):
    s = ""
    s += "DESTINATION MAC %s\n" % readable_mac(self.dst_mac)
    s += "SOURCE MAC %s\n" % readable_mac(self.src_mac)

    if self.e_type in self.ether_types:
      s += "IP TYPE %s (%s)\n" % (("0x%.4x" % self.e_type), self.ether_types[self.e_type])
    else:
      s += "IP TYPE %s\n" % ("0x%.4x" % self.e_type)

    if not self.packet is None:
      s += "\nDATAGRAM - " + self.ether_types[self.e_type] + "\n"
      s += str(self.packet)
    return s
