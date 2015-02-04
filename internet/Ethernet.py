__author__ = 'Robbe Van der Gucht'


class EthernetFrame:
  """Ethernet 802.3 Packet format"""
  from struct import unpack

  @staticmethod
  def readable_mac(mac):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac[0]), ord(mac[1]), ord(mac[2]),
                                              ord(mac[3]), ord(mac[4]), ord(mac[5]))

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

  def __str__(self):
    s = ""
    s += "DESTINATION MAC %s\n" % self.readable_mac(self.dst_mac)
    s += "SOURCE MAC %s\n" % self.readable_mac(self.src_mac)
    s += "IP TYPE %s\n" % ("0x%.4x" % self.e_type)
    return s
