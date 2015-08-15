__author__ = 'Robbe Van der Gucht'


class UDP:
  from struct import unpack

  def __init__(self, datagram):
    """RFC 768 - User Datagram Protocol
    0       7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |
    |          data octets ...
    +---------------- ...
    """

    unpackstr = '!HHHH'
    # ! - big-endian (network std)
    # H - unsigned short (int) 16 bits

    udpheader = self.unpack(unpackstr, datagram[:4 * 2]) # 4 * 2 bytes
    self.source_port = udpheader[0]
    self.destination_port = udpheader[1]
    self.length = udpheader[2]
    self.checksum = udpheader[3]

  def __str__(self):
    s = "\nUDP Datagram \n"
    s += "Source port      : %d\n" % self.source_port
    s += "Destination port : %d\n" % self.destination_port
    s += "length           : %d\n" % self.length
    s += "checksum         : %s\n" % hex(self.checksum)
    return s