__author__ = 'Robbe Van der Gucht'


class DHCP:
  from struct import unpack
  from IPv4 import IPv4Address
  """RFC 2131 - Dynamic Host Configuration Protocol
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
  +---------------+---------------+---------------+---------------+
  |                            xid (4)                            |
  +-------------------------------+-------------------------------+
  |           secs (2)            |           flags (2)           |
  +-------------------------------+-------------------------------+
  |                          ciaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          yiaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          siaddr  (4)                          |
  +---------------------------------------------------------------+
  |                          giaddr  (4)                          |
  +---------------------------------------------------------------+
  |                                                               |
  |                          chaddr  (16)                         |
  |                                                               |
  |                                                               |
  +---------------------------------------------------------------+
  |                                                               |
  |                          sname   (64)                         |
  +---------------------------------------------------------------+
  |                                                               |
  |                          file    (128)                        |
  +---------------------------------------------------------------+
  |                                                               |
  |                          options (variable)                   |
  +---------------------------------------------------------------+
  """

  def __init__(self, datagram):
    unpackstr = "!BBBBIHH4s4s4s4s16s64s128s"

    header = self.unpack(unpackstr, datagram[:236])

    self.op     = header[0] # B - unsigned char (int) 1 byte
    self.htype  = header[1] # B
    self.hlen   = header[2] # B
    self.hops   = header[3] # B
    self.xid    = header[4] # I - unsigned int (int) 4 bytes
    self.secs   = header[5] # H - unsigned short (int) 2 bytes
    self.flags  = header[6] # H
    self.ciaddr = self.IPv4Address(header[7])  # 4s - char[] (str)
    self.yiaddr = self.IPv4Address(header[8])  # 4s
    self.siaddr = self.IPv4Address(header[9])  # 4s
    self.giaddr = self.IPv4Address(header[10]) # 4s
    self.chaddr = header[11] # 16s
    self.sname  = header[12] # 64s
    self.file   = header[13] # 128s

  def __str__(self):
    s = "\nDHCP - Dynamic Host Configuration Protocol\n"
    s += "Message type: %d - %s\n" % (self.op, (('Boot Request', 'Boot Reply')[self.op]))
    s += "Hardware type: %s\n" % hex(self.htype)
    s += "Hardware address length: %d\n" % self.hlen
    s += "Hops: %d\n" % self.hops
    s += "Transaction ID: %s\n" % hex(self.xid)
    s += "Seconds elapsed: %d\n" % self.secs
    s += "Flags: %s\n" % bin(self.flags)
    s += "Client IP address       : %s\n" % self.ciaddr
    s += "Your (client) IP address: %s\n" % self.yiaddr
    s += "Next Server IP address  : %s\n" % self.siaddr
    s += "Relay agent IP address  : %s\n" % self.giaddr
    s += "Client MAC address: %s\n" % hex(self.chaddr)
    s += "Server host name: %s\n" % self.sname
    s += "Boot file: %s\n" % self.file
    return s