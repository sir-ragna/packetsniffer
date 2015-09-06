__author__ = 'Robbe Van der Gucht'

import logging
from MacAddress import readable_mac


class DHCP:
  from struct import unpack
  from IPv4Address import IPv4Address
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

  RFC 2132 talks about DHCP options. subnetmask/def gateway/...
  """

  MAGIC_COOKIE_CONST = '\x63\x82\x53\x63'  # RFC 1497 P.2
  """Magic cookie was proposed in RFC 951 (Bootstrap Protocol)
  In RFC 1497 a constant was chosen as the original vendor field from the Bootp was deprecated."""

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
    self.chaddr = header[11][:self.hlen] # 16s
    self.sname  = header[12] # 64s
    self.file   = header[13] # 128s

    self.vendor_options = []

    logging.debug("ciaddr: %s" % self.ciaddr)
    logging.debug("yiaddr: %s" % self.yiaddr)
    logging.debug("siaddr: %s" % self.siaddr)
    logging.debug("giaddr: %s" % self.giaddr)

    # Check for magic Cookie
    if self.MAGIC_COOKIE_CONST == self.unpack('!4s', datagram[236:240])[0]:
      logging.debug("DHCP Magic cookie found")
      self.magic_cookie = True
      self.parse_optionals(datagram[240:])
    else:
      self.magic_cookie = False
      logging.warning("DHCP Magic cookie is absent")

    if self.htype != 0x01:
      logging.warning("Hardware type is not an ethernet mac address")

  def parse_optionals(self, option_data):
    logging.debug("Option data length: %d" % len(option_data))

    while len(option_data) > 0:
      peek = self.unpack('!B', option_data[:1])[0]
      logging.debug("Parsing DHCP option code: %s" % str(peek))

      if peek == 0x00:  # Padding, discard
        logging.debug("DHCP Options padding")
        option_data = option_data[1:]
        continue
      elif peek == 0xFF:  # End marker, subsequent octets are padding
        logging.debug("DHCP Options end marker")
        # should be padding -- TODO do a check to verify this
        break

      logging.debug("Unpacking option. len: %d" % len(option_data))
      # Create a tuple of (code(int), len(int), data(raw bytes)), append this to vendor_options
      vop_code, vop_length = self.unpack('!BB', option_data[:2])
      vop_raw_value = option_data[2:2 + vop_length]
      self.vendor_options.append((vop_code, vop_length, vop_raw_value))
      option_data = option_data[2 + vop_length:]

  def __str__(self):
    s = "\nDHCP - Dynamic Host Configuration Protocol\n"
    s += "Message type: %d - %s\n" % (self.op, (('Boot Request', 'Boot Reply')[self.op - 1]))
                                                                          # ^ op is not zero-based
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
    if self.htype == 0x01:
      # Ethernet MAC address
      s += "Client MAC address: %s\n" % readable_mac(self.chaddr)
    else:
      s += "Client HW address: %s\n" % self.chaddr

    if self.sname == '\x00' * 64:
      s += "No Server host name\n"
    else:
      s += "Server host name: %s\n" % self.sname

    if self.file == '\x00' * 128:
      s += "No boot file\n"
    else:
      s += "Boot file: %s\n" % self.file

    if self.magic_cookie:
      s += "Magic Cookie is present(rfc: 1497)\n"
    else:
      s += "No Magic Cookie :-(\n"

    return s