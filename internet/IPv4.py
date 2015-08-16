__author__ = 'Robbe Van der Gucht'


class ErrorInvalidDatagram(Exception):
  def __init__(self, msg=''):
    self.message = "Invalid datagram: %s" % msg


class Unimplemented(Exception):
  def __init__(self, msg=''):
    self.message = "Uniplemented: %s" % msg


class IPv4Address:
  from socket import inet_ntoa
  """RFC 791 only defines 3 address classes. A, B and C"""
  def __init__(self, addr):
    self.b_address = addr
    self.s_address = self.inet_ntoa(addr)
    self.addr_class = "UNKNOWN"

    first_byte = int("0x%.2x" % ord(addr[0]), 16)  # Can be more elegant

    if first_byte < 0b01111111:  # in class a, the high order bit is zero
      self.addr_class = "A"
    elif first_byte < 0b10111111:  # in class b, the high order two bits are one-zero
      self.addr_class = "B"
    elif first_byte < 0b11011111:  # in class c, the high order three bits are one-one-zero
      self.addr_class = "C"
    elif self.s_address == "0.0.0.0":
      self.addr_class = "Broadcast"
    else:
      self.addr_class = "Unimplemented address class. (Not in RFC 791)"

  def __str__(self):
    return "%s\tClass %s" % (self.s_address, self.addr_class)


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
  from struct import unpack
  from UDP import UDP
  TypeOfServicePrecedence = { 0b111: "Network Control",
                              0b110: "Internetwork Control",
                              0b101: "CRITIC/ECP",
                              0b100: "Flash Override",
                              0b011: "Flash",
                              0b010: "Immediate",
                              0b001: "Priority",
                              0b000: "Routine" }

  # List take from RFC 790 P6.
  # IANA should have more updated list.
  protocol_codes = { 1 : "ICMP",
                     3 : "Gateway-to-Gateway",
                     4 : "CMCC Gateway Monitoring Message",
                     5 : "ST",
                     6 : "TCP",
                     7 : "ULC",
                     9 : "Secure",
                     10: "BBN RCC Monitoring",
                     11: "NVP",
                     12: "PUP",
                     13: "Pluribus",
                     14: "Telenet",
                     15: "XNET",
                     16: "Chaos",
                     17: "UDP",
                     18: "Multiplexing",
                     19: "DCN",
                     20: "TAC Monitoring",
                     63: "any local network",
                     64: "SATNET and Backroom EXPAK",
                     65: "MIT Subnet Support",
                     69: "SATNET Monitoring",
                     71: "Internet Packet Core Utility",
                     76: "Backroom SATNET Monitoring",
                     78: "WIDEBAND Monitoring",
                     79: "WIDEBAND EXPAK"}

  def __init__(self, raw_datagram=None):
    if raw_datagram is None:
      raise ErrorInvalidDatagram("Cannot unpack empty datagram.")
    vihl = self.unpack("!B", raw_datagram[:1])  # version + ip header length
    self.version = vihl[0] >> 4
    self.ihl = vihl[0] & 0x0F  # ihl => number of 32 bit words in header (max: 15)

    if self.ihl < 5:  # less then minimum length
      raise ErrorInvalidDatagram("IP Header Length is less than minimum(5 * 32 bit words). IHL :: " + str(self.ihl))

    self.unpackstr = '!BBHHHBBH4s4s'  # for ihl == 5
    # ! - big-endian (network std)
    # B - unsigned char   (int)    8 bits
    # H - unsigned short  (int)    16 bits
    # s - char[]          (bytes)  8[] bits

    if self.ihl > 5:
      # capture options if they exist
      optionlen = self.ihl - 5
      self.unpackstr + str(4 * optionlen) + 's'

    ipheader = self.unpack(self.unpackstr, raw_datagram[:self.ihl * 4])  # 5 * 4 bytes | 5 * 32 bits
    self.type_of_service = ipheader[1]  # TODO: details page 12 RFC 791
    self.precedence = self.type_of_service >> 5
    self.total_length = ipheader[2]
    self.identification = ipheader[3]
    self.flags = ipheader[4] >> 13
    self.f_reserved = (0b100 & self.flags) >> 2
    self.f_may_fragment = (0b010 & self.flags) >> 1
    self.f_is_last = 0b001 & self.flags
    self.f_str = "{0:03b}".format(self.flags)
    self.fragment_offset = (ipheader[4] << 3) >> 3
    self.time_to_live = ipheader[5]
    self.protocol = ipheader[6]
    self.header_checksum = ipheader[7]
    self.source_address = IPv4Address(ipheader[8])
    self.destination_address = IPv4Address(ipheader[9])

    if self.ihl > 5:
      self.options = ipheader[10]

    self.transport_layer = None
    if self.protocol == 17:
      self.transport_layer = self.UDP(raw_datagram[self.ihl * 4:])

  def __str__(self):
    s = ""
    s += "Type of service : %d\n" % self.type_of_service
    s += "IP Header Length: %d\n" % self.ihl
    s += "Total length    : %d\n" % self.total_length
    s += "Identification  : %s\t%d\n" % (hex(self.identification),
                                       self.identification)  # display hex & number
    s += "Flags: %s\n" % self.f_str
    s += "\tReserved      : %s\n" % ("Not set", "Set")[self.f_reserved]
    s += "\tMay Fragment  : %s\n" % ("Not set", "Set")[self.f_may_fragment]
    s += "\tLast Fragment : %s\n" % ("Not set", "Set")[self.f_is_last]
    s += "ToS Precedence: %s\n" % self.TypeOfServicePrecedence[self.precedence]
    s += "Time to live  : %d\n" % self.time_to_live
    if self.protocol in self.protocol_codes:
      s += "Protocol      : %d (%s)\n" % (self.protocol, self.protocol_codes[self.protocol])
    else:
      s += "Protocol      : %d\n" % self.protocol
    s += "Header checksum: %s\n" % hex(self.header_checksum)
    s += "Source IP      : %s\n" % str(self.source_address)
    s += "Destination IP : %s\n" % str(self.destination_address)
    s += "Unpack string  : %s\n" % self.unpackstr

    if self.ihl > 5:
      s += "Options        : %s\n" % hex(self.options)

    if self.transport_layer is not None:
      s += str(self.transport_layer)

    return s
