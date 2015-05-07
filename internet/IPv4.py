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
  TypeOfServicePrecedence = { 0b111: "Network Control",
                              0b110: "Internetwork Control",
                              0b101: "CRITIC/ECP",
                              0b100: "Flash Override",
                              0b011: "Flash",
                              0b010: "Immediate",
                              0b001: "Priority",
                              0b000: "Routine" }

  def __init__(self, raw_datagram=None):
    if raw_datagram is None:
      raise ErrorInvalidDatagram("Cannot unpack empty datagram.")
    vihl = self.unpack("!B", raw_datagram[:1])  # version + ip header length
    self.version = vihl[0] >> 4
    self.ihl = vihl[0] & 0x0F  # ihl => number of 32 bit words in header (max: 15)
    print("IHL: %d" % self.ihl)

    if self.ihl < 5:  # less then minimum length
      raise ErrorInvalidDatagram("IHL is less than minimum(5). IHL :: " + str(self.ihl))

    unpackstr = '!BBHHHBBH4s4s'  # for ihl == 5
    # ! - big-endian (network std)
    # B - unsigned char   (int)    8 bits
    # H - unsigned short  (int)    16 bits
    # s - char[]          (bytes)  8[] bits

    if self.ihl >= 5: # minimum
      ipheader = self.unpack(unpackstr, raw_datagram[:5 * 4])  # 5 * 4 bytes | 5 * 32 bits
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
        # TODO implement IP datagram headers longer than 20 bytes :-)
        raise Exception("Not implemented yet [IP HEADER LONGER THAN 20 BYTES]")

  def __str__(self):
    s = ""
    s += "Type of service: %d\n" % self.type_of_service
    s += "Total length: %d\n" % self.total_length
    s += "Identification: %s\t%d\n" % (hex(self.identification),
                                       self.identification)  # display hex & number
    s += "Flags: %s\n" % self.f_str
    s += "\tReserved      : %s\n" % ("Not set", "Set")[self.f_reserved]
    s += "\tMay Fragment  : %s\n" % ("Not set", "Set")[self.f_may_fragment]
    s += "\tLast Fragment : %s\n" % ("Not set", "Set")[self.f_is_last]
    s += "ToS Precedence: %s\n" % self.TypeOfServicePrecedence[self.precedence]
    s += "Time to live: %d\n" % self.time_to_live
    s += "Protocol: %d\n" % self.protocol
    s += "Header checksum: %s\n" % hex(self.header_checksum)
    s += "Source IP      : %s\n" % str(self.source_address)
    s += "Destination IP : %s\n" % str(self.destination_address)
    return s
