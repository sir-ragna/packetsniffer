__author__ = 'Robbe Van der Gucht'

import re

ascii_ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

class IPv4Address:
  from socket import inet_ntoa
  from socket import inet_aton
  """RFC 791 only defines 3 address classes. A, B and C"""

  def __init__(self, addr):
    if ascii_ip_pattern.match(addr):  # ascii to native
      self.s_address = addr
      self.b_address = self.inet_aton(addr)
    else:  # native to ascii
      self.b_address = addr
      self.s_address = self.inet_ntoa(addr)

    self.addr_class = "UNKNOWN"

    first_byte = int("0x%.2x" % ord(self.b_address[0]), 16)  # Can be more elegant

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