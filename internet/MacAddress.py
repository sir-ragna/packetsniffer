__author__ = 'Robbe Van der Gucht'


def readable_mac(address):
   return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(address[0]), ord(address[1]), ord(address[2]),
                                             ord(address[3]), ord(address[4]), ord(address[5]))


class MacAddress:

  def __getitem__(self, index):
    """Return byte from MAC Address based upon index"""
    return self.address[index]

  def __str__(self):
    """Print a human readable string of MAC Address"""
    return readable_mac(self.address)

  def __init__(self, address):
    self.address = address


