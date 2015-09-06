__author__ = 'Robbe Van der Gucht'

from random import choice
import socket
import sys
import logging
import internet
from data import init_datastore, save_packet
import atexit

# Set up logger
log_file = 'virtnic.log'
logging.basicConfig(filename=log_file,
                    level=logging.DEBUG,
                    format='%(levelname)s:%(asctime)s:%(message)s')
logger = logging.getLogger(__name__)


@atexit.register
def check_logs():
  print("\nCheck log file %s for errors" % log_file)


class NetworkInterface:

  def get_mac_bytes(self):
    return b''.join([s.decode('hex') for s in self.mac_address.split(':')])

  def get_mac_str(self):
    return self.mac_address

  def __init__(self, mac_address=None):
    if mac_address is None:
      self.mac_address = ''.join([choice(list("0123456789ABCDEF")) if a == 'X' else a for a in list("XX:XX:XX:XX:XX:XX")])
    else:
      self.mac_address = mac_address

  def start_listening(self, datastore_file='packets.dat'):
    """Listen for incoming traffic"""

    try:
      s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
      # socket.ntohs converts bytes from little endian(intel) to big endian(network)
      init_datastore(datastore_file)
    except socket.error, msg:
      logging.critical("Socket could not be created. Error Code: %s Message: %s", str(msg[0]), str(msg[1]))
      sys.exit(1)

    try:
      while 1:
        unit = s.recvfrom(65565)[0]
                                # ^
                                # 65,535 <= max length of IPv4 packet
                                # + ethernet frame header

        logging.debug("TOTAL ETHERNET FRAME LENGTH: %d", len(unit))

        try:
          ethframe = internet.EthernetFrame(unit)
          save_packet(ethframe, datastore_file)
        except internet.Unimplemented as err:
          logging.warning(err.msg)
        except internet.ErrorInvalidDatagram as err:
          logging.error(err.msg)

        print(str(ethframe))

    except KeyboardInterrupt:
      logging.info("Keyboard interrupt received")
      try:
        s.close()
      except socket.error:
        logging.warning("Closing socket failed")
      logging.info("Stopping program")

  def __str__(self):
    s = "Network Interface\n"
    s += "Hardware address: %s" % self.mac_address
    return s

vnic = NetworkInterface()
vnic.start_listening()