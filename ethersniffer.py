#!/usr/bin/python

import socket
import sys
import internet
import logging
import atexit

"""Listen on an ethernet port and print out traffic"""

# Set up logger
log_file = 'ethersniffer.log'
logging.basicConfig(filename=log_file,
                    level=logging.DEBUG,
                    format='%(levelname)s:%(asctime)s:%(message)s')
logger = logging.getLogger(__name__)


@atexit.register
def check_logs():
  print("\nCheck log file %s for errors" % log_file)

try:
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
  # socket.ntohs converts bytes from little endian(intel) to big endian(network)
except socket.error, msg:
  logging.critical("Socket could not be created. Error Code: %s Message: %s", str(msg[0]), str(msg[1]))
  sys.exit(1)

while 1:
  unit = s.recvfrom(65565)[0]
                          # ^ 
                          # 65,535 <= max length of IPv4 packet
                          # + ethernet frame header

  print('#' * 80)
  print("TOTAL ETHERNET FRAME LENGTH: %d" % len(unit))

  try:
    ethframe = internet.EthernetFrame(unit)
  except internet.Unimplemented as err:
    logging.warning(err.msg)
  except internet.ErrorInvalidDatagram as err:
    logging.error(err.msg)

  print(str(ethframe))





