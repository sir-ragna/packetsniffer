__author__ = 'Robbe Van der Gucht'

import cPickle as pickle
import logging
import os

def init_datastore(filename):
  if os.path.isfile(filename):
    logging.warning("%s already exists", str(filename))
    return
  try:
    with open(filename, 'wb') as file_handle:
      pickle.dump([], file_handle)
  except IOError:
    logging.critical("Could not create file %s", str(filename))


def save_packets(newpackets, file_name):
  try:
    with open(file_name, 'rb') as file_handle:

      storedpackets = pickle.load(file_handle)
      logging.debug("Opened %s for writing packets", str(file_name))
      file_handle.close()
    with open(file_name, 'wb') as file_handle:
      pickle.dump(storedpackets + newpackets, file_handle)
      file_handle.close()
      logging.debug("Packet(s) written to datastore - %s", str(file_name))
  except IOError as err:
    logging.critical("Could not store ethernet frames in datastore. File: %s\tError: %s", str(file_name), str(err))


def save_packet(packet, file_name):
  save_packets([packet], file_name)


def retrieve_packets(file_name):
  try:
    with open(file_name, 'rb') as file_handle:
      data = pickle.load(file_handle)
      return data
  except IOError:
    logging.critical("Could not retrieve ethernet frames from data storage. File: %s", str(file_name))

