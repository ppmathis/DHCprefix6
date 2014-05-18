import threading
import time
import sys
from scapy.layers.dhcp6 import DHCP6OptClientId
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff


class Listener(threading.Thread):
	FILTER = 'icmp6 or (udp and src port 547 and dst port 546)'

	def __init__(self, interface, handler):
		threading.Thread.__init__(self)
		self.kill_received = False
		(self._interface, self._handler) = interface, handler

	def run(self):
		while self.kill_received is not True:
			try:
				sniff(
					filter=self.FILTER,
					prn=self._dispatch_to_handler,
					store=0,
					timeout=5,
					iface=str(self._interface.name)
				)
			except:
				self._logger.exception('Unexpected error occurred in listener thread')

	def _dispatch_to_handler(self, packet):
		self._handler(self._interface, packet)


class Handler(threading.Thread):
	def __init__(self, interfaces, prefixes, manager, logger):
		threading.Thread.__init__(self)
		self.kill_received = False

		self._queue = []
		(self._interfaces, self._prefixes, self._manager, self._logger) = (interfaces, prefixes, manager, logger)

	def run(self):
		while self.kill_received is not True:
			try:
				# Grab packet from queue or wait if no tasks are available
				if len(self._queue) == 0:
					time.sleep(0)
				else:
					packet = self._queue.pop()
					self._process_packet(packet[0], packet[1])
			except:
				self._logger.exception('Unexpected error occurred in packet handler thread')

	def handle(self, interface, packet):
		self._queue.append([interface, packet])

	def _process_packet(self, interface, packet):
		# Drop some various types of bogus packets
		if Ether not in packet:
			return
		if str(interface.mac) != (packet[Ether].dst):
			return
		if DHCP6OptClientId not in packet:
			return

		# Determine client ID and try to find a matching prefix
		client_duid = "00:03:00:01:%s" % str(packet[DHCP6OptClientId].duid.lladdr)
		prefix = self._prefixes.get_by_duid(client_duid)
		if prefix is None:
			self._logger.debug("Dropped packet with invalid DUID: %s" % client_duid)
			return

		self._manager.handle_packet(client_duid, packet)