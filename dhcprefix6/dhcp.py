import random
import threading
import time
import sys
from datetime import datetime, timedelta
from scapy.arch import get_if_hwaddr, get_if_list
from scapy.layers.dhcp6 import DHCP6OptIAPrefix, DHCP6_Solicit, DHCP6OptClientId, DHCP6OptIA_PD, DHCP6OptElapsedTime, \
	DUID_LL, DHCP6_Advertise, DHCP6OptServerId, DUID_LLT, DHCP6_Request, DHCP6_Reply, DHCP6_Renew, DHCP6_Rebind, \
	DHCP6OptStatusCode, DHCP6OptOptReq
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
import dhcprefix6.types as types

# Try to import the function 'in6_getifaddr', which is
# only supported by UNIX systems. To keep compatiblity
# to windows systems, this nifty little hack was added.
try:
	from scapy.arch import in6_getifaddr
except ImportError:
	pass


class PrefixState(object):
	INITIAL, \
	SOLICITED, \
	ADVERTISED, \
	REQUESTED, \
	CONFIRMED, \
	RENEWING, \
	REBINDING, \
	WITHDRAWN = range(8)

	STRINGS = {
		INITIAL: 'Initial',
		SOLICITED: 'Solicited',
		ADVERTISED: 'Advertised',
		REQUESTED: 'Requested',
		CONFIRMED: 'Confirmed',
		RENEWING: 'Renewing',
		REBINDING: 'Rebinding',
		WITHDRAWN: 'Withdrawn'
	}


class Manager(threading.Thread):
	def __init__(self, virtual_interfaces, retry_time, expire_time_multi, logger):
		threading.Thread.__init__(self)
		self.kill_received = False

		self._virtual_interfaces = virtual_interfaces
		(self._retry_time, self._expire_time_multi) = (retry_time, expire_time_multi)
		self._logger = logger

	def run(self):
		# Wait one second to ensure that all threads are up and running
		time.sleep(1)

		while self.kill_received is not True:
			try:
				# Solicit all virtual interfaces with a state of INITIAL or WITHDRAWN
				vifaces = self._get_viface_by_states([PrefixState.INITIAL, PrefixState.WITHDRAWN])
				for viface in vifaces:
					self._solicit(viface)

				# Request all advertised prefixes on every virtual interface
				vifaces = self._get_viface_by_states([PrefixState.ADVERTISED])
				for viface in vifaces:
					self._request(viface)

				# Search for confirmed prefixes where T1 or T2 has expired
				vifaces = self._get_viface_by_states([PrefixState.CONFIRMED])
				for viface in vifaces:
					if viface.expire.has_occured(viface.last_confirm):
						self._logger.warning(
							"Unable to renew or rebind prefix %s - resetting state to initial" % viface.prefix)
						viface.state = PrefixState.INITIAL
					elif viface.t2.has_occured(viface.last_confirm):
						self._rebind(viface)
					elif viface.t1.has_occured(viface.last_confirm):
						self._renew(viface)

				# Search for timeouted messages
				vifaces = self._get_viface_by_states(
					[PrefixState.SOLICITED, PrefixState.REQUESTED, PrefixState.RENEWING, PrefixState.REBINDING])
				trigger_value = datetime.now() - timedelta(seconds=self._retry_time)
				for viface in vifaces:
					if viface.last_action < trigger_value:
						self._logger.info(
							"State %s of prefix %s timeouted." % (PrefixState.STRINGS[viface.state], viface.prefix))
						if viface.state in [PrefixState.SOLICITED, PrefixState.REQUESTED]:
							viface.state = PrefixState.INITIAL
						elif viface.state in [PrefixState.RENEWING, PrefixState.REBINDING]:
							viface.state = PrefixState.CONFIRMED
			except:
				self._logging.exception('Unexpected error occurred in manager thread')

			# Sleep for one second to avoid CPU load
			time.sleep(1)

	def handle_packet(self, client_duid, packet):
		try:
			# Try to find virtual interface by client DUID
			viface = self._get_viface_by_client_duid(client_duid)
			if viface is None:
				self._logger.warning("Could not find virtual interface with client DUID %s" % (client_duid))
				return

			# Process packet based on its type
			if DHCP6_Advertise in packet:
				self._handle_advertise(viface, packet)
			elif DHCP6_Reply in packet:
				self._handle_reply(viface, packet)
		except:
			self._logging.exception('Unexpected error occurred in packet handler')

	def _solicit(self, viface):
		# Set the state of the virtual interface
		viface.state = PrefixState.SOLICITED
		viface.last_action = datetime.now()

		# Build and send SOLICIT message
		viface.transaction_id = PacketBuilder.generate_transaction_id()
		packet = PacketBuilder.solicit(viface)
		viface.send(packet)

		# Print some debug information
		self._logger.info("Sent SOLICIT message on virtual interface %s" % viface)
		self._logger.debug("> Client DUID: %s" % viface.client_duid)
		self._logger.debug("> Prefix: %s" % viface.prefix)

	def _request(self, viface):
		# Set the state of the virtual interface
		viface.state = PrefixState.REQUESTED
		viface.last_action = datetime.now()

		# Build and send REQUEST message
		packet = PacketBuilder.request(viface)
		viface.send(packet)

		# Print some debug information
		self._logger.info("Sent REQUEST message on virtual interface %s" % viface)
		self._logger.debug("> Client DUID: %s" % viface.client_duid)
		self._logger.debug("> Server DUID: %s" % viface.server_duid)
		self._logger.debug("> Prefix: %s" % viface.prefix)
		self._logger.debug("> Timeouts: T1=%d, T2=%d, Expire=%d" % (viface.t1, viface.t2, viface.expire))

	def _renew(self, viface):
		# Set the state of the virtual interface
		viface.state = PrefixState.RENEWING
		viface.last_action = datetime.now()

		# Build and send RENEW message
		packet = PacketBuilder.renew(viface)
		viface.send(packet)

		# Print some debug information
		self._logger.info("Sent RENEW message on virtual interface %s" % viface)
		self._logger.debug("> Client DUID: %s" % viface.client_duid)
		self._logger.debug("> Server DUID: %s" % viface.server_duid)
		self._logger.debug("> Prefix: %s" % viface.prefix)
		self._logger.debug("> Timeouts: T1=%d, T2=%d, Expire=%d" % (viface.t1, viface.t2, viface.expire))

	def _rebind(self, viface):
		# Set the state of the virtual interface
		viface.state = PrefixState.REBINDING
		viface.last_action = datetime.now()

		# Build and send REBIND message
		packet = PacketBuilder.rebind(viface)
		viface.send(packet)

		# Print some debug information
		self._logger.info("Sent REBIND message on virtual interface %s" % viface)
		self._logger.debug("> Client DUID: %s" % viface.client_duid)
		self._logger.debug("> Prefix: %s" % viface.prefix)
		self._logger.debug("> Timeouts: T1=%d, T2=%d, Expire=%d" % (viface.t1, viface.t2, viface.expire))

	def _handle_advertise(self, viface, packet):
		# Drop packet if interface state is incorrect
		if viface.state is not PrefixState.SOLICITED:
			return

		# Check if packet is valid and contains a prefix
		if DHCP6OptServerId not in packet:
			self._logger.warning("Dropped ADVERTISE message with invalid options on virtual interface %s" % viface)
		if DHCP6OptIA_PD not in packet or DHCP6OptIAPrefix not in packet:
			self._logger.warning("ADVERTISE message on virtual interface %s does not contain any prefixes" % viface)
			viface.state = PrefixState.INITIAL
			return

		# Check status code if available
		if DHCP6OptStatusCode in packet and packet[DHCP6OptStatusCode].statuscode != 0:
			self._logger.warning("Dropped REPLY message with status: %s" % packet[DHCP6OptStatusCode].statusmsg)
			return

		# Compare advertised prefix against configured one
		configured_prefix = str(viface.prefix)
		announced_prefix = "%s/%d" % (packet[DHCP6OptIAPrefix].prefix, packet[DHCP6OptIAPrefix].plen)
		if configured_prefix != announced_prefix:
			viface.state = PrefixState.INITIAL

			self._logger.warning("Announced prefix does not match configured prefix!")
			self._logger.info("> Virtual interface: %s" % viface)
			self._logger.info("> Announced prefix: %s" % announced_prefix)
			self._logger.info("> Configure prefix: %s" % configured_prefix)

		# Reset the interface, if T1 is bigger than T2
		if packet[DHCP6OptIA_PD].T1 > packet[DHCP6OptIA_PD].T2:
			self._logger.warning("Dropped ADVERTISE message with invalid timeouts: T1=%d, T2=%d" %
				(packet[DHCP6OptIA_PD].T1, packet[DHCP6OptIA_PD].T2))
			viface.state = PrefixState.INITIAL

		# If preferred or valid lifetime of prefix is zero, reset the interface state to INITIAL
		if packet[DHCP6OptIAPrefix].preflft == 0 or packet[DHCP6OptIAPrefix].validlft == 0:
			self._logger.warning("Dropped ADVERTISE message with invalid lifetime: preflft=%d, validlft=%d" %
				(packet[DHCP6OptIAPrefix].preflft, packet[DHCP6OptIAPrefix].validlft))
			viface.state = PrefixState.INITIAL

		# Change interface state to ADVERTISED
		viface.state = PrefixState.ADVERTISED
		viface.server_duid = PacketBuilder.scapy_to_duid(packet[DHCP6OptServerId])
		viface.t1 = types.DhcpTimeout(packet[DHCP6OptIA_PD].T1)
		viface.t2 = types.DhcpTimeout(packet[DHCP6OptIA_PD].T2)
		viface.expire = types.DhcpTimeout(packet[DHCP6OptIA_PD].T2 * self._expire_time_multi)

		self._logger.info("Received ADVERTISE message on virtual interface %s" % viface)
		self._logger.debug("> Client DUID: %s" % viface.client_duid)
		self._logger.debug("> Server DUID: %s" % viface.server_duid)
		self._logger.debug("> Prefix: %s" % viface.prefix)

	def _handle_reply(self, viface, packet):
		# Drop packet if interface state is incorrect
		if viface.state not in [PrefixState.REQUESTED, PrefixState.RENEWING, PrefixState.REBINDING]:
			return

		# Check if packet is valid
		if DHCP6OptServerId not in packet:
			self._logger.warning("Dropped REPLY message with invalid options on virtual interface %s" % viface)

		# Drop message if server DUID does not match stored one
		# Exception: When interface is in state REBINDING, accept any server DUID
		server_duid = PacketBuilder.scapy_to_duid(packet[DHCP6OptServerId])
		if viface.state is PrefixState.REBINDING:
			viface.server_duid = PacketBuilder.scapy_to_duid(packet[DHCP6OptServerId])
		else:
			if str(server_duid) != str(viface.server_duid):
				self._logger.debug("Dropped REPLY message from unknown server DUID: %s" % server_duid)
				return

		# Check status code if available
		if DHCP6OptStatusCode in packet and packet[DHCP6OptStatusCode].statuscode != 0:
			self._logger.warning("Dropped REPLY message with status: %s" % packet[DHCP6OptStatusCode].statusmsg)
			return

		# Drop message and reset interface state to INITIAL if no prefix was confirmed
		# Exception: When interface is in state REBINDING, reset the state to WITHDRAWN
		if DHCP6OptIA_PD not in packet or DHCP6OptIAPrefix not in packet:
			self._logger.warning("REPLY message on virtual interface %s did not confirm any prefixes" % viface)
			if viface.state is not PrefixState.REBINDING:
				viface.state = PrefixState.INITIAL
			else:
				viface.state = PrefixState.WITHDRAWN
				self._logger.warning("Prefix %s was marked as withdrawn by server" % viface.prefix)
			return

		# Compare confirmed prefix against configured one
		configured_prefix = str(viface.prefix)
		confirmed_prefix = "%s/%d" % (packet[DHCP6OptIAPrefix].prefix, packet[DHCP6OptIAPrefix].plen)
		if configured_prefix != confirmed_prefix:
			viface.state = PrefixState.INITIAL

			self._logger.warning("Confirmed prefix does not match configured prefix!")
			self._logger.info("> Virtual interface: %s" % viface)
			self._logger.info("> Confirmed prefix: %s" % confirmed_prefix)
			self._logger.info("> Configure prefix: %s" % configured_prefix)

		# Reset the interface, if T1 is bigger than T2
		if packet[DHCP6OptIA_PD].T1 > packet[DHCP6OptIA_PD].T2:
			self._logger.warning("Dropped REPLY message with invalid timeouts: T1=%d, T2=%d" %
				(packet[DHCP6OptIA_PD].T1, packet[DHCP6OptIA_PD].T2))
			viface.state = PrefixState.INITIAL

		# If preferred or valid lifetime of prefix is zero, set the interface state to WITHDRAWN
		if packet[DHCP6OptIAPrefix].preflft == 0 or packet[DHCP6OptIAPrefix].validlft == 0:
			self._logger.warning("Prefix %s was marked as withdrawn by server" % viface.prefix)
			viface.state = PrefixState.WITHDRAWN

		# If T1 and/or T2 were not set, calculate timeout values base on RFC3633
		if packet[DHCP6OptIA_PD].T1 == 0 or packet[DHCP6OptIA_PD].T2 == 0:
			packet[DHCP6OptIA_PD].T1 = packet[DHCP6OptIAPrefix].preflft * 0.5
			packet[DHCP6OptIA_PD].T2 = packet[DHCP6OptIAPrefix].preflft * 0.8

		# Change interface state to CONFIRMED
		viface.state = PrefixState.CONFIRMED
		viface.last_confirm = datetime.now()
		viface.t1 = types.DhcpTimeout(packet[DHCP6OptIA_PD].T1)
		viface.t2 = types.DhcpTimeout(packet[DHCP6OptIA_PD].T2)
		viface.expire = types.DhcpTimeout(packet[DHCP6OptIA_PD].T2 * self._expire_time_multi)

		self._logger.info("Received REPLY message on virtual interface %s" % viface)
		self._logger.debug("> Client DUID: %s" % viface.client_duid)
		self._logger.debug("> Server DUID: %s" % viface.server_duid)
		self._logger.debug("> Prefix: %s" % viface.prefix)
		self._logger.debug("> Timeouts: T1=%d, T2=%d, Expire=%d" % (viface.t1, viface.t2, viface.expire))

	def _get_viface_by_client_duid(self, client_duid):
		for viface in self._virtual_interfaces:
			if str(viface.client_duid) == str(client_duid):
				return viface
		return None

	def _get_viface_by_states(self, states):
		return [viface for viface in self._virtual_interfaces if viface.state in states]


class PacketBuilder(object):
	@staticmethod
	def solicit(viface):
		ether_head = PacketBuilder.build_ether_head(viface.physical)
		iapdopt = [DHCP6OptIAPrefix(prefix=str(viface.prefix.address), plen=int(viface.prefix.length))]

		packet = ether_head / DHCP6_Solicit(trid=int(viface.transaction_id))
		packet = packet / DHCP6OptClientId(duid=PacketBuilder.duid_to_scapy(viface.client_duid))
		packet = packet / DHCP6OptIA_PD(iaid=int(viface.iaid), iapdopt=iapdopt)
		packet = packet / DHCP6OptElapsedTime()

		return packet

	@staticmethod
	def request(viface):
		ether_head = PacketBuilder.build_ether_head(viface.physical)
		iapdopt = [DHCP6OptIAPrefix(prefix=str(viface.prefix.address), plen=int(viface.prefix.length))]

		packet = ether_head / DHCP6_Request(trid=int(viface.transaction_id))
		packet = packet / DHCP6OptClientId(duid=PacketBuilder.duid_to_scapy(viface.client_duid))
		packet = packet / DHCP6OptServerId(duid=PacketBuilder.duid_to_scapy(viface.server_duid))
		packet = packet / DHCP6OptIA_PD(iaid=int(viface.iaid), T1=int(viface.t1), T2=int(viface.t2), iapdopt=iapdopt)
		packet = packet / DHCP6OptElapsedTime()

		return packet

	@staticmethod
	def renew(viface):
		ether_head = PacketBuilder.build_ether_head(viface.physical)
		iapdopt = [DHCP6OptIAPrefix(prefix=str(viface.prefix.address), plen=int(viface.prefix.length))]

		packet = ether_head / DHCP6_Renew(trid=int(viface.transaction_id))
		packet = packet / DHCP6OptClientId(duid=PacketBuilder.duid_to_scapy(viface.client_duid))
		packet = packet / DHCP6OptServerId(duid=PacketBuilder.duid_to_scapy(viface.server_duid))
		packet = packet / DHCP6OptIA_PD(iaid=int(viface.iaid), T1=int(viface.t1), T2=int(viface.t2), iapdopt=iapdopt)
		packet = packet / DHCP6OptElapsedTime()

		return packet

	@staticmethod
	def rebind(viface):
		ether_head = PacketBuilder.build_ether_head(viface.physical)
		iapdopt = [DHCP6OptIAPrefix(prefix=str(viface.prefix.address), plen=int(viface.prefix.length))]

		packet = ether_head / DHCP6_Rebind(trid=int(viface.transaction_id))
		packet = packet / DHCP6OptClientId(duid=PacketBuilder.duid_to_scapy(viface.client_duid))
		packet = packet / DHCP6OptIA_PD(iaid=int(viface.iaid), iapdopt=iapdopt)
		packet = packet / DHCP6OptElapsedTime()

		return packet

	@staticmethod
	def build_ether_head(interface):
		ether_head = Ether(src=str(interface.mac), dst='33:33:00:01:00:02')
		ether_head = ether_head / IPv6(src=str(interface.ip), dst='ff02::1:2')
		ether_head = ether_head / UDP(sport=546, dport=547)

		return ether_head

	@staticmethod
	def duid_to_scapy(duid):
		duid = str(duid)
		duid_type = int(duid[0:5].replace(':', ''), 16)
		hw_type = int(duid[6:11].replace(':', ''), 16)

		if duid_type is 1:
			timeval = int(duid[12:23].replace(':', ''), 16)
			lladdr = duid[24:]
			return DUID_LLT(hwtype=hw_type, timeval=timeval, lladdr=lladdr)
		elif duid_type is 3:
			lladdr = duid[12:]
			return DUID_LL(hwtype=hw_type, lladdr=lladdr)

	@staticmethod
	def scapy_to_duid(serverid_opt):
		return types.DeviceID(':'.join([hex(x)[2:].zfill(2) for x in map(ord, str(serverid_opt.duid))]))

	@staticmethod
	def generate_transaction_id():
		return types.TransactionID(random.randint(0x000000, 0xffffff))


class Interface(object):
	last_action = None
	transaction_id = None

	def __init__(self, name, mac, ip):
		# Validate and amend interface options
		self.validate_iface_name(name)
		mac = self.get_iface_mac(name) if mac is None else mac
		ip = self.get_iface_lladdr(name) if ip is None else ip

		# Check if autodetection worked
		if mac is None:
			raise EnvironmentError("Could not determine mac address of interface %s" % name)
		if ip is None:
			raise EnvironmentError("Could not determine link local address of interface %s" % name)

		# Assign interface options
		self.name = types.InterfaceName(name)
		self.mac = types.MacAdress(mac)
		self.ip = types.Ipv6Address(ip)

	def __str__(self):
		return str(self.name)

	def send(self, packet):
		sendp(packet, iface=str(self.name), verbose=False)

	@staticmethod
	def validate_iface_name(name):
		if name not in get_if_list():
			raise EnvironmentError("Could not find interface %s" % name)

	@staticmethod
	def get_iface_mac(name):
		return get_if_hwaddr(name)

	@staticmethod
	def get_iface_lladdr(name):
		for addr, _, iface in in6_getifaddr():
			if iface == name and addr.startswith('fe80::'):
				return addr


class Prefix(object):
	def __init__(self, interface, duid, address, length):
		self.interface = types.InterfaceName(interface)
		self.duid = types.DeviceID(duid)
		self.address = types.Ipv6Address(address)
		self.length = types.Ipv6PrefixLength(length)

	def __str__(self):
		return "%s/%d" % (self.address, int(self.length))

	def get_address(self):
		return self.address

	def get_length(self):
		return self.length


class VirtualInterface(object):
	def __init__(self, iaid, client_duid, prefix, physical, logger=None):
		# Assign default properties
		self._state = PrefixState.INITIAL
		self.last_action = None
		self.last_confirm = None
		self.transaction_id = None
		self.server_duid = None
		self.t1 = None
		self.t2 = None
		self.expire = None
		self._logger = logger

		# Assign user-defined properties
		self.iaid = types.InterfaceID(iaid)
		self.client_duid = client_duid
		self.prefix = prefix
		self.physical = physical

	def __str__(self):
		return "%s[%d]" % (self.physical.name, int(self.iaid))

	def send(self, packet):
		return self.physical.send(packet)

	@property
	def state(self):
		return self._state

	@state.setter
	def state(self, value):
		if self._logger is not None:
			if value in [PrefixState.CONFIRMED, PrefixState.RENEWING, PrefixState.REBINDING, PrefixState.WITHDRAWN]:
				self._logger.info("State of prefix %s has changed to: %s" % (self.prefix, PrefixState.STRINGS[value]))
			else:
				self._logger.debug("State of prefix %s has changed to: %s" % (self.prefix, PrefixState.STRINGS[value]))
		self._state = value