import logging
import signal
import sys
import time
import dhcprefix6.config as config
import dhcprefix6.util as util
import dhcprefix6.store as store
import dhcprefix6.dhcp as dhcp
import dhcprefix6.network as network


class App(object):
	VERSION = (1, 0, 0)
	_logger = None
	_handler = None
	_manager = None
	_physical_interfaces = None
	_virtual_interfaces = None

	def __init__(self, config_file):
		# Setup logging
		self._setup_logging()
		self._print_welcome_msg()

		# Setup threading
		self._thread_pool = []
		signal.signal(signal.SIGINT, self._signal_handler)

		# Load application configuration
		self._config = config.AppConfig()
		self._config.load(config_file)
		self._logger.info("Loaded configuration file: %s" % config_file)

		# Initialize stores
		self._physical_interfaces = store.InterfaceStore()
		self._prefixes = store.PrefixStore()

	def run(self):
		try:
			# Reset stores
			self._physical_interfaces.reset()
			self._prefixes.reset()

			# Initialize and validate options
			self._initialize_interfaces()
			self._initialize_prefixes()
			self._validate_interfaces()
			self._validate_prefixes()

			# Group prefixes
			self._build_virtual_interfaces()
			self._dump_virtual_interfaces()

			# Start threads
			self._start_manager()
			self._start_handler()
			self._start_listeners()

			# Keep application running
			while True:
				time.sleep(1)
		except:
			self._logger.exception('Unexpected error occurred in main application thread')
			self._signal_handler()

	def _initialize_interfaces(self):
		for interface in self._config.get('interfaces'):
			interface = self._physical_interfaces.add(dhcp.Interface(
				name=interface['name'],
				mac=interface['mac'],
				ip=interface['ip']
			))

			self._logger.info("Initialized interface %s" % interface)
			self._logger.info("> MAC address: %s" % interface.mac)
			self._logger.info("> Link-local address: %s" % interface.ip)

	def _initialize_prefixes(self):
		for prefix in self._config.get('prefixes'):
			prefix = self._prefixes.add(dhcp.Prefix(
				interface=prefix.get('interface'),
				duid=prefix.get('duid'),
				address=prefix.get('address'),
				length=prefix.get('length')
			))

			self._logger.info("Initialized prefix %s" % prefix)
			self._logger.info("> Interface: %s" % prefix.interface)
			self._logger.info("> Client DUID: %s" % prefix.duid)

	def _validate_interfaces(self):
		used_names = []
		used_macs = []
		used_ips = []

		for interface in self._physical_interfaces.raw():
			if interface.name in used_names:
				raise ValueError("Duplicate interface name detected: %s" % interface.name)
			if interface.mac in used_macs:
				raise ValueError("Duplicate interface mac address detected: %s" % interface.mac)
			if interface.ip in used_ips:
				raise ValueError("Duplicate interface ip address detected: %s" % interface.ip)

			used_names.append(interface.name)
			used_macs.append(interface.mac)
			used_ips.append(interface.ip)

	def _validate_prefixes(self):
		used_duids = []

		for prefix in self._prefixes.raw():
			if self._physical_interfaces.get_by_name(prefix.interface) is None:
				raise ValueError("Prefix %s requires inexistant physical interface %s" % (prefix, prefix.interface))
			if prefix.duid in used_duids:
				raise ValueError("You can only specify one prefix per interface and DUID: %s" % prefix)

			used_duids.append(prefix.duid)

	def _build_virtual_interfaces(self):
		self._virtual_interfaces = list()
		iaid = 25000
		for prefix in self._prefixes.raw():
			self._virtual_interfaces.append(dhcp.VirtualInterface(
				iaid=iaid,
				client_duid=prefix.duid,
				prefix=prefix,
				physical=self._physical_interfaces.get_by_name(prefix.interface),
				logger=self._logger
			))
			iaid += 1

	def _dump_virtual_interfaces(self):
		for viface in self._virtual_interfaces:
			self._logger.debug("Virtual interface #%d" % viface.iaid)
			self._logger.debug("> Physical device: %s" % viface.physical.name)
			self._logger.debug("> MAC address: %s" % viface.physical.mac)
			self._logger.debug("> Link-local address: %s" % viface.physical.ip)
			self._logger.debug("> Client DUID: %s" % viface.client_duid)
			self._logger.debug("> Prefix: %s" % viface.prefix)
		pass

	def _start_handler(self):
		self._handler = network.Handler(self._physical_interfaces, self._prefixes, self._manager, self._logger)
		self._handler.start()
		self._thread_pool.append(self._handler)
		self._logger.info('Started packet handler thread')

	def _start_listeners(self):
		for interface in self._physical_interfaces.raw():
			listener = network.Listener(interface, self._handler.handle)
			listener.start()
			self._thread_pool.append(listener)
			self._logger.info("Started listener on interface %s" % interface)

	def _start_manager(self):
		self._manager = dhcp.Manager(
			virtual_interfaces=self._virtual_interfaces,
			retry_time=int(self._config.get('retry_time')),
			expire_time_multi=float(self._config.get('expire_time_multi')),
			logger=self._logger
		)
		self._manager.start()
		self._thread_pool.append(self._manager)
		self._logger.info('Started manager thread')
		self._logger.info("> Retry time: %d second(s)" % self._config.get('retry_time'))
		self._logger.info("> Expire time multi: T2 x %f" % self._config.get('expire_time_multi'))

	def _setup_logging(self):
		# Global logging options
		logging.basicConfig(format='[%(asctime)s]  %(levelname)s  %(message)s')
		logging.addLevelName(logging.DEBUG, "%s%s%s" % (util.Colors.WHITE, 'DEBUG  ', util.Colors.RESET))
		logging.addLevelName(logging.INFO, "%s%s%s" % (util.Colors.CYAN, 'INFO   ', util.Colors.RESET))
		logging.addLevelName(logging.WARNING, "%s%s%s" % (util.Colors.YELLOW, 'WARNING', util.Colors.RESET))
		logging.addLevelName(logging.ERROR, "%s%s%s" % (util.Colors.RED, 'ERROR  ', util.Colors.RESET))
		logging.addLevelName(logging.CRITICAL, "%s%s%s" % (util.Colors.RED, 'CRITICAL', util.Colors.RESET))

		# Application logger
		self._logger = logging.getLogger('dhcprefix6')
		self._logger.setLevel(logging.INFO)

	def _print_welcome_msg(self):
		self._logger.info('=~=~=~=~=~=~=~=~^ dhcprefix6 ^~=~=~=~=~=~=~=~=')
		self._logger.info("| Author: Pascal Mathis <dev@snapserv.net>   |")
		self._logger.info("| Version: %d.%d.%d                             |" % self.VERSION)
		self._logger.info('=~=~=~=~=~=~=~=~=~=~=~=~=~=~~=~=~=~=~=~=~=~=~=')

	def _signal_handler(self):
		print()
		self._logger.warning('Application aborted. Stopping all threads...')
		self._logger.debug("> Thread count: %d thread(s)" % len(self._thread_pool))

		for thread in self._thread_pool:
			thread.kill_received = True
		sys.exit(0)