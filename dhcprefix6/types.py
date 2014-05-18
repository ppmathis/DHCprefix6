import re
from datetime import datetime, timedelta
import dhcprefix6.validation as validation

UINT8_MIN = 0
UINT8_MAX = 2 ** 10 - 1
UINT16_MIN = 0
UINT16_MAX = 2 ** 16 - 1
UINT24_MIN = 0
UINT24_MAX = 2 ** 24 - 1
UINT32_MIN = 0
UINT32_MAX = 2 ** 32 - 1

IPV6_PREFIX_LENGTH_MIN = 8
IPV6_PREFIX_LENGTH_MAX = 128


class InterfaceName(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, str): return False
		return True


class MacAdress(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, str): return False
		if not re.match('[0-9a-f]{2}(:[0-9a-f]{2}){5}$', value.lower()): return False
		return True


class DeviceID(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, str): return False
		return True


class InterfaceID(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, int): return False
		if value < UINT32_MIN or value > UINT32_MAX: return False
		return True


class TransactionID(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, int): return False
		if value < UINT24_MIN or value > UINT24_MAX: return False
		return True


class Ipv6Address(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, str): return False
		return True


class Ipv6PrefixLength(validation.ValidatedType):
	@staticmethod
	def validate(value):
		if not isinstance(value, int): return False
		if value < IPV6_PREFIX_LENGTH_MIN or value > IPV6_PREFIX_LENGTH_MAX: return False
		return True


class DhcpTimeout(object):
	def __init__(self, timeout):
		self._timeout = int(timeout)
		self._delta = timedelta(seconds=int(timeout))

	def __int__(self):
		return self._timeout

	def as_delta(self):
		return self._delta

	def has_occured(self, offset):
		now = datetime.now()
		return now > offset + self._delta