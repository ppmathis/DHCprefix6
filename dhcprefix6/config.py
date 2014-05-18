import yaml
import logging


class AppConfig(object):
	_config = None

	def __init__(self):
		pass

	def load(self, config_path):
		if self._config is not None:
			raise Exception('Application configuration can only be loaded once')

		with open(config_path, 'r') as config_file:
			raw_config = yaml.load(config_file.read())
			self._validate(raw_config)

	def _validate(self, raw_config):
		# Reset configuration
		self._config = dict()
		self._config['interfaces'] = list()
		self._config['prefixes'] = list()

		# Basic configuration values
		self._config['retry_time'] = raw_config.get('retry_time', 60)
		self._config['expire_time_multi'] = raw_config.get('expire_time_multi', 1.5)

		# Parse interfaces
		for interface in raw_config.get('interfaces', []):
			self._config['interfaces'].append({
				'name': interface.get('name'),
				'mac': interface.get('mac', None),
				'ip': interface.get('ip', None)
			})

		# Parse prefixes
		for prefix in raw_config.get('prefixes', []):
			self._config['prefixes'].append({
				'interface': prefix.get('interface'),
				'duid': prefix.get('duid'),
				'address': prefix.get('address'),
				'length': prefix.get('length')
			})

	def get(self, key):
		return self._config[key]