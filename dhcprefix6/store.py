class Store(object):
	_store = None

	def __init__(self):
		self.reset()

	def reset(self):
		self._store = list()

	def add(self, data):
		self._store.append(data)
		return data

	def get(self, key):
		return self._store[key]

	def set(self, key, data):
		self._store[key] = data
		return data

	def raw(self):
		return self._store


class InterfaceStore(Store):
	def get_by_name(self, name):
		for interface in self._store:
			if interface.name == name: return interface
		return None


class PrefixStore(Store):
	def get_by_duid(self, duid):
		for prefix in self._store:
			if str(prefix.duid) == str(duid): return prefix
		return None