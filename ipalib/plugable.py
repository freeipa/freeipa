# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Base classes for plug-in architecture and generative API.
"""

import re
import inspect
import errors


def to_cli(name):
	"""
	Takes a Python identifier and transforms it into form suitable for the
	Command Line Interface.
	"""
	assert isinstance(name, str)
	return name.replace('_', '-')


def from_cli(cli_name):
	"""
	Takes a string from the Command Line Interface and transforms it into a
	Python identifier.
	"""
	assert isinstance(cli_name, basestring)
	return cli_name.replace('-', '_')


def check_identifier(name):
	"""
	Raises errors.NameSpaceError if `name` is not a valid Python identifier
	suitable for use in a NameSpace.
	"""
	regex = r'^[a-z][_a-z0-9]*[a-z0-9]$'
	if re.match(regex, name) is None:
		raise errors.NameSpaceError(name, regex)


class Plugin(object):
	"""
	Base class for all plugins.
	"""

	__api = None

	def __get_api(self):
		"""
		Returns the plugable.API instance passed to Plugin.finalize(), or
		or returns None if finalize() has not yet been called.
		"""
		return self.__api
	api = property(__get_api)

	def finalize(self, api):
		"""
		After all the plugins are instantiated, the plugable.API calls this
		method, passing itself as the only argument. This is where plugins
		should check that other plugins they depend upon have actually be
		loaded.
		"""
		assert self.__api is None, 'finalize() can only be called once'
		assert api is not None, 'finalize() argument cannot be None'
		self.__api = api

	def __get_name(self):
		"""
		Returns the class name of this instance.
		"""
		return self.__class__.__name__
	name = property(__get_name)

	def __repr__(self):
		"""
		Returns a fully qualified <module><name> representation of the class.
		"""
		return '%s.%s()' % (
			self.__class__.__module__,
			self.__class__.__name__
		)


class ReadOnly(object):
	"""
	Base class for classes with read-only attributes.
	"""
	__slots__ = tuple()

	def __setattr__(self, name, value):
		"""
		This raises an AttributeError anytime an attempt is made to set an
		attribute.
		"""
		raise AttributeError('read-only: cannot set %s.%s' %
			(self.__class__.__name__, name)
		)

	def __delattr__(self, name):
		"""
		This raises an AttributeError anytime an attempt is made to delete an
		attribute.
		"""
		raise AttributeError('read-only: cannot del %s.%s' %
			(self.__class__.__name__, name)
		)


class Proxy(ReadOnly):
	__slots__ = (
		'__base',
		'__target',
		'__name_attr',
		'__public',
		'name',
	)

	def __init__(self, base, target, name_attr='name'):
		if not inspect.isclass(base):
			raise TypeError('arg1 must be a class, got %r' % base)
		if not isinstance(target, base):
			raise ValueError('arg2 must be instance of arg1, got %r' % target)
		object.__setattr__(self, '_Proxy__base', base)
		object.__setattr__(self, '_Proxy__target', target)
		object.__setattr__(self, '_Proxy__name_attr', name_attr)
		object.__setattr__(self, '_Proxy__public', base.__public__)
		object.__setattr__(self, 'name', getattr(target, name_attr))

		# Check __public
		assert type(self.__public) is frozenset

		# Check name
		check_identifier(self.name)

	def __iter__(self):
		for name in sorted(self.__public):
			yield name

	def __getitem__(self, key):
		if key in self.__public:
			return getattr(self.__target, key)
		raise KeyError('no proxy attribute %r' % key)

	def __getattr__(self, name):
		if name in self.__public:
			return getattr(self.__target, name)
		raise AttributeError('no proxy attribute %r' % name)

	def __call__(self, *args, **kw):
		return self['__call__'](*args, **kw)

	def _clone(self, name_attr):
		return self.__class__(self.__base, self.__target, name_attr)

	def __repr__(self):
		return '%s(%s, %r, %r)' % (
			self.__class__.__name__,
			self.__base.__name__,
			self.__target,
			self.__name_attr,
		)


class NameSpace(ReadOnly):
	"""
	A read-only namespace of (key, value) pairs that can be accessed
	both as instance attributes and as dictionary items.
	"""

	def __init__(self, proxies):
		"""
		NameSpace
		"""
		object.__setattr__(self, '_NameSpace__proxies', tuple(proxies))
		object.__setattr__(self, '_NameSpace__d', dict())
		for proxy in self.__proxies:
			assert isinstance(proxy, Proxy)
			assert proxy.name not in self.__d
			self.__d[proxy.name] = proxy
			assert not hasattr(self, proxy.name)
			object.__setattr__(self, proxy.name, proxy)

	def __iter__(self):
		"""
		Iterates through the proxies in this NameSpace in the same order they
		were passed in the contructor.
		"""
		for proxy in self.__proxies:
			yield proxy

	def __len__(self):
		"""
		Returns number of proxies in this NameSpace.
		"""
		return len(self.__proxies)

	def __contains__(self, key):
		"""
		Returns True if a proxy named `key` is in this NameSpace.
		"""
		return key in self.__d

	def __getitem__(self, key):
		"""
		Returns proxy named `key`; otherwise raises KeyError.
		"""
		if key in self.__d:
			return self.__d[key]
		raise KeyError('NameSpace has no item for key %r' % key)

	def __repr__(self):
		return '%s(<%d proxies>)' % (self.__class__.__name__, len(self))


class Registrar(object):
	def __init__(self, *allowed):
		"""
		`*allowed` is a list of the base classes plugins can be subclassed
		from.
		"""
		self.__allowed = frozenset(allowed)
		self.__d = {}
		self.__registered = set()
		assert len(self.__allowed) == len(allowed)
		for base in self.__allowed:
			assert inspect.isclass(base)
			assert base.__name__ not in self.__d
			self.__d[base.__name__] = {}

	def __findbase(self, cls):
		"""
		If `cls` is a subclass of a base in self.__allowed, returns that
		base; otherwise raises SubclassError.
		"""
		assert inspect.isclass(cls)
		found = False
		for base in self.__allowed:
			if issubclass(cls, base):
				found = True
				yield base
		if not found:
			raise errors.SubclassError(cls, self.__allowed)

	def __call__(self, cls, override=False):
		"""
		Register the plugin `cls`.
		"""
		if not inspect.isclass(cls):
			raise TypeError('plugin must be a class: %r'  % cls)

		# Raise DuplicateError if this exact class was already registered:
		if cls in self.__registered:
			raise errors.DuplicateError(cls)

		# Find the base class or raise SubclassError:
		for base in self.__findbase(cls):
			sub_d = self.__d[base.__name__]

			# Check override:
			if cls.__name__ in sub_d:
				# Must use override=True to override:
				if not override:
					raise errors.OverrideError(base, cls)
			else:
				# There was nothing already registered to override:
				if override:
					raise errors.MissingOverrideError(base, cls)

			# The plugin is okay, add to sub_d:
			sub_d[cls.__name__] = cls

		# The plugin is okay, add to __registered:
		self.__registered.add(cls)

	def __getitem__(self, item):
		"""
		Returns a copy of the namespace dict of the base class named `name`.
		"""
		if inspect.isclass(item):
			if item not in self.__allowed:
				raise KeyError(repr(item))
			key = item.__name__
		else:
			key = item
		return dict(self.__d[key])

	def __contains__(self, item):
		"""
		Returns True if a base class named `name` is in this Registrar.
		"""
		if inspect.isclass(item):
			return item in self.__allowed
		return item in self.__d

	def __iter__(self):
		"""
		Iterates through a (base, registered_plugins) tuple for each allowed
		base.
		"""
		for base in self.__allowed:
			sub_d = self.__d[base.__name__]
			yield (base, tuple(sub_d[k] for k in sorted(sub_d)))


class API(ReadOnly):
	def __init__(self, *allowed):
		keys = tuple(b.__name__ for b in allowed)
		object.__setattr__(self, '_API__keys', keys)
		object.__setattr__(self, 'register', Registrar(*allowed))

	def __call__(self):
		"""
		Finalize the registration, instantiate the plugins.
		"""
		d = {}
		def plugin_iter(base, classes):
			for cls in classes:
				if cls not in d:
					d[cls] = cls()
				plugin = d[cls]
				yield Proxy(base, plugin)

		for (base, classes) in self.register:
			ns = NameSpace(plugin_iter(base, classes))
			assert not hasattr(self, base.__name__)
			object.__setattr__(self, base.__name__, ns)
		for plugin in d.values():
			plugin.finalize(self)
			assert plugin.api is self

	def __iter__(self):
		for key in self.__keys:
			yield key
