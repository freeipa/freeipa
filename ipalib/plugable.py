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
Utility classes for registering plugins, base classes for writing plugins.
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
		Returns a valid Python expression that could create this plugin
		instance given the appropriate environment.
		"""
		return '%s.%s' % (
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
	"""
	Used to only export certain attributes into the dynamic API.

	Subclasses must list names of attributes to be proxied in the __slots__
	class attribute.
	"""

	__slots__ = (
		'__call__',
		'__obj',
		'name',
	)

	def __init__(self, obj, proxy_name=None):
		"""
		Proxy attributes on `obj`.
		"""
		if proxy_name is None:
			proxy_name = obj.__class__.__name__
		check_identifier(proxy_name)
		object.__setattr__(self, '_Proxy__obj', obj)
		object.__setattr__(self, 'name', proxy_name)
		if callable(obj):
			object.__setattr__(self, '__call__', obj.__call__)
		#for name in self.__slots__:
		#	object.__setattr__(self, name, getattr(obj, name))

	def __repr__(self):
		return '%s(%r)' % (self.__class__.__name__, self.__obj)

	def __str__(self):
		return to_cli(self.name)

	def _clone(self, new_name):
		return self.__class__(self.__obj, proxy_name=new_name)

	def __getattr__(self, name):
		if name in self.__slots__:
			return getattr(self.__obj, name)
		raise AttributeError('attribute %r not in %s.__slots__' % (
				name,
				self.__class__.__name__
			)
		)


class NameSpace(ReadOnly):
	"""
	A read-only namespace of (key, value) pairs that can be accessed
	both as instance attributes and as dictionary items.
	"""

	__max_len = None

	def __init__(self, items, base=None):
		"""
		`items` should be an iterable providing the members of this
		NameSpace.
		"""
		object.__setattr__(self, '_NameSpace__items', tuple(items))
		object.__setattr__(self, '_NameSpace__base', base)

		# dict mapping Python name to item:
		object.__setattr__(self, '_NameSpace__pname', {})

		# dict mapping human-readibly name to item:
		object.__setattr__(self, '_NameSpace__hname', {})

		for item in self.__items:
			object.__setattr__(self, item.name, item)
			for (key, d) in [
				(item.name, self.__pname),
				(str(item), self.__hname),
			]:
				assert key not in d
				d[key] = item

	def __iter__(self):
		"""
		Iterates through the items in this NameSpace in the same order they
		were passed in the contructor.
		"""
		for item in self.__items:
			yield item

	def __len__(self):
		"""
		Returns number of items in this NameSpace.
		"""
		return len(self.__items)

	def __contains__(self, key):
		"""
		Returns True if an item with pname or hname `key` is in this
		NameSpace.
		"""
		return (key in self.__pname) or (key in self.__hname)

	def __getitem__(self, key):
		"""
		Returns item with pname or hname `key`; otherwise raises KeyError.
		"""
		if key in self.__pname:
			return self.__pname[key]
		if key in self.__hname:
			return self.__hname[key]
		raise KeyError('NameSpace has no item for key %r' % key)

	def __call__(self):
		if self.__max_len is None:
			ml = max(len(k) for k in self.__pname)
			object.__setattr__(self, '_NameSpace__max_len', ml)
		return self.__max_len

	def __repr__(self):
		if self.__base is None:
			base = repr(self.__base)
		else:
			base = '%s.%s' % (self.__base.__module__, self.__base.__name__)
		return '%s(*proxies, base=%s)' % (self.__class__.__name__, base)





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
		object.__setattr__(self, '_API__plugins', [])

	def __call__(self):
		"""
		Finalize the registration, instantiate the plugins.
		"""
		for (base, plugins) in self.register:
			ns = NameSpace(self.__plugin_iter(base, plugins), base=base)
			assert not hasattr(self, base.__name__)
			object.__setattr__(self, base.__name__, ns)
		for plugin in self.__plugins:
			plugin.finalize(self)
			assert plugin.api is self

	def __plugin_iter(self, base, plugins):
		assert issubclass(base.proxy, Proxy)
		for cls in plugins:
			plugin = cls()
			self.__plugins.append(plugin)
			yield base.proxy(plugin)

	def __iter__(self):
		for key in self.__keys:
			yield key
