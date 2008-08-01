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
Utility classes for registering plugins, base classe for writing plugins.
"""


import inspect
import errors


def to_cli(name):
	"""
	Takes a Python identifier and transforms it into form suitable for the
	Command Line Interface.
	"""
	assert isinstance(name, str)
	return name.replace('__', '.').replace('_', '-')


def from_cli(cli_name):
	"""
	Takes a string from the Command Line Interface and transforms it into a
	Python identifier.
	"""
	assert isinstance(cli_name, basestring)
	return cli_name.replace('-', '_').replace('.', '__')


class Plugin(object):
	"""
	Base class for all plugins.
	"""

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
	"""
	Used to only export certain attributes into the dynamic API.

	Subclasses must list names of attributes to be proxied in the __slots__
	class attribute.
	"""

	__slots__ = (
		'__obj',
		'name',
	)

	def __init__(self, obj, proxy_name=None):
		"""
		Proxy attributes on `obj`.
		"""
		if proxy_name is None:
			proxy_name = obj.__class__.__name__
		assert isinstance(proxy_name, str)
		object.__setattr__(self, '_Proxy__obj', obj)
		object.__setattr__(self, 'name', proxy_name)
		for name in self.__slots__:
			object.__setattr__(self, name, getattr(obj, name))

	def __repr__(self):
		return '%s(%r)' % (self.__class__.__name__, self.__obj)

	def __str__(self):
		return to_cli(self.name)


class NameSpace(ReadOnly):
	"""
	A read-only namespace of (key, value) pairs that can be accessed
	both as instance attributes and as dictionary items.
	"""

	def __init__(self, kw):
		"""
		The `kw` argument is a dict of the (key, value) pairs to be in this
		NameSpace instance.  The optional `order` keyword argument specifies
		the order of the keys in this namespace; if omitted, the default is
		to sort the keys in ascending order.
		"""
		assert isinstance(kw, dict)
		self.__kw = dict(kw)
		for (key, value) in self.__kw.items():
			assert not key.startswith('_')
			setattr(self, key, value)
		if order is None:
			self.__keys = sorted(self.__kw)
		else:
			self.__keys = list(order)
			assert set(self.__keys) == set(self.__kw)
		self.__locked = True

	def __setattr__(self, name, value):
		"""
		Raises an exception if trying to set an attribute after the
		NameSpace has been locked; otherwise calls object.__setattr__().
		"""
		if self.__locked:
			raise errors.SetError(name)
		super(NameSpace, self).__setattr__(name, value)

	def __getitem__(self, key):
		"""
		Returns item from namespace named `key`.
		"""
		return self.__kw[key]

	def __hasitem__(self, key):
		"""
		Returns True if namespace has an item named `key`.
		"""
		return bool(key in self.__kw)

	def __iter__(self):
		"""
		Yields the names in this NameSpace in ascending order, or in the
		the order specified in `order` kw arg.

		For example:

		>>> ns = NameSpace(dict(attr_b='world', attr_a='hello'))
		>>> list(ns)
		['attr_a', 'attr_b']
		>>> [ns[k] for k in ns]
		['hello', 'world']
		"""
		for key in self.__keys:
			yield key

	def __call__(self):
		"""
		Iterates through the values in this NameSpace in the same order as
		the keys.
		"""
		for key in self.__keys:
			yield self.__kw[key]

	def __len__(self):
		"""
		Returns number of items in this NameSpace.
		"""
		return len(self.__keys)


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
		for base in self.__allowed:
			if issubclass(cls, base):
				return base
		raise errors.SubclassError(cls, self.__allowed)

	def __call__(self, cls, override=False):
		"""
		Register the plugin `cls`.
		"""
		if not inspect.isclass(cls):
			raise TypeError('plugin must be a class: %r'  % cls)

		# Find the base class or raise SubclassError:
		base = self.__findbase(cls)
		sub_d = self.__d[base.__name__]

		# Raise DuplicateError if this exact class was already registered:
		if cls in self.__registered:
			raise errors.DuplicateError(cls)

		# Check override:
		if cls.__name__ in sub_d:
			# Must use override=True to override:
			if not override:
				raise errors.OverrideError(base, cls)
		else:
			# There was nothing already registered to override:
			if override:
				raise errors.MissingOverrideError(base, cls)

		# The plugin is okay, add to __registered and sub_d:
		self.__registered.add(cls)
		sub_d[cls.__name__] = cls

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
			yield (base, self.__d[base.__name__].values())
