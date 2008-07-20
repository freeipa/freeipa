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

import inspect
import exceptions


class NameSpace(object):
	"""
	A read-only namespace of (key, value) pairs that can be accessed
	both as instance attributes and as dictionary items.  For example:

	>>> ns = NameSpace(dict(my_message='Hello world!'))
	>>> ns.my_message
	'Hello world!'
	>>> ns['my_message']
	'Hello world!'

	Keep in mind that Python doesn't offer true ready-only attributes. A
	NameSpace is read-only in that it prevents programmers from
	*accidentally* setting its attributes, but a motivated programmer can
	still set them.

	For example, setting an attribute the normal way will raise an exception:

	>>> ns.my_message = 'some new value'
	(raises exceptions.SetError)

	But a programmer could still set the attribute like this:

	>>> ns.__dict__['my_message'] = 'some new value'

	You should especially not implement a security feature that relies upon
	NameSpace being strictly read-only.
	"""

	__locked = False # Whether __setattr__ has been locked

	def __init__(self, kw, order=None):
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
			raise exceptions.SetError(name)
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
		return key in self.__kw

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


class Named(object):
	def __get_name(self):
		return self.__class__.__name__
	name = property(__get_name)


class ObjectMember(Named):
	def __init__(self, obj):
		self.__obj = obj

	def __get_obj(self):
		return self.__obj
	obj = property(__get_obj)


class Command(ObjectMember):
	def __get_full_name(self):
		return '%s_%s' % (self.name, self.obj.name)
	full_name = property(__get_full_name)


class Attribute(ObjectMember):
	def __get_full_name(self):
		return '%s_%s' % (self.obj.name, self.name)
	full_name = property(__get_full_name)


class Object(Named):
	def __init__(self):
		self.__commands = self.__build_ns(self.get_commands)
		self.__attributes = self.__build_ns(self.get_attributes, True)

	def __get_commands(self):
		return self.__commands
	commands = property(__get_commands)

	def __get_attributes(self):
		return self.__attributes
	attributes = property(__get_attributes)

	def __build_ns(self, callback, preserve=False):
		d = {}
		o = []
		for cls in callback():
			i = cls(self)
			assert i.name not in d
			d[i.name] = i
			o.append(i.name)
		if preserve:
			return NameSpace(d, order=o)
		return NameSpace(d)

	def get_commands(self):
		return []

	def get_attributes(self):
		return []


class API(object):
	__objects = None
	__commands = None

	def __init__(self):
		self.__obj_d = {}

	def __get_objects(self):
		return self.__objects
	objects = property(__get_objects)

	def __get_commands(self):
		return self.__commands
	commands = property(__get_commands)

	def register_object(self, cls, override=False):
		assert type(override) is bool
		if not (inspect.isclass(cls) and issubclass(cls, Object)):
			raise exceptions.RegistrationError(cls,	'Object')
		obj = cls()
		if obj.name in self.__obj_d and not override:
			raise exceptions.OverrideError(obj.name)
		self.__obj_d[obj.name] = obj

	def finalize(self):
		cmd_d = {}
		for obj in self.__obj_d.values():
			for cmd in obj.commands():
				assert cmd.full_name not in cmd_d
				cmd_d[cmd.full_name] = cmd
		self.__commands = NameSpace(cmd_d)
		self.__objects = NameSpace(self.__obj_d)
		self.__obj_d = None
