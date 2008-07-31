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
	(raises errors.SetError)

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



class Named(object):
	__name = None

	def _get_name(self):
		return self.__class__.__name__

	def __get_loc(self):
		cls = self.__class__
		return '%s.%s' % (cls.__module__, cls.__name__)
	loc = property(__get_loc)

	def __get_name(self):
		if self.__name is None:
			self.__name = self._get_name()
		return self.__name
	name = property(__get_name)

	def __get_cli_name(self):
		return self.name.replace('_', '-')
	cli_name = property(__get_cli_name)


class AbstractCommand(object):
	def __call__(self):
		print 'You called %s.%s()' % (
			self.__class__.__module__,
			self.__class__.__name__
		)

	def get_doc(self, _):
		"""
		This should return a gettext translated summarary of the command.

		For example, if you were documenting the 'add-user' command, you're
		method would look something like this.

		>>> def get_doc(self, _):
		>>>		return _('add new user')
		"""
		raise NotImplementedError('%s.%s.%s()' % (
				self.__class__.__module__,
				self.__class__.__name__,
				'get_doc',
			)
		)


class Attribute(Named):
	__locked = False
	__obj = None

	def __init__(self):
		m = re.match('^([a-z]+)__([a-z]+)$', self.__class__.__name__)
		assert m
		self.__obj_name = m.group(1)
		self.__attr_name = m.group(2)

	def __get_obj(self):
		return self.__obj
	def __set_obj(self, obj):
		if self.__obj is not None:
			raise errors.TwiceSetError(self.__class__.__name__, 'obj')
		assert isinstance(obj, Object)
		self.__obj = obj
		assert self.obj is obj
	obj = property(__get_obj, __set_obj)

	def __get_obj_name(self):
		return self.__obj_name
	obj_name = property(__get_obj_name)

	def __get_attr_name(self):
		return self.__attr_name
	attr_name = property(__get_attr_name)


class Method(AbstractCommand, Attribute):
	def _get_name(self):
		return '%s_%s' % (self.attr_name, self.obj_name)


class Property(Attribute):
	def _get_name(self):
		return self.attr_name


class Command(AbstractCommand, Named):
	pass


class Object(Named):
	__methods = None
	__properties = None

	def __get_methods(self):
		return self.__methods
	def __set_methods(self, methods):
		if self.__methods is not None:
			raise errors.TwiceSetError(
				self.__class__.__name__, 'methods'
			)
		assert type(methods) is NameSpace
		self.__methods = methods
		assert self.methods is methods
	methods = property(__get_methods, __set_methods)

	def __get_properties(self):
		return self.__properties
	def __set_properties(self, properties):
		if self.__properties is not None:
			raise errors.TwiceSetError(
				self.__class__.__name__, 'properties'
			)
		assert type(properties) is NameSpace
		self.__properties = properties
		assert self.properties is properties
	properties = property(__get_properties, __set_properties)



class AttributeCollector(object):
	def __init__(self):
		self.__d = {}

	def __getitem__(self, key):
		assert isinstance(key, str)
		if key not in self.__d:
			self.__d[key] = {}
		return self.__d[key]

	def __iter__(self):
		for key in self.__d:
			yield key

	def add(self, i):
		assert isinstance(i, Attribute)
		self[i.obj_name][i.attr_name] = i

	def namespaces(self):
		for key in self:
			yield (key, NameSpace(self[key]))


class Collector(object):
	def __init__(self):
		self.__d = {}

	def __get_d(self):
		return dict(self.__d)
	d = property(__get_d)

	def __iter__(self):
		for key in self.__d:
			yield key

	def add(self, i):
		assert isinstance(i, Named)
		self.__d[i.name] = i

	def ns(self):
		return NameSpace(self.__d)


class Proxy(object):
	def __init__(self, d):
		self.__d = d

	def __getattr__(self, name):
		if name not in self.__d:
			raise AttributeError(name)
		return self.__d[name]



class Registrar(object):
	__allowed = (
		Command,
		Object,
		Method,
		Property,
	)

	def __init__(self, d=None):
		if d is None:
			self.__d = {}
		else:
			assert isinstance(d, dict)
			assert d == {}
			self.__d = d
		for base in self.__allowed:
			assert inspect.isclass(base)
			assert base.__name__ not in self.__d
			sub_d = {}
			self.__d[base.__name__] = sub_d
			setattr(self, base.__name__, Proxy(sub_d))

	def __iter__(self):
		for key in self.__d:
			yield key

	def __getitem__(self, key):
		return dict(self.__d[key])

	def items(self):
		for key in self:
			yield (key, self[key])

	def __findbase(self, cls):
		if not inspect.isclass(cls):
			raise errors.RegistrationError('not a class', cls)
		for base in self.__allowed:
			if issubclass(cls, base):
				return base
		raise errors.RegistrationError(
			'not subclass of an allowed base',
			cls,
		)

	def __call__(self, cls):
		base = self.__findbase(cls)
		ns = self.__d[base.__name__]
		assert cls.__name__ not in ns
		ns[cls.__name__] = cls


	def get_instances(self, base_name):
		for cls in self[base_name].values():
			yield cls()

	def get_attrs(self, base_name):
		d = {}
		for i in self.get_instances(base_name):
			if i.obj_name not in d:
				d[i.obj_name] = []
			d[i.obj_name].append(i)
		return d






class RegistrarOld(object):


	def __init__(self):
		self.__tmp_commands = Collector()
		self.__tmp_objects = Collector()
		self.__tmp_methods = AttributeCollector()
		self.__tmp_properties = AttributeCollector()

	def __get_objects(self):
		return self.__objects
	objects = property(__get_objects)

	def __get_commands(self):
		return self.__commands
	commands = property(__get_commands)


	def __get_target(self, i):
		if isinstance(i, Command):
			return self.__tmp_commands
		if isinstance(i, Object):
			return self.__tmp_objects
		if isinstance(i, Method):
			return self.__tmp_methods
		assert isinstance(i, Property)
		return self.__tmp_properties


	def register(self, cls):
		assert inspect.isclass(cls)
		assert issubclass(cls, Named)
		i = cls()
		self.__get_target(i).add(i)


	def finalize(self):
		self.__objects = self.__tmp_objects.ns()
		for (key, ns) in self.__tmp_methods.namespaces():
			self.__objects[key].methods = ns
		for (key, ns) in self.__tmp_properties.namespaces():
			self.__objects[key].properties = ns
		commands = self.__tmp_commands.d
		for obj in self.__objects():
			assert isinstance(obj, Object)
			if obj.methods is None:
				obj.methods = NameSpace({})
			if obj.properties is None:
				obj.properties = NameSpace({})
			for m in obj.methods():
				m.obj = obj
				assert m.name not in commands
				commands[m.name] = m
			for p in obj.properties():
				p.obj = obj
		self.__commands = NameSpace(commands)



class API(object):
	__max_cmd_len = None
	__objects = None
	__commands = None

	def __init__(self, registrar):
		assert isinstance(registrar, Registrar)
		self.__r = registrar

	def __get_objects(self):
		return self.__objects
	objects = property(__get_objects)

	def __get_commands(self):
		return self.__commands
	commands = property(__get_commands)

	def __get_max_cmd_len(self):
		if self.__max_cmd_len is None:
			if self.commands is None:
				return None
			self.__max_cmd_len = max(len(n) for n in self.commands)
		return self.__max_cmd_len
	max_cmd_len = property(__get_max_cmd_len)

	def __items(self, base, name):
		for cls in self.__r[base].values():
			i = cls()
			yield (getattr(i, name), i)

	def __namespace(self, base, name):
		return NameSpace(dict(self.__items(base, name)))



	def finalize(self):
		self.__objects = self.__namespace('Object', 'name')

		m = {}
		for obj in self.__objects():
			if obj.name not in m:
				m[obj.name] = {}

		for cls in self.__r['Method'].values():
			meth = cls()
			assert meth.obj_name in m

		return

		for (key, ns) in self.__tmp_methods.namespaces():
			self.__objects[key].methods = ns
		for (key, ns) in self.__tmp_properties.namespaces():
			self.__objects[key].properties = ns
		commands = self.__tmp_commands.d
		for obj in self.__objects():
			assert isinstance(obj, Object)
			if obj.methods is None:
				obj.methods = NameSpace({})
			if obj.properties is None:
				obj.properties = NameSpace({})
			for m in obj.methods():
				m.obj = obj
				assert m.name not in commands
				commands[m.name] = m
			for p in obj.properties():
				p.obj = obj
		self.__commands = NameSpace(commands)
