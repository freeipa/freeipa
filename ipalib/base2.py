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
from base import NameSpace


class Named(object):
	def __get_name(self):
		return self.__class__.__name__
	name = property(__get_name)


class WithObj(Named):
	_obj = None
	__obj = None
	__obj_locked = False

	def __get_obj(self):
		return self.__obj
	def __set_obj(self, obj):
		if self.__obj_locked:
			raise exceptions.TwiceSetError(self.__class__.__name__, 'obj')
		self.__obj_locked = True
		if obj is None:
			assert self.__obj is None
			assert self.obj is None
		else:
			assert isinstance(obj, Named)
			assert isinstance(self._obj, str)
			assert obj.name == self._obj
			self.__obj = obj
			assert self.obj is obj
	obj = property(__get_obj, __set_obj)


class Command(WithObj):
	pass

class Property(WithObj):
	pass

class Object(Named):
	__commands = None

	def __get_commands(self):
		return self.__commands
	def __set_commands(self, commands):
		if self.__commands is not None:
			raise exceptions.TwiceSetError(
				self.__class__.__name__, 'commands'
			)
		assert type(commands) is NameSpace
		self.__commands = commands
		assert self.commands is commands
	commands = property(__get_commands, __set_commands)


class Collector(object):
	def __init__(self):
		self.__d = {}
		self.globals = []

	def __getitem__(self, key):
		assert isinstance(key, str)
		if key not in self.__d:
			self.__d[key] = []
		return self.__d[key]

	def __iter__(self):
		for key in self.__d:
			yield key

	def add(self, i):
		assert isinstance(i, WithObj)
		if i._obj is None:
			self.globals.append(i)
		else:
			self[i._obj].append(i)

	def namespaces(self):
		for key in self:
			d = dict((i.name, i) for i in self[key])
			yield (key, NameSpace(d))



class Registrar(object):
	__object = None
	__commands = None
	__properties = None

	def __init__(self):
		self.__tmp_objects = {}
		self.__tmp_commands = {}
		self.__tmp_properties = {}

	def __get_objects(self):
		return self.__objects
	objects = property(__get_objects)

	def __get_commands(self):
		return self.__commands
	commands = property(__get_commands)

	def __get_target(self, i):
		if isinstance(i, Object):
			return (self.__tmp_objects, i.name)
		if isinstance(i, Command):
			return (self.__tmp_commands, i.name)
		assert isinstance(i, Property)


	def register(self, cls):
		assert inspect.isclass(cls)
		assert issubclass(cls, Named)
		i = cls()
		(target, key) = self.__get_target(i)
		target[key] = i

	def finalize(self):
		obj_cmd = Collector()
		for cmd in self.__tmp_commands.values():
			if cmd._obj is None:
				cmd.obj = None
			else:
				obj = self.__tmp_objects[cmd._obj]
				cmd.obj = obj
			obj_cmd.add(cmd)
		self.__objects = NameSpace(self.__tmp_objects)
		self.__commands = NameSpace(self.__tmp_commands)
		for (key, ns) in obj_cmd.namespaces():
			self.objects[key].commands = ns
