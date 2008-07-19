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

"""

from base import NameSpace

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

	def __get_commands(self):
		return

	def get_commands(self):
		raise NotImplementedError

	def get_attributes(self):
		raise NotImplementedError
