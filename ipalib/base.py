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
Base classes in for plug-in architecture and generative API.
"""

from exceptions import NameSpaceError


class Command(object):
	def normalize(self, kw):
		raise NotImplementedError

	def validate(self, kw):
		raise NotImplementedError

	def execute(self, kw):
		raise NotImplementedError

	def __call__(self, **kw):
		kw = self.normalize(kw)
		invalid = self.validate(kw)
		if invalid:
			return invalid
		return self.execute(kw)


class Argument(object):
	pass


class NameSpace(object):
	def __init__(self, kw):
		assert isinstance(kw, dict)
		self.__kw = dict(kw)
		for (key, value) in self.__kw.items():
			assert not key.startswith('_')
			setattr(self, key, value)
		self.__keys = sorted(self.__kw)

	def __getitem__(self, key):
		return self.__kw[key]

	def __iter__(self):
		for key in self.__keys:
			yield key








class API(object):
	def __init__(self):
		self.__c = object()
		self.__o = object()

	def __get_c(self):
		return self.__c
	c = property(__get_c)

	def __get_o(self):
		return self.__o
	o = property(__get_o)

	def register_command(self, name, callback, override=False):
		pass
