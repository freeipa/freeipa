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

	def __getitem__(self, name):
		"""
		Returns a copy of the namespace dict of the base class named `name`.
		"""
		return dict(self.__d[name])

	def __iter__(self):
		"""
		Iterates through the names of the allowed base classes.
		"""
		for key in self.__d:
			yield key
