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
Base classes for the public plugable.API instance, which the XML-RPC, CLI,
and UI all use.
"""

import re
import plugable


class cmd_proxy(plugable.Proxy):
	__slots__ = (
		'get_label',
		'get_summary',
		'get_help',
		'get_options',
	)


class cmd(plugable.Plugin):
	proxy = cmd_proxy


class obj(plugable.Plugin):
	pass


class attr(plugable.Plugin):
	__obj = None

	def __init__(self):
		m = re.match('^([a-z]+)_([a-z]+)$', self.__class__.__name__)
		assert m
		self.__obj_name = m.group(1)
		self.__attr_name = m.group(2)

	def __get_obj_name(self):
		return self.__obj_name
	obj_name = property(__get_obj_name)

	def __get_attr_name(self):
		return self.__attr_name
	attr_name = property(__get_attr_name)

	def __get_obj(self):
		"""
		Returns the obj instance this attribute is associated with, or None
		if no association has been set.
		"""
		return self.__obj
	obj = property(__get_obj)

	def finalize(self, api):
		super(attr, self).finalize(api)
		self.__obj = api.obj[self.obj_name]


class mthd(attr, cmd):
	pass


class prop(attr):
	pass
