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
import errors


RULE_FLAG = 'validation_rule'

def rule(obj):
	assert not hasattr(obj, RULE_FLAG)
	setattr(obj, RULE_FLAG, True)
	return obj

def is_rule(obj):
	return getattr(obj, RULE_FLAG, False) is True




class opt(plugable.ReadOnly):
	__public__ = frozenset((
		'normalize',
		'validate',
		'default',
		'required',
		'type',
	))
	__rules = None

	def normalize(self, value):
		try:
			return self.type(value)
		except (TypeError, ValueError):
			raise errors.NormalizationError(
				self.__class__.__name__, value, self.type
			)

	def __get_rules(self):
		if self.__rules is None:
			self.__rules = tuple(self.__rules_iter())
		return self.__rules
	rules = property(__get_rules)

	def __rules_iter(self):
		pass

	def validate(self, value):
		pass






class cmd(plugable.Plugin):
	__public__ = frozenset((
		'normalize',
		'autofill',
		'__call__',
		'get_doc',
		'opt',

	))
	__opt = None

	def get_doc(self, _):
		"""
		Returns the gettext translated doc-string for this command.

		For example:

		>>> def get_doc(self, _):
		>>> 	return _('add new user')
		"""
		raise NotImplementedError('%s.get_doc()' % self.name)

	def get_options(self):
		"""
		Returns iterable with opt_proxy objects used to create the opt
		NameSpace when __get_opt() is called.
		"""
		raise NotImplementedError('%s.get_options()' % self.name)

	def __get_opt(self):
		"""
		Returns the NameSpace containing opt_proxy objects.
		"""
		if self.__opt is None:
			self.__opt = plugable.NameSpace(self.get_options())
		return self.__opt
	opt = property(__get_opt)

	def __call__(self, *args, **kw):
		(args, kw) = self.normalize(*args, **kw)
		(args, kw) = self.autofill(*args, **kw)
		self.validate(*args, **kw)



class obj(plugable.Plugin):
	__public__ = frozenset((
		'mthd',
		'prop',
	))
	__mthd = None
	__prop = None

	def __get_mthd(self):
		return self.__mthd
	mthd = property(__get_mthd)

	def __get_prop(self):
		return self.__prop
	prop = property(__get_prop)

	def finalize(self, api):
		super(obj, self).finalize(api)
		self.__mthd = self.__create_ns('mthd')
		self.__prop = self.__create_ns('prop')

	def __create_ns(self, name):
		return plugable.NameSpace(self.__filter(name))

	def __filter(self, name):
		for i in getattr(self.api, name):
			if i.obj_name == self.name:
				yield i._clone('attr_name')


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
	__public__ = frozenset((
		'obj',
		'obj_name',
	))


class prop(attr):
	__public__ = frozenset((
		'obj',
		'obj_name',
	))

	def get_doc(self, _):
		return _('prop doc')


class PublicAPI(plugable.API):
	__max_cmd_len = None

	def __init__(self):
		super(PublicAPI, self).__init__(cmd, obj, mthd, prop)

	def __get_max_cmd_len(self):
		if self.__max_cmd_len is None:
			if not hasattr(self, 'cmd'):
				return None
			max_cmd_len = max(len(str(cmd)) for cmd in self.cmd)
			object.__setattr__(self, '_PublicAPI__max_cmd_len', max_cmd_len)
		return self.__max_cmd_len
	max_cmd_len = property(__get_max_cmd_len)
