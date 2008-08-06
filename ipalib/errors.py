# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty inmsgion
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
All custom errors raised by `ipalib` package.
"""

class IPAError(Exception):
	"""
	Use this base class for your custom IPA errors unless there is a
	specific reason to subclass from AttributeError, KeyError, etc.
	"""
	msg = None

	def __init__(self, *args, **kw):
		self.args = args
		self.kw = kw

	def __str__(self):
		"""
		Returns the string representation of this exception.
		"""
		if self.msg is None:
			if len(self.args) == 1:
				return unicode(self.args[0])
			return unicode(self.args)
		if len(self.args) > 0:
			return self.msg % self.args
		return self.msg % self.kw





class SetError(IPAError):
	msg = 'setting %r, but NameSpace does not allow attribute setting'



class RegistrationError(IPAError):
	"""
	Base class for errors that occur during plugin registration.
	"""


class NameSpaceError(RegistrationError):
	msg = 'name %r does not re.match %r'


class SubclassError(RegistrationError):
	"""
	Raised when registering a plugin that is not a subclass of one of the
	allowed bases.
	"""
	msg = 'plugin %r not subclass of any base in %r'

	def __init__(self, cls, allowed):
		self.cls = cls
		self.allowed = allowed

	def __str__(self):
		return self.msg % (self.cls, self.allowed)


class DuplicateError(RegistrationError):
	"""
	Raised when registering a plugin whose exact class has already been
	registered.
	"""
	msg = '%r at %d was already registered'

	def __init__(self, cls):
		self.cls = cls

	def __str__(self):
		return self.msg % (self.cls, id(self.cls))


class OverrideError(RegistrationError):
	"""
	Raised when override=False yet registering a plugin that overrides an
	existing plugin in the same namespace.
	"""
	msg = 'unexpected override of %s.%s with %r (use override=True if intended)'

	def __init__(self, base, cls):
		self.base = base
		self.cls = cls

	def __str__(self):
		return self.msg % (self.base.__name__, self.cls.__name__, self.cls)


class MissingOverrideError(RegistrationError):
	"""
	Raised when override=True yet no preexisting plugin with the same name
	and base has been registered.
	"""
	msg = '%s.%s has not been registered, cannot override with %r'

	def __init__(self, base, cls):
		self.base = base
		self.cls = cls

	def __str__(self):
		return self.msg % (self.base.__name__, self.cls.__name__, self.cls)



class TwiceSetError(IPAError):
	msg = '%s.%s cannot be set twice'
