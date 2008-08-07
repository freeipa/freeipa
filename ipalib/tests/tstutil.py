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
Utility functions for the unit tests.
"""

class ExceptionNotRaised(Exception):
	"""
	Exception raised when an *expected* exception is *not* raised during a
	unit test.
	"""
	msg = 'expected %s'

	def __init__(self, expected):
		self.expected = expected

	def __str__(self):
		return self.msg % self.expected.__name__


def raises(exception, callback, *args, **kw):
	"""
	Tests that the expected exception is raised; raises ExceptionNotRaised
	if test fails.
	"""
	raised = False
	try:
		callback(*args, **kw)
	except exception, e:
		raised = True
	if not raised:
		raise ExceptionNotRaised(exception)
	return e


def getitem(obj, key):
	"""
	Works like getattr but for dictionary interface. Uses this in combination
	with raises() to test that, for example, KeyError is raised.
	"""
	return obj[key]


def no_set(obj, name, value='some_new_obj'):
	"""
	Tests that attribute cannot be set.
	"""
	raises(AttributeError, setattr, obj, name, value)


def no_del(obj, name):
	"""
	Tests that attribute cannot be deleted.
	"""
	raises(AttributeError, delattr, obj, name)


def read_only(obj, name, value='some_new_obj'):
	"""
	Tests that attribute is read-only. Returns attribute.
	"""
	# Test that it cannot be set:
	no_set(obj, name, value)

	# Test that it cannot be deleted:
	no_del(obj, name)

	# Return the attribute
	return getattr(obj, name)


def is_prop(prop):
	return type(prop) is property


class ClassChecker(object):

	def new(self, *args, **kw):
		return self.cls(*args, **kw)

	def get_sub(self):
		raise NotImplementedError('get_sub()')
