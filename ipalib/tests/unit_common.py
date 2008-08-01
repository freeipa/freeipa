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
Utility functions for unit tests.
"""


def no_set(obj, name):
	"""
	Tests that attribute cannot be set.
	"""
	raised = False
	try:
		setattr(obj, name, 'some_new_obj')
	except AttributeError:
		raised = True
	assert raised


def no_del(obj, name):
	"""
	Tests that attribute cannot be deleted.
	"""
	raised = False
	try:
		delattr(obj, name)
	except AttributeError:
		raised = True
	assert raised


def read_only(obj, name):
	"""
	Tests that attribute is read-only. Returns attribute.
	"""
	assert isinstance(obj, object)
	assert hasattr(obj, name)

	# Test that it cannot be set:
	no_set(obj, name)

	# Test that it cannot be deleted:
	no_del(obj, name)

	# Return the attribute
	return getattr(obj, name)
