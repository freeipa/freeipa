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
Unit tests for `ipalib.base` module.
"""

from ipalib import base2 as base
from ipalib import exceptions


def read_only(obj, name):
	"""
	Check that a given property is read-only.
	Returns the value of the property.
	"""
	assert isinstance(obj, object)
	assert hasattr(obj, name)
	raised = False
	try:
		setattr(obj, name, 'some new obj')
	except AttributeError:
		raised = True
	assert raised
	return getattr(obj, name)


class ClassChecker(object):
	cls = None # Override this is subclasses

	def new(self, *args, **kw):
		return self.cls(*args, **kw)

	def args(self):
		return []

	def kw(self):
		return {}

	def std(self):
		return self.new(*self.args(), **self.kw())



def test_Named():
	class named_class(base.Named):
		pass

	i = named_class()
	assert i.name == 'named_class'


def test_WithObj():
	class some_object(base.Named):
		pass

	class another_object(base.Named):
		pass

	class some_command(base.WithObj):
		_obj = 'some_object'

	obj = some_object()
	cmd = some_command()

	# Test that it can be set:
	assert cmd.obj is None
	cmd.obj = obj
	assert cmd.obj is obj

	# Test that it cannot be set twice:
	raised = False
	try:
		cmd.obj = obj
	except exceptions.TwiceSetError:
		raised = True
	assert raised

	# Test that it can't be set with the wrong name:
	obj = another_object()
	cmd = some_command()
	raised = False
	try:
		cmd.obj = obj
	except AssertionError:
		raised = True
	assert raised


def test_Registar():
	class adduser(base.Command):
		_obj = 'user'
	class moduser(base.Command):
		_obj = 'user'
	class deluser(base.Command):
		_obj = 'user'
	class finduser(base.Command):
		_obj = 'user'
	class kinit(base.Command):
		pass
	class user(base.Object):
		pass
	class group(base.Object):
		pass

	r = base.Registrar()
	r.register(adduser)
	r.register(moduser)
	r.register(deluser)
	r.register(finduser)
	r.register(kinit)
	r.register(user)
	r.register(group)

	r.finalize()
	assert len(r.commands) == 5
	assert len(r.objects) == 2

	obj = r.objects.user
	assert type(obj) is user
	for name in ['adduser', 'moduser', 'deluser', 'finduser']:
		cmd = r.commands[name]
		assert type(cmd) is locals()[name]
		assert cmd.obj is obj

	assert r.commands.kinit.obj is None

	for cmd in r.commands():
		raised = False
		try:
			cmd.obj = None
		except exceptions.TwiceSetError:
			raised = True
		assert raised
