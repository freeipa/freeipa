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
Unit tests for `ipalib.crud` module.
"""

from ipalib import crud, base, exceptions

class create(crud.Command):
		pass

class retrieve(crud.Command):
		pass

class update(crud.Command):
		pass

class delete(crud.Command):
		pass

class givenName(crud.Attribute):
	pass

class sn(crud.Attribute):
	pass

class login(crud.Attribute):
	pass


class user(crud.Object):
	def get_commands(self):
		return [
			create,
			retrieve,
			update,
			delete,
		]

	def get_attributes(self):
		return [
			givenName,
			sn,
			login,
		]


def test_Named():
	class named_class(crud.Named):
		pass

	n = named_class()
	assert n.name == 'named_class'


def test_Command():
	class user(object):
		name = 'user'
	class add(crud.Command):
		pass
	i = add(user())
	assert i.name == 'add'
	assert i.full_name == 'add_user'


def test_Object():
	i = user()
	assert i.name == 'user'

	# Test commands:
	commands = i.commands
	assert isinstance(commands, base.NameSpace)
	assert list(commands) == ['create', 'delete', 'retrieve', 'update']
	assert len(commands) == 4
	for name in commands:
		cls = globals()[name]
		cmd = commands[name]
		assert type(cmd) is cls
		assert getattr(commands, name) is cmd
		assert cmd.name == name
		assert cmd.full_name == ('%s_user' % name)

	# Test attributes:
	attributes = i.attributes
	assert isinstance(attributes, base.NameSpace)
	assert list(attributes) == ['givenName', 'sn', 'login']
	assert len(attributes) == 3
	for name in attributes:
		cls = globals()[name]
		attr = attributes[name]
		assert type(attr) is cls
		assert getattr(attributes, name) is attr
		assert attr.name == name
		assert attr.full_name == ('user_%s' % name)
