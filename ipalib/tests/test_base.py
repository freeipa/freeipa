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

from ipalib import base, exceptions


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


class test_NameSpace:
	"""
	Unit tests for `NameSpace` class.
	"""

	def	ns(self, kw):
		"""
		Returns a new NameSpace instance.
		"""
		return base.NameSpace(kw)

	def kw(self):
		"""
		Returns standard test kw dict suitable for passing to
		NameSpace.__init__().
		"""
		return dict(
			attr_a='Hello',
			attr_b='all',
			attr_c='yall!',
		)

	def std(self):
		"""
		Returns standard (kw, ns) tuple.
		"""
		kw = self.kw()
		ns = self.ns(kw)
		return (kw, ns)

	def test_public(self):
		"""
		Tests that a NameSpace instance created with empty dict has no public
		attributes (that would then conflict with names we want to assign to
		the NameSpace). Also tests that a NameSpace instance created with a
		non-empty dict has no unexpected public methods.
		"""
		ns = self.ns({})
		assert list(ns) == []
		assert len(ns) == 0
		for name in dir(ns):
			assert name.startswith('__') or name.startswith('_NameSpace__')
		(kw, ns) = self.std()
		keys = set(kw)
		for name in dir(ns):
			assert (
				name.startswith('__') or
				name.startswith('_NameSpace__') or
				name in keys
			)

	def test_dict_vs_attr(self):
		"""
		Tests that NameSpace.__getitem__() and NameSpace.__getattr__() return
		the same values.
		"""
		(kw, ns) = self.std()
		assert len(kw) > 0
		assert len(kw) == len(list(ns))
		for (key, val) in kw.items():
			assert ns[key] is val
			assert getattr(ns, key) is val

	def test_setattr(self):
		"""
		Tests that attributes cannot be set on NameSpace instance.
		"""
		(kw, ns) = self.std()
		value = 'new value'
		for key in kw:
			raised = False
			try:
				setattr(ns, key, value)
			except exceptions.SetError:
				raised = True
			assert raised
			assert getattr(ns, key, None) != value
			assert ns[key] != value

	def test_setitem(self):
		"""
		Tests that attributes cannot be set via NameSpace dict interface.
		"""
		(kw, ns) = self.std()
		value = 'new value'
		for key in kw:
			raised = False
			try:
				ns[key] = value
			except TypeError:
				raised = True
			assert raised
			assert getattr(ns, key, None) != value
			assert ns[key] != value

	def test_hasitem(self):
		"""
		Test __hasitem__() membership method.
		"""
		(kw, ns) = self.std()
		nope = [
			'attr_d',
			'attr_e',
			'whatever',
		]
		for key in kw:
			assert key in ns
		for key in nope:
			assert key not in kw
			assert key not in ns

	def test_iter(self):
		"""
		Tests that __iter__() method returns sorted list of attribute names.
		"""
		(kw, ns) = self.std()
		assert list(ns) == sorted(kw)
		assert [ns[k] for k in ns] == ['Hello', 'all', 'yall!']

	def test_len(self):
		"""
		Test __len__() method.
		"""
		(kw, ns) = self.std()
		assert len(kw) == len(ns) == 3


def test_Command():
	class user(object):
		name = 'user'
	class add(base.Command):
		pass
	i = add(user())
	assert i.name == 'add'
	assert i.full_name == 'add_user'


def test_Attribute():
	class user(object):
		name = 'user'
	class sn(base.Attribute):
		pass
	i = sn(user())
	assert i.name == 'sn'
	assert i.full_name == 'user_sn'


def test_Object():
	class create(base.Command):
			pass

	class retrieve(base.Command):
			pass

	class update(base.Command):
			pass

	class delete(base.Command):
			pass

	class givenName(base.Attribute):
		pass

	class sn(base.Attribute):
		pass

	class login(base.Attribute):
		pass


	class user(base.Object):
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

	i = user()
	assert i.name == 'user'

	# Test commands:
	commands = i.commands
	assert isinstance(commands, base.NameSpace)
	assert list(commands) == ['create', 'delete', 'retrieve', 'update']
	assert len(commands) == 4
	for name in commands:
		cls = locals()[name]
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
		cls = locals()[name]
		attr = attributes[name]
		assert type(attr) is cls
		assert getattr(attributes, name) is attr
		assert attr.name == name
		assert attr.full_name == ('user_%s' % name)


class test_API:
	"""
	Unit tests for `API` class.
	"""

	def new(self):
		"""
		Returns a new API instance.
		"""
		return base.API()

	def dont_fresh(self):
		"""
		Test expectations of a fresh API instance.
		"""
		api = self.new()
		assert read_only(api, 'cmd') is None

	def dont_register_command(self):
		api = self.new()

		class cmd_my_command(base.Command):
			pass
		class cmd_another_command(base.Command):
			pass

		# Check that RegistrationError is raised when registering anything
		# other than a subclass of Command:
		for obj in [object, cmd_my_command()]:
			raised = False
			try:
				api.register_command(obj)
			except exceptions.RegistrationError:
				raised = True
			assert raised

		# Check that command registration works:
		api.register_command(cmd_my_command)
		api.register_command(cmd_another_command)

		# Check that DuplicateError is raised when registering the same class
		# twice:
		raised = False
		try:
			api.register_command(cmd_my_command)
		except exceptions.DuplicateError:
			raised = True
		assert raised

		# Check that OverrideError is raised when registering same name
		# without override = True:
		class cmd_my_command(base.Command):
			pass
		raised = False
		try:
			api.register_command(cmd_my_command)
		except exceptions.OverrideError:
			raised = True
		assert raised

		# Check that override=True works:
		api.register_command(cmd_my_command, override=True)

	def dont_finalize(self):
		api = self.new()
		assert read_only(api, 'cmd') is None

		class cmd_my_command(base.Command):
			pass
		class cmd_another_command(base.Command):
			pass

		api.register_command(cmd_my_command)
		api.register_command(cmd_another_command)

		api.finalize()

		cmd = read_only(api, 'cmd')
		assert isinstance(cmd, base.NameSpace)
		assert api.cmd is cmd

		assert len(cmd) == 2
		assert list(cmd) == ['another_command', 'my_command']
		assert isinstance(cmd.my_command, cmd_my_command)
		assert cmd.my_command is cmd['my_command']
		assert isinstance(cmd.another_command, cmd_another_command)
		assert cmd.another_command is cmd['another_command']
