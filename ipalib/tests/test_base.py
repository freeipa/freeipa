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

from ipalib import base, exceptions, crud


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

	def test_fresh(self):
		"""
		Test expectations of a fresh API instance.
		"""
		api = self.new()
		assert read_only(api, 'objects') is None
		assert read_only(api, 'commands') is None

	def test_register_exception(self):
		"""
		Check that RegistrationError is raised when registering anything
		other than a subclass of Command.
		"""
		api = self.new()

		class my_command(base.Command):
			pass

		for obj in [object, my_command]:
			raised = False
			try:
				api.register_object(obj)
			except exceptions.RegistrationError:
				raised = True
			assert raised

	def test_override_exception(self):
		class some_object(base.Object):
			def get_commands(self):
				return []
			def get_attributes(self):
				return []

		api = self.new()
		api.register_object(some_object)
		raised = False
		try:
			api.register_object(some_object)
		except exceptions.OverrideError:
			raised = True
		assert raised
		api.register_object(some_object, override=True)

	def test_finalize(self):
		class user(crud.CrudLike):
			pass
		class group(crud.CrudLike):
			pass
		class service(crud.CrudLike):
			pass

		names = list(user().commands)
		assert len(names) == 4
		full_names = set()
		for o in ['user', 'group', 'service']:
			full_names.update('%s_%s' % (v, o) for v in names)
		assert len(full_names) == 12


		api = self.new()
		api.register_object(user)
		api.register_object(group)
		api.register_object(service)
		api.finalize()

		# Test API.objects property:
		objects = read_only(api, 'objects')
		assert type(objects) is base.NameSpace
		assert objects is api.objects # Same instance must be returned
		assert len(objects) is 3
		assert list(objects) == ['group', 'service', 'user']

		# Test API.commands property:
		commands = read_only(api, 'commands')
		assert type(commands) is base.NameSpace
		assert commands is api.commands # Same instance must be returned
		assert len(commands) is 12
		assert list(commands) == sorted(full_names)
