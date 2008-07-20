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

	u = r.objects.user
	assert isinstance(u.commands, base.NameSpace)
	assert len(u.commands) == 4
	assert list(u.commands) == ['adduser', 'deluser', 'finduser', 'moduser']
