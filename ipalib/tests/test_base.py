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


def test_Attribute():
	class user__add(base.Attribute):
		pass
	i = user__add()
	assert i.obj_name == 'user'
	assert i.attr_name == 'add'
	assert i.obj is None
	class user(base.Object):
		pass
	u = user()
	i.obj = u
	assert i.obj is u
	raised = False
	try:
		i.obj = u
	except exceptions.TwiceSetError:
		raised = True
	assert raised


def test_Method():
	class user__mod(base.Method):
		pass
	i = user__mod()
	assert isinstance(i, base.Attribute)
	assert isinstance(i, base.AbstractCommand)
	assert i.obj_name == 'user'
	assert i.attr_name == 'mod'
	assert i.name == 'mod_user'


def test_Property():
	class user__firstname(base.Property):
		pass
	i = user__firstname()
	assert isinstance(i, base.Attribute)
	assert i.obj_name == 'user'
	assert i.attr_name == 'firstname'
	assert i.name == 'firstname'


def test_Command():
	class dostuff(base.Command):
		pass
	i = dostuff()
	assert isinstance(i, base.AbstractCommand)
	assert i.name == 'dostuff'



def test_AttributeCollector():
	class user__add(base.Attribute):
		pass
	class user__mod(base.Attribute):
		pass
	class group__add(base.Attribute):
		pass
	u_a = user__add()
	u_m = user__mod()
	g_a = group__add()

	ac = base.AttributeCollector()
	ac.add(u_a)
	ac.add(u_m)
	ac.add(g_a)

	assert set(ac) == set(['user', 'group'])

	u = ac['user']
	assert set(u) == set(['add', 'mod'])
	assert set(u.values()) == set([u_a, u_m])

	g = ac['group']
	assert g.keys() == ['add']
	assert g.values() == [g_a]


def test_Collector():
	class user(base.Object):
		pass
	class group(base.Object):
		pass
	u = user()
	g = group()
	c = base.Collector()
	c.add(u)
	c.add(g)
	ns = c.ns()
	assert isinstance(ns, base.NameSpace)
	assert set(ns) == set(['user', 'group'])
	assert ns.user is u
	assert ns.group is g


class test_Registrar():
	r = base.Registrar()
	allowed = set(['Command', 'Object', 'Method', 'Property'])
	assert set(r) == allowed

	# Some test classes:
	class wrong_base(object):
		pass
	class krbtest(base.Command):
		pass
	class user(base.Object):
		pass
	class user__add(base.Method):
		pass
	class user__firstname(base.Property):
		pass

	# Check that exception is raised trying to register an instance of a
	# class of a correct base:
	raised = False
	try:
		r(user())
	except exceptions.RegistrationError:
		raised = True

	# Check that exception is raised trying to register class of wrong base:
	raised = False
	try:
		r(wrong_base)
	except exceptions.RegistrationError:
		raised = True
	assert raised

	# Check that adding a valid class works
	for cls in (krbtest, user, user__add, user__firstname):
		r(cls)
		key = cls.__bases__[0].__name__
		d = r[key]
		assert d.keys() == [cls.__name__]
		assert d.values() == [cls]
		# Check that a copy is returned
		d2 = r[key]
		assert d2 == d
		assert d2 is not d
		p = getattr(r, key)
		assert isinstance(p, base.Proxy)
		# Check that same instance is returned
		assert p is getattr(r, key)
		assert getattr(p, cls.__name__) is cls

	for base_name in allowed:
		for i in r.get_instances(base_name):
			assert isinstance(i, getattr(base, base_name))


	m = r.get_attrs('Method')
	assert isinstance(m, dict)
	assert len(m) == 1
	assert len(m['user']) == 1
	assert isinstance(m['user'][0], user__add)

	p = r.get_attrs('Property')
	assert isinstance(p, dict)
	assert len(p) == 1
	assert len(p['user']) == 1
	assert isinstance(p['user'][0], user__firstname)






def test_API():
	r = base.Registrar()
	api = base.API(r)

	class kinit(base.Command):
		pass
	class user__add(base.Method):
		pass
	class user__del(base.Method):
		pass
	class user__firstname(base.Property):
		pass
	class user__lastname(base.Property):
		pass
	class user__login(base.Property):
		pass
	class user(base.Object):
		pass
	class group(base.Object):
		pass

	assert read_only(api, 'objects') is None
	assert read_only(api, 'commands') is None
	assert read_only(api, 'max_cmd_len') is None

	r(kinit)
	r(user__add)
	r(user__del)
	r(user__firstname)
	r(user__lastname)
	r(user__login)
	r(user)
	r(group)


	api.finalize()


	objects = read_only(api, 'objects')
	assert isinstance(objects, base.NameSpace)
	assert len(objects) == 2
	assert list(objects) == ['group', 'user']
	assert type(objects.user) is user
	assert type(objects.group) is group

	return

	u = objects.user
	assert len(u.methods) == 2
	assert list(u.methods) == ['add', 'del']
	assert len(u.properties) == 3
	assert list(u.properties) == ['firstname', 'lastname', 'login']

	for m in u.methods():
		assert m.obj is u
	for p in u.properties():
		assert p.obj is u

	g = objects.group
	assert len(g.methods) == 0
	assert len(g.properties) == 0


	assert len(r.commands) == 3
	assert list(r.commands) == sorted(['kinit', 'add_user', 'del_user'])
