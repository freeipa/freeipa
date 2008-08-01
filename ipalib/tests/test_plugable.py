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
Unit tests for `ipalib.plugable` module.
"""

from tstutil import raises, no_set, no_del, read_only
from ipalib import plugable, errors


def test_to_cli():
	f = plugable.to_cli
	assert f('initialize') == 'initialize'
	assert f('find_everything') == 'find-everything'
	assert f('user__add') == 'user.add'
	assert f('meta_service__do_something') == 'meta-service.do-something'


def test_from_cli():
	f = plugable.from_cli
	assert f('initialize') == 'initialize'
	assert f('find-everything') == 'find_everything'
	assert f('user.add') == 'user__add'
	assert f('meta-service.do-something') == 'meta_service__do_something'


def test_Plugin():
	p = plugable.Plugin()
	assert p.name == 'Plugin'
	assert repr(p) == '%s.Plugin()' % plugable.__name__

	class some_plugin(plugable.Plugin):
		pass
	p = some_plugin()
	assert p.name == 'some_plugin'
	assert repr(p) == '%s.some_plugin()' % __name__


def test_ReadOnly():
	obj = plugable.ReadOnly()
	names = ['not_an_attribute', 'an_attribute']
	for name in names:
		no_set(obj, name)
		no_del(obj, name)

	class some_ro_class(plugable.ReadOnly):
		def __init__(self):
			object.__setattr__(self, 'an_attribute', 'Hello world!')
	obj = some_ro_class()
	for name in names:
		no_set(obj, name)
		no_del(obj, name)
	assert read_only(obj, 'an_attribute') == 'Hello world!'


def test_Proxy():
	assert issubclass(plugable.Proxy, plugable.ReadOnly)

	class CommandProxy(plugable.Proxy):
		__slots__ = (
			'validate',
			'__call__',
		)

	class do_something(object):
		def __repr__(self):
			return '<my repr>'

		def __call__(self, arg):
			return arg + 1

		def validate(self, arg):
			return arg + 2

		def not_public(self, arg):
			return arg + 3

	# Test basic Proxy functionality
	i = do_something()
	p = CommandProxy(i)
	assert '__dict__' not in dir(p)
	assert p.name == 'do_something'
	assert str(p) == 'do-something'
	assert repr(p) == 'CommandProxy(<my repr>)'
	assert p(1) == 2
	assert p.validate(1) == 3

	# Test that proxy_name can be overriden:
	i = do_something()
	p = CommandProxy(i, proxy_name='user__add')
	assert '__dict__' not in dir(p)
	assert p.name == 'user__add'
	assert str(p) == 'user.add'
	assert repr(p) == 'CommandProxy(<my repr>)'
	assert p(1) == 2
	assert p.validate(1) == 3

	# Test that attributes not listed in __slots__ are not present:
	name = 'not_public'
	i = do_something()
	p = CommandProxy(i)
	assert getattr(i, name)(1) == 4
	raises(AttributeError, getattr, p, name)

	# Test that attributes are read-only:
	name = 'validate'
	i = do_something()
	p = CommandProxy(i)
	assert getattr(p, name)(1) == 3
	assert read_only(p, name)(1) == 3


def test_Registrar():
	class Base1(object):
		pass
	class Base2(object):
		pass
	class Base3(object):
		pass
	class plugin1(Base1):
		pass
	class plugin2(Base2):
		pass
	class plugin3(Base3):
		pass

	# Test creation of Registrar:
	r = plugable.Registrar(Base1, Base2)

	# Test __hasitem__, __getitem__:
	for base in [Base1, Base2]:
		assert base in r
		assert base.__name__ in r
		assert r[base] == {}
		assert r[base.__name__] == {}


	# Check that TypeError is raised trying to register something that isn't
	# a class:
	raises(TypeError, r, plugin1())

	# Check that SubclassError is raised trying to register a class that is
	# not a subclass of an allowed base:
	raises(errors.SubclassError, r, plugin3)

	# Check that registration works
	r(plugin1)
	sub_d = r['Base1']
	assert len(sub_d) == 1
	assert sub_d['plugin1'] is plugin1
	# Check that a copy is returned
	assert sub_d is not r['Base1']
	assert sub_d == r['Base1']

	# Check that DuplicateError is raised trying to register exact class
	# again:
	raises(errors.DuplicateError, r, plugin1)

	# Check that OverrideError is raised trying to register class with same
	# name and same base:
	orig1 = plugin1
	class base1_extended(Base1):
		pass
	class plugin1(base1_extended):
		pass
	raises(errors.OverrideError, r, plugin1)

	# Check that overriding works
	r(plugin1, override=True)
	sub_d = r['Base1']
	assert len(sub_d) == 1
	assert sub_d['plugin1'] is plugin1
	assert sub_d['plugin1'] is not orig1

	# Check that MissingOverrideError is raised trying to override a name
	# not yet registerd:
	raises(errors.MissingOverrideError, r, plugin2, override=True)

	# Check that additional plugin can be registered:
	r(plugin2)
	sub_d = r['Base2']
	assert len(sub_d) == 1
	assert sub_d['plugin2'] is plugin2


	# Setup to test __iter__:
	class plugin1a(Base1):
		pass
	r(plugin1a)

	class plugin1b(Base1):
		pass
	r(plugin1b)

	class plugin2a(Base2):
		pass
	r(plugin2a)

	class plugin2b(Base2):
		pass
	r(plugin2b)

	m = {
		'Base1': set([plugin1, plugin1a, plugin1b]),
		'Base2': set([plugin2, plugin2a, plugin2b]),
	}

	# Now test __iter__:
	for (base, plugins) in r:
		assert base in [Base1, Base2]
		assert set(plugins) == m[base.__name__]
	assert len(list(r)) == 2

	# Again test __hasitem__, __getitem__:
	for base in [Base1, Base2]:
		assert base in r
		assert base.__name__ in r
		d = dict((p.__name__, p) for p in m[base.__name__])
		assert len(d) == 3
		assert r[base] == d
		assert r[base.__name__] == d
