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

from tstutil import raises, getitem, no_set, no_del, read_only
from ipalib import plugable, errors


def test_to_cli():
	f = plugable.to_cli
	assert f('initialize') == 'initialize'
	assert f('user_add') == 'user-add'


def test_from_cli():
	f = plugable.from_cli
	assert f('initialize') == 'initialize'
	assert f('user-add') == 'user_add'


def test_valid_identifier():
	f = plugable.check_identifier
	okay = [
		'user_add',
		'stuff2junk',
		'sixty9',
	]
	nope = [
		'_user_add',
		'__user_add',
		'user_add_',
		'user_add__',
		'_user_add_',
		'__user_add__',
		'60nine',
	]
	for name in okay:
		f(name)
	for name in nope:
		raises(errors.NameSpaceError, f, name)
	for name in okay:
		raises(errors.NameSpaceError, f, name.upper())


def test_Plugin():
	cls = plugable.Plugin
	assert type(cls.name) is property

	api = 'the api instance'
	p = plugable.Plugin()
	assert read_only(p, 'name') == 'Plugin'
	assert repr(p) == '%s.Plugin()' % plugable.__name__
	assert read_only(p, 'api') is None
	raises(AssertionError, p.finalize, None)
	p.finalize(api)
	assert read_only(p, 'api') is api
	raises(AssertionError, p.finalize, api)

	class some_plugin(plugable.Plugin):
		pass
	p = some_plugin()
	assert read_only(p, 'name') == 'some_plugin'
	assert repr(p) == '%s.some_plugin()' % __name__
	assert read_only(p, 'api') is None
	raises(AssertionError, p.finalize, None)
	p.finalize(api)
	assert read_only(p, 'api') is api
	raises(AssertionError, p.finalize, api)


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
	cls = plugable.Proxy
	assert issubclass(cls, plugable.ReadOnly)

	# Setup:
	class base(object):
		public = frozenset((
			'public_0',
			'public_1',
			'__call__',
		))

		def public_0(self):
			return 'public_0'

		def public_1(self):
			return 'public_1'

		def __call__(self, caller):
			return 'ya called it, %s.' % caller

		def private_0(self):
			return 'private_0'

		def private_1(self):
			return 'private_1'

	class plugin(base):
		name = 'user_add'
		attr_name = 'add'

	# Test that TypeError is raised when base is not a class:
	raises(TypeError, cls, base(), None)

	# Test that ValueError is raised when target is not instance of base:
	raises(ValueError, cls, base, object())

	# Test with correct arguments:
	i = plugin()
	p = cls(base, i)
	assert read_only(p, 'name') == 'user_add'
	assert list(p) == sorted(base.public)

	# Test normal methods:
	for n in xrange(2):
		pub = 'public_%d' % n
		priv = 'private_%d' % n
		assert getattr(i, pub)() == pub
		assert getattr(p, pub)() == pub
		assert hasattr(p, pub)
		assert getattr(i, priv)() == priv
		assert not hasattr(p, priv)

	# Test __call__:
	value = 'ya called it, dude.'
	assert i('dude') == value
	assert p('dude') == value
	assert callable(p)

	# Test name_attr='name' kw arg
	i = plugin()
	p = cls(base, i, 'attr_name')
	assert read_only(p, 'name') == 'add'

	# Test _clone():
	i = plugin()
	p = cls(base, i)
	assert read_only(p, 'name') == 'user_add'
	c = p._clone('attr_name')
	assert isinstance(c, cls)
	assert read_only(c, 'name') == 'add'
	assert c is not p
	assert c('whoever') == p('whoever')


def test_NameSpace():
	cls = plugable.NameSpace
	assert issubclass(cls, plugable.ReadOnly)

	class base(object):
		public = frozenset((
			'plusplus',
		))

		def plusplus(self, n):
			return n + 1

	class plugin(base):
		def __init__(self, name):
			self.name = name

	def get_name(i):
		return 'noun_verb%d' % i

	def get_proxies(n):
		for i in xrange(n):
			yield plugable.Proxy(base, plugin(get_name(i)))

	cnt = 20
	ns = cls(get_proxies(cnt))

	# Test __len__
	assert len(ns) == cnt

	# Test __iter__
	i = None
	for (i, proxy) in enumerate(ns):
		assert type(proxy) is plugable.Proxy
		assert proxy.name == get_name(i)
	assert i == cnt - 1

	# Test __contains__, __getitem__, getattr():
	proxies = frozenset(ns)
	for i in xrange(cnt):
		name = get_name(i)
		assert name in ns
		proxy = ns[name]
		assert proxy.name == name
		assert type(proxy) is plugable.Proxy
		assert proxy in proxies
		assert read_only(ns, name) is proxy

	# Test dir():
	assert set(get_name(i) for i in xrange(cnt)).issubset(set(dir(ns)))

	# Test that KeyError, AttributeError is raised:
	name = get_name(cnt)
	assert name not in ns
	raises(KeyError, getitem, ns, name)
	raises(AttributeError, getattr, ns, name)
	no_set(ns, name)


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


def test_API():
	assert issubclass(plugable.API, plugable.ReadOnly)

	# Setup the test bases, create the API:
	class base0(plugable.Plugin):
		public = frozenset((
			'method',
		))

		def method(self, n):
			return n

	class base1(plugable.Plugin):
		public = frozenset((
			'method',
		))

		def method(self, n):
			return n + 1

	api = plugable.API(base0, base1)
	r = api.register
	assert isinstance(r, plugable.Registrar)
	assert read_only(api, 'register') is r

	class base0_plugin0(base0):
		pass
	r(base0_plugin0)

	class base0_plugin1(base0):
		pass
	r(base0_plugin1)

	class base0_plugin2(base0):
		pass
	r(base0_plugin2)

	class base1_plugin0(base1):
		pass
	r(base1_plugin0)

	class base1_plugin1(base1):
		pass
	r(base1_plugin1)

	class base1_plugin2(base1):
		pass
	r(base1_plugin2)

	# Test API instance:
	api() # Calling instance performs finalization

	def get_base(b):
		return 'base%d' % b

	def get_plugin(b, p):
		return 'base%d_plugin%d' % (b, p)

	for b in xrange(2):
		base_name = get_base(b)
		ns = getattr(api, base_name)
		assert isinstance(ns, plugable.NameSpace)
		assert read_only(api, base_name) is ns
		assert len(ns) == 3
		for p in xrange(3):
			plugin_name = get_plugin(b, p)
			proxy = ns[plugin_name]
			assert isinstance(proxy, plugable.Proxy)
			assert proxy.name == plugin_name
			assert read_only(ns, plugin_name) is proxy
			assert read_only(proxy, 'method')(7) == 7 + b
