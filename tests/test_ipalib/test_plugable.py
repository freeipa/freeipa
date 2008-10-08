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
Test the `ipalib.plugable` module.
"""

from tests.util import raises, no_set, no_del, read_only
from tests.util import getitem, setitem, delitem
from tests.util import ClassChecker
from ipalib import plugable, errors


class test_ReadOnly(ClassChecker):
    """
    Test the `ipalib.plugable.ReadOnly` class
    """
    _cls = plugable.ReadOnly

    def test_class(self):
        """
        Test the `ipalib.plugable.ReadOnly` class
        """
        assert self.cls.__bases__ == (object,)
        assert callable(self.cls.__lock__)
        assert callable(self.cls.__islocked__)

    def test_lock(self):
        """
        Test the `ipalib.plugable.ReadOnly.__lock__` method.
        """
        o = self.cls()
        assert o._ReadOnly__locked is False
        o.__lock__()
        assert o._ReadOnly__locked is True
        e = raises(AssertionError, o.__lock__) # Can only be locked once
        assert str(e) == '__lock__() can only be called once'
        assert o._ReadOnly__locked is True # This should still be True

    def test_lock(self):
        """
        Test the `ipalib.plugable.ReadOnly.__islocked__` method.
        """
        o = self.cls()
        assert o.__islocked__() is False
        o.__lock__()
        assert o.__islocked__() is True

    def test_setattr(self):
        """
        Test the `ipalib.plugable.ReadOnly.__setattr__` method.
        """
        o = self.cls()
        o.attr1 = 'Hello, world!'
        assert o.attr1 == 'Hello, world!'
        o.__lock__()
        for name in ('attr1', 'attr2'):
            e = raises(AttributeError, setattr, o, name, 'whatever')
            assert str(e) == 'read-only: cannot set ReadOnly.%s' % name
        assert o.attr1 == 'Hello, world!'

    def test_delattr(self):
        """
        Test the `ipalib.plugable.ReadOnly.__delattr__` method.
        """
        o = self.cls()
        o.attr1 = 'Hello, world!'
        o.attr2 = 'How are you?'
        assert o.attr1 == 'Hello, world!'
        assert o.attr2 == 'How are you?'
        del o.attr1
        assert not hasattr(o, 'attr1')
        o.__lock__()
        e = raises(AttributeError, delattr, o, 'attr2')
        assert str(e) == 'read-only: cannot del ReadOnly.attr2'
        assert o.attr2 == 'How are you?'


def test_lock():
    """
    Test the `ipalib.plugable.lock` function.
    """
    f = plugable.lock

    # Test on a ReadOnly instance:
    o = plugable.ReadOnly()
    assert not o.__islocked__()
    assert f(o) is o
    assert o.__islocked__()

    # Test on something not subclassed from ReadOnly:
    class not_subclass(object):
        def __lock__(self):
            pass
        def __islocked__(self):
            return True
    o = not_subclass()
    raises(ValueError, f, o)

    # Test that it checks __islocked__():
    class subclass(plugable.ReadOnly):
        def __islocked__(self):
            return False
    o = subclass()
    raises(AssertionError, f, o)


class test_SetProxy(ClassChecker):
    """
    Test the `ipalib.plugable.SetProxy` class.
    """
    _cls = plugable.SetProxy

    def test_class(self):
        """
        Test the `ipalib.plugable.SetProxy` class.
        """
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Test the `ipalib.plugable.SetProxy.__init__` method.
        """
        okay = (set, frozenset, dict)
        fail = (list, tuple)
        for t in okay:
            self.cls(t())
            raises(TypeError, self.cls, t)
        for t in fail:
            raises(TypeError, self.cls, t())
            raises(TypeError, self.cls, t)

    def test_SetProxy(self):
        """
        Test container emulation of `ipalib.plugable.SetProxy` class.
        """
        def get_key(i):
            return 'key_%d' % i

        cnt = 10
        target = set()
        proxy = self.cls(target)
        for i in xrange(cnt):
            key = get_key(i)

            # Check initial state
            assert len(proxy) == len(target)
            assert list(proxy) == sorted(target)
            assert key not in proxy
            assert key not in target

            # Add and test again
            target.add(key)
            assert len(proxy) == len(target)
            assert list(proxy) == sorted(target)
            assert key in proxy
            assert key in target


class test_DictProxy(ClassChecker):
    """
    Test the `ipalib.plugable.DictProxy` class.
    """
    _cls = plugable.DictProxy

    def test_class(self):
        """
        Test the `ipalib.plugable.DictProxy` class.
        """
        assert self.cls.__bases__ == (plugable.SetProxy,)

    def test_init(self):
        """
        Test the `ipalib.plugable.DictProxy.__init__` method.
        """
        self.cls(dict())
        raises(TypeError, self.cls, dict)
        fail = (set, frozenset, list, tuple)
        for t in fail:
            raises(TypeError, self.cls, t())
            raises(TypeError, self.cls, t)

    def test_DictProxy(self):
        """
        Test container emulation of `ipalib.plugable.DictProxy` class.
        """
        def get_kv(i):
            return (
                'key_%d' % i,
                'val_%d' % i,
            )
        cnt = 10
        target = dict()
        proxy = self.cls(target)
        for i in xrange(cnt):
            (key, val) = get_kv(i)

            # Check initial state
            assert len(proxy) == len(target)
            assert list(proxy) == sorted(target)
            assert list(proxy()) == [target[k] for k in sorted(target)]
            assert key not in proxy
            raises(KeyError, getitem, proxy, key)

            # Add and test again
            target[key] = val
            assert len(proxy) == len(target)
            assert list(proxy) == sorted(target)
            assert list(proxy()) == [target[k] for k in sorted(target)]

            # Verify TypeError is raised trying to set/del via proxy
            raises(TypeError, setitem, proxy, key, val)
            raises(TypeError, delitem, proxy, key)


class test_MagicDict(ClassChecker):
    """
    Tests the `ipalib.plugable.MagicDict` class.
    """
    _cls = plugable.MagicDict

    def test_class(self):
        """
        Tests the `ipalib.plugable.MagicDict` class.
        """
        assert self.cls.__bases__ == (plugable.DictProxy,)
        for non_dict in ('hello', 69, object):
            raises(TypeError, self.cls, non_dict)

    def test_MagicDict(self):
        """
        Test container emulation of `ipalib.plugable.MagicDict` class.
        """
        cnt = 10
        keys = []
        d = dict()
        dictproxy = self.cls(d)
        for i in xrange(cnt):
            key = 'key_%d' % i
            val = 'val_%d' % i
            keys.append(key)

            # Test thet key does not yet exist
            assert len(dictproxy) == i
            assert key not in dictproxy
            assert not hasattr(dictproxy, key)
            raises(KeyError, getitem, dictproxy, key)
            raises(AttributeError, getattr, dictproxy, key)

            # Test that items/attributes cannot be set on dictproxy:
            raises(TypeError, setitem, dictproxy, key, val)
            raises(AttributeError, setattr, dictproxy, key, val)

            # Test that additions in d are reflected in dictproxy:
            d[key] = val
            assert len(dictproxy) == i + 1
            assert key in dictproxy
            assert hasattr(dictproxy, key)
            assert dictproxy[key] is val
            assert read_only(dictproxy, key) is val

        # Test __iter__
        assert list(dictproxy) == keys

        for key in keys:
            # Test that items cannot be deleted through dictproxy:
            raises(TypeError, delitem, dictproxy, key)
            raises(AttributeError, delattr, dictproxy, key)

            # Test that deletions in d are reflected in dictproxy
            del d[key]
            assert len(dictproxy) == len(d)
            assert key not in dictproxy
            raises(KeyError, getitem, dictproxy, key)
            raises(AttributeError, getattr, dictproxy, key)


class test_Plugin(ClassChecker):
    """
    Test the `ipalib.plugable.Plugin` class.
    """
    _cls = plugable.Plugin

    def test_class(self):
        """
        Test the `ipalib.plugable.Plugin` class.
        """
        assert self.cls.__bases__ == (plugable.ReadOnly,)
        assert self.cls.__public__ == frozenset()
        assert type(self.cls.name) is property
        assert type(self.cls.doc) is property
        assert type(self.cls.api) is property

    def test_name(self):
        """
        Test the `ipalib.plugable.Plugin.name` property.
        """
        assert read_only(self.cls(), 'name') == 'Plugin'

        class some_subclass(self.cls):
            pass
        assert read_only(some_subclass(), 'name') == 'some_subclass'

    def test_doc(self):
        """
        Test the `ipalib.plugable.Plugin.doc` property.
        """
        class some_subclass(self.cls):
            'here is the doc string'
        assert read_only(some_subclass(), 'doc') == 'here is the doc string'

    def test_implements(self):
        """
        Test the `ipalib.plugable.Plugin.implements` classmethod.
        """
        class example(self.cls):
            __public__ = frozenset((
                'some_method',
                'some_property',
            ))
        class superset(self.cls):
            __public__ = frozenset((
                'some_method',
                'some_property',
                'another_property',
            ))
        class subset(self.cls):
            __public__ = frozenset((
                'some_property',
            ))
        class any_object(object):
            __public__ = frozenset((
                'some_method',
                'some_property',
            ))

        for ex in (example, example()):
            # Test using str:
            assert ex.implements('some_method')
            assert not ex.implements('another_method')

            # Test using frozenset:
            assert ex.implements(frozenset(['some_method']))
            assert not ex.implements(
                frozenset(['some_method', 'another_method'])
            )

            # Test using another object/class with __public__ frozenset:
            assert ex.implements(example)
            assert ex.implements(example())

            assert ex.implements(subset)
            assert not subset.implements(ex)

            assert not ex.implements(superset)
            assert superset.implements(ex)

            assert ex.implements(any_object)
            assert ex.implements(any_object())

    def test_implemented_by(self):
        """
        Test the `ipalib.plugable.Plugin.implemented_by` classmethod.
        """
        class base(self.cls):
            __public__ = frozenset((
                'attr0',
                'attr1',
                'attr2',
            ))

        class okay(base):
            def attr0(self):
                pass
            def __get_attr1(self):
                assert False # Make sure property isn't accesed on instance
            attr1 = property(__get_attr1)
            attr2 = 'hello world'
            another_attr = 'whatever'

        class fail(base):
            def __init__(self):
                # Check that class, not instance is inspected:
                self.attr2 = 'hello world'
            def attr0(self):
                pass
            def __get_attr1(self):
                assert False # Make sure property isn't accesed on instance
            attr1 = property(__get_attr1)
            another_attr = 'whatever'

        # Test that AssertionError is raised trying to pass something not
        # subclass nor instance of base:
        raises(AssertionError, base.implemented_by, object)

        # Test on subclass with needed attributes:
        assert base.implemented_by(okay) is True
        assert base.implemented_by(okay()) is True

        # Test on subclass *without* needed attributes:
        assert base.implemented_by(fail) is False
        assert base.implemented_by(fail()) is False

    def test_set_api(self):
        """
        Test the `ipalib.plugable.Plugin.set_api` method.
        """
        api = 'the api instance'
        o = self.cls()
        assert o.api is None
        e = raises(AssertionError, o.set_api, None)
        assert str(e) == 'set_api() argument cannot be None'
        o.set_api(api)
        assert o.api is api
        e = raises(AssertionError, o.set_api, api)
        assert str(e) == 'set_api() can only be called once'

    def test_finalize(self):
        """
        Test the `ipalib.plugable.Plugin.finalize` method.
        """
        o = self.cls()
        assert not o.__islocked__()
        o.finalize()
        assert o.__islocked__()


class test_PluginProxy(ClassChecker):
    """
    Test the `ipalib.plugable.PluginProxy` class.
    """
    _cls = plugable.PluginProxy

    def test_class(self):
        """
        Test the `ipalib.plugable.PluginProxy` class.
        """
        assert self.cls.__bases__ == (plugable.SetProxy,)

    def test_proxy(self):
        """
        Test proxy behaviour of `ipalib.plugable.PluginProxy` instance.
        """
        # Setup:
        class base(object):
            __public__ = frozenset((
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
            doc = 'add a new user'

        # Test that TypeError is raised when base is not a class:
        raises(TypeError, self.cls, base(), None)

        # Test that ValueError is raised when target is not instance of base:
        raises(ValueError, self.cls, base, object())

        # Test with correct arguments:
        i = plugin()
        p = self.cls(base, i)
        assert read_only(p, 'name') is plugin.name
        assert read_only(p, 'doc') == plugin.doc
        assert list(p) == sorted(base.__public__)

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
        p = self.cls(base, i, 'attr_name')
        assert read_only(p, 'name') == 'add'

    def test_implements(self):
        """
        Test the `ipalib.plugable.PluginProxy.implements` method.
        """
        class base(object):
            __public__ = frozenset()
            name = 'base'
            doc = 'doc'
            @classmethod
            def implements(cls, arg):
                return arg + 7

        class sub(base):
            @classmethod
            def implements(cls, arg):
                """
                Defined to make sure base.implements() is called, not
                target.implements()
                """
                return arg

        o = sub()
        p = self.cls(base, o)
        assert p.implements(3) == 10

    def test_clone(self):
        """
        Test the `ipalib.plugable.PluginProxy.__clone__` method.
        """
        class base(object):
            __public__ = frozenset()
        class sub(base):
            name = 'some_name'
            doc = 'doc'
            label = 'another_name'

        p = self.cls(base, sub())
        assert read_only(p, 'name') == 'some_name'
        c = p.__clone__('label')
        assert isinstance(c, self.cls)
        assert c is not p
        assert read_only(c, 'name') == 'another_name'


def test_check_name():
    """
    Test the `ipalib.plugable.check_name` function.
    """
    f = plugable.check_name
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
        assert name is f(name)
        e = raises(TypeError, f, unicode(name))
        assert str(e) == errors.TYPE_FORMAT % ('name', str, unicode(name))
    for name in nope:
        raises(errors.NameSpaceError, f, name)
    for name in okay:
        raises(errors.NameSpaceError, f, name.upper())

class DummyMember(object):
    def __init__(self, i):
        assert type(i) is int
        self.name = 'member_%02d' % i


class test_NameSpace(ClassChecker):
    """
    Test the `ipalib.plugable.NameSpace` class.
    """
    _cls = plugable.NameSpace

    def test_class(self):
        """
        Test the `ipalib.plugable.NameSpace` class.
        """
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        """
        Test the `ipalib.plugable.NameSpace.__init__` method.
        """
        o = self.cls(tuple())
        assert list(o) == []
        assert list(o()) == []
        for cnt in (10, 25):
            members = tuple(DummyMember(cnt - i) for i in xrange(cnt))
            for sort in (True, False):
                o = self.cls(members, sort=sort)
                if sort:
                    ordered = tuple(sorted(members, key=lambda m: m.name))
                else:
                    ordered = members
                names = tuple(m.name for m in ordered)
                assert o.__todict__() == dict((o.name, o) for o in ordered)

                # Test __len__:
                assert len(o) == cnt

                # Test __contains__:
                for name in names:
                    assert name in o
                assert ('member_00') not in o

                # Test __iter__, __call__:
                assert tuple(o) == names
                assert tuple(o()) == ordered

                # Test __getitem__, getattr:
                for (i, member) in enumerate(ordered):
                    assert o[i] is member
                    name = member.name
                    assert o[name] is member
                    assert read_only(o, name) is member

                # Test negative indexes:
                for i in xrange(1, cnt + 1):
                    assert o[-i] is ordered[-i]

                # Test slices:
                assert o[2:cnt-5] == ordered[2:cnt-5]
                assert o[::3] == ordered[::3]

                # Test __repr__:
                assert repr(o) == \
                    'NameSpace(<%d members>, sort=%r)' % (cnt, sort)


def test_Environment():
    """
    Test the `ipalib.plugable.Environment` class.
    """
    # This has to be the same as iter_cnt
    control_cnt = 0
    class prop_class:
        def __init__(self, val):
            self._val = val
        def get_value(self):
            return self._val

    class iter_class(prop_class):
        # Increment this for each time iter_class yields
        iter_cnt = 0
        def get_value(self):
            for item in self._val:
                self.__class__.iter_cnt += 1
                yield item

    # Tests for basic functionality
    basic_tests = (
        ('a', 1),
        ('b', 'basic_foo'),
        ('c', ('basic_bar', 'basic_baz')),
    )
    # Tests with prop classes
    prop_tests = (
        ('d', prop_class(2), 2),
        ('e', prop_class('prop_foo'), 'prop_foo'),
        ('f', prop_class(('prop_bar', 'prop_baz')), ('prop_bar', 'prop_baz')),
    )
    # Tests with iter classes
    iter_tests = (
        ('g', iter_class((3, 4, 5)), (3, 4, 5)),
        ('h', iter_class(('iter_foo', 'iter_bar', 'iter_baz')),
                         ('iter_foo', 'iter_bar', 'iter_baz')
        ),
    )

    # Set all the values
    env = plugable.Environment()
    for name, val in basic_tests:
        env[name] = val
    for name, val, dummy in prop_tests:
        env[name] = val
    for name, val, dummy in iter_tests:
        env[name] = val

    # Test if the values are correct
    for name, val in basic_tests:
        assert env[name] == val
    for name, dummy, val in prop_tests:
        assert env[name] == val
    # Test if the get_value() function is called only when needed
    for name, dummy, correct_values in iter_tests:
        values_in_env = []
        for val in env[name]:
            control_cnt += 1
            assert iter_class.iter_cnt == control_cnt
            values_in_env.append(val)
        assert tuple(values_in_env) == correct_values

    # Test __setattr__()
    env.spam = 'ham'
    assert env.spam == 'ham'

    # Test if we throw AttributeError exception when trying to overwrite
    # existing value, or delete it
    raises(AttributeError, setitem, env, 'a', 1)
    raises(AttributeError, setattr, env, 'a', 1)
    raises(AttributeError, delitem, env, 'a')
    raises(AttributeError, delattr, env, 'a')
    raises(AttributeError, plugable.Environment.update, env, dict(a=1000))
    # This should be silently ignored
    env.update(dict(a=1000), True)
    assert env.a != 1000


def test_Registrar():
    """
    Test the `ipalib.plugable.Registrar` class
    """
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

    # Test __iter__:
    assert list(r) == ['Base1', 'Base2']

    # Test __hasitem__, __getitem__:
    for base in [Base1, Base2]:
        name = base.__name__
        assert name in r
        assert r[name] is base
        magic = getattr(r, name)
        assert type(magic) is plugable.MagicDict
        assert len(magic) == 0

    # Check that TypeError is raised trying to register something that isn't
    # a class:
    raises(TypeError, r, plugin1())

    # Check that SubclassError is raised trying to register a class that is
    # not a subclass of an allowed base:
    raises(errors.SubclassError, r, plugin3)

    # Check that registration works
    r(plugin1)
    assert len(r.Base1) == 1
    assert r.Base1['plugin1'] is plugin1
    assert r.Base1.plugin1 is plugin1

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
    assert len(r.Base1) == 1
    assert r.Base1.plugin1 is plugin1
    assert r.Base1.plugin1 is not orig1

    # Check that MissingOverrideError is raised trying to override a name
    # not yet registerd:
    raises(errors.MissingOverrideError, r, plugin2, override=True)

    # Test that another plugin can be registered:
    assert len(r.Base2) == 0
    r(plugin2)
    assert len(r.Base2) == 1
    assert r.Base2.plugin2 is plugin2

    # Setup to test more registration:
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

    # Again test __hasitem__, __getitem__:
    for base in [Base1, Base2]:
        name = base.__name__
        assert name in r
        assert r[name] is base
        magic = getattr(r, name)
        assert len(magic) == 3
        for key in magic:
            klass = magic[key]
            assert getattr(magic, key) is klass
            assert issubclass(klass, base)


def test_API():
    """
    Test the `ipalib.plugable.API` class.
    """
    assert issubclass(plugable.API, plugable.ReadOnly)

    # Setup the test bases, create the API:
    class base0(plugable.Plugin):
        __public__ = frozenset((
            'method',
        ))

        def method(self, n):
            return n

    class base1(plugable.Plugin):
        __public__ = frozenset((
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
    api.finalize()

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
            assert isinstance(proxy, plugable.PluginProxy)
            assert proxy.name == plugin_name
            assert read_only(ns, plugin_name) is proxy
            assert read_only(proxy, 'method')(7) == 7 + b

    # Test that calling finilize again raises AssertionError:
    raises(AssertionError, api.finalize)

    # Test with base class that doesn't request a proxy
    class NoProxy(plugable.Plugin):
        __proxy__ = False
    api = plugable.API(NoProxy)
    class plugin0(NoProxy):
        pass
    api.register(plugin0)
    class plugin1(NoProxy):
        pass
    api.register(plugin1)
    api.finalize()
    names = ['plugin0', 'plugin1']
    assert list(api.NoProxy) == names
    for name in names:
        plugin = api.NoProxy[name]
        assert getattr(api.NoProxy, name) is plugin
        assert isinstance(plugin, plugable.Plugin)
        assert not isinstance(plugin, plugable.PluginProxy)
