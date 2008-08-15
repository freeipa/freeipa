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
from tstutil import getitem, setitem, delitem
from tstutil import ClassChecker
from ipalib import plugable, errors


class test_ReadOnly(ClassChecker):
    """
    Test the `plugable.ReadOnly` class
    """
    _cls = plugable.ReadOnly

    def test_class(self):
        assert self.cls.__bases__ == (object,)
        assert callable(self.cls.__lock__)
        assert callable(self.cls.__islocked__)

    def test_lock(self):
        """
        Tests the `plugable.ReadOnly.__lock__` and
        `plugable.ReadOnly.__islocked__` methods.
        """
        o = self.cls()
        assert o.__islocked__() is False
        o.__lock__()
        assert o.__islocked__() is True
        raises(AssertionError, o.__lock__) # Can only be locked once
        assert o.__islocked__() is True # This should still be True

    def test_when_unlocked(self):
        """
        Test that default state is unlocked, that setting and deleting
        attributes works.
        """
        o = self.cls()

        # Setting:
        o.hello = 'world'
        assert o.hello == 'world'

        # Deleting:
        del o.hello
        assert not hasattr(o, 'hello')

    def test_when_locked(self):
        """
        Test that after __lock__() has been called, setting or deleting an
        attribute raises AttributeError.
        """
        obj = self.cls()
        obj.__lock__()
        names = ['not_an_attribute', 'an_attribute']
        for name in names:
            no_set(obj, name)
            no_del(obj, name)

        class some_ro_class(self.cls):
            def __init__(self):
                self.an_attribute = 'Hello world!'
                self.__lock__()
        obj = some_ro_class()
        for name in names:
            no_set(obj, name)
            no_del(obj, name)
        assert read_only(obj, 'an_attribute') == 'Hello world!'


def test_lock():
    """
    Tests the `plugable.lock` function.
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
    Tests the `plugable.SetProxy` class.
    """
    _cls = plugable.SetProxy

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_init(self):
        okay = (set, frozenset, dict)
        fail = (list, tuple)
        for t in okay:
            self.cls(t())
            raises(TypeError, self.cls, t)
        for t in fail:
            raises(TypeError, self.cls, t())
            raises(TypeError, self.cls, t)

    def test_SetProxy(self):
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
    Tests the `plugable.DictProxy` class.
    """
    _cls = plugable.DictProxy

    def test_class(self):
        assert self.cls.__bases__ == (plugable.SetProxy,)

    def test_init(self):
        self.cls(dict())
        raises(TypeError, self.cls, dict)
        fail = (set, frozenset, list, tuple)
        for t in fail:
            raises(TypeError, self.cls, t())
            raises(TypeError, self.cls, t)

    def test_DictProxy(self):
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
            assert key not in proxy
            raises(KeyError, getitem, proxy, key)

            # Add and test again
            target[key] = val
            assert len(proxy) == len(target)
            assert list(proxy) == sorted(target)

            # Verify TypeError is raised trying to set/del via proxy
            raises(TypeError, setitem, proxy, key, val)
            raises(TypeError, delitem, proxy, key)


class test_MagicDict(ClassChecker):
    """
    Tests the `plugable.MagicDict` class.
    """
    _cls = plugable.MagicDict

    def test_class(self):
        assert self.cls.__bases__ == (plugable.DictProxy,)
        for non_dict in ('hello', 69, object):
            raises(TypeError, self.cls, non_dict)

    def test_MagicDict(self):
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
    Tests the `plugable.Plugin` class.
    """
    _cls = plugable.Plugin

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)
        assert self.cls.__public__ == frozenset()
        assert type(self.cls.name) is property
        assert type(self.cls.doc) is property
        assert type(self.cls.api) is property

    def test_name(self):
        """
        Tests the `plugable.Plugin.name` property.
        """
        assert read_only(self.cls(), 'name') == 'Plugin'

        class some_subclass(self.cls):
            pass
        assert read_only(some_subclass(), 'name') == 'some_subclass'

    def test_doc(self):
        """
        Tests the `plugable.Plugin.doc` property.
        """
        class some_subclass(self.cls):
            'here is the doc string'
        assert read_only(some_subclass(), 'doc') == 'here is the doc string'

    def test_implements(self):
        """
        Tests the `plugable.Plugin.implements` classmethod.
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
        Tests the `plugable.Plugin.implemented_by` classmethod.
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

    def test_finalize(self):
        """
        Tests the `plugable.Plugin.finalize` method.
        """
        api = 'the api instance'
        o = self.cls()
        assert read_only(o, 'name') == 'Plugin'
        assert repr(o) == '%s.Plugin()' % plugable.__name__
        assert read_only(o, 'api') is None
        raises(AssertionError, o.finalize, None)
        o.finalize(api)
        assert read_only(o, 'api') is api
        raises(AssertionError, o.finalize, api)

        class some_plugin(self.cls):
            pass
        sub = some_plugin()
        assert read_only(sub, 'name') == 'some_plugin'
        assert repr(sub) == '%s.some_plugin()' % __name__
        assert read_only(sub, 'api') is None
        raises(AssertionError, sub.finalize, None)
        sub.finalize(api)
        assert read_only(sub, 'api') is api
        raises(AssertionError, sub.finalize, api)


class test_Proxy(ClassChecker):
    """
    Tests the `plugable.Proxy` class.
    """
    _cls = plugable.Proxy

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_proxy(self):
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
        Tests the `plugable.Proxy.implements` method.
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
        Tests the `plugable.Proxy.__clone__` method.
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
    Tests the `plugable.check_name` function.
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
    for name in nope:
        raises(errors.NameSpaceError, f, name)
    for name in okay:
        raises(errors.NameSpaceError, f, name.upper())


class test_NameSpace(ClassChecker):
    """
    Tests the `plugable.NameSpace` class.
    """
    _cls = plugable.NameSpace

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)

    def test_namespace(self):
        class base(object):
            __public__ = frozenset((
                'plusplus',
            ))
            doc = 'doc'

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
        ns = self.cls(get_proxies(cnt))
        assert ns.__islocked__() is True

        # Test __len__
        assert len(ns) == cnt

        # Test __iter__
        i = None
        for (i, key) in enumerate(ns):
            assert type(key) is str
            assert key == get_name(i)
        assert i == cnt - 1

        # Test __call__
        i = None
        for (i, proxy) in enumerate(ns()):
            assert type(proxy) is plugable.Proxy
            assert proxy.name == get_name(i)
        assert i == cnt - 1

        # Test __contains__, __getitem__, getattr():
        proxies = frozenset(ns())
        for i in xrange(cnt):
            name = get_name(i)
            assert name in ns
            proxy = ns[name]
            assert proxy.name == name
            assert type(proxy) is plugable.Proxy
            assert proxy in proxies
            assert read_only(ns, name) is proxy

        # Test dir():
        assert set(get_name(i) for i in xrange(cnt)).issubset(dir(ns))

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
        assert base.__name__ in r
        dp = r[base.__name__]
        assert type(dp) is plugable.MagicDict
        assert len(dp) == 0

    # Check that TypeError is raised trying to register something that isn't
    # a class:
    raises(TypeError, r, plugin1())

    # Check that SubclassError is raised trying to register a class that is
    # not a subclass of an allowed base:
    raises(errors.SubclassError, r, plugin3)

    # Check that registration works
    r(plugin1)
    dp = r['Base1']
    assert type(dp) is plugable.MagicDict
    assert len(dp) == 1
    assert r.Base1 is dp
    assert dp['plugin1'] is plugin1
    assert dp.plugin1 is plugin1

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
        assert base.__name__ in r
        dp = r[base.__name__]
        assert len(dp) == 3
        for key in dp:
            klass = dp[key]
            assert getattr(dp, key) is klass
            assert issubclass(klass, base)


def test_API():
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
            assert isinstance(proxy, plugable.Proxy)
            assert proxy.name == plugin_name
            assert read_only(ns, plugin_name) is proxy
            assert read_only(proxy, 'method')(7) == 7 + b

    # Test that calling finilize again raises AssertionError:
    raises(AssertionError, api.finalize)
