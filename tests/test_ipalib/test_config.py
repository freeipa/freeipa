# Authors:
#   Martin Nagy <mnagy@redhat.com>
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
Test the `ipalib.config` module.
"""

import types
import os
from os import path
import sys
from tests.util import raises, setitem, delitem, ClassChecker
from tests.util import getitem, setitem, delitem
from tests.util import TempDir, TempHome
from ipalib import config, constants


def test_Environment():
    """
    Test the `ipalib.config.Environment` class.
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
    env = config.Environment()
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
    assert env['spam'] == 'ham'
    assert env.get('spam') == 'ham'
    assert env.get('nonexistent') == None
    assert env.get('nonexistent', 42) == 42

    # Test if we throw AttributeError exception when trying to overwrite
    # existing value, or delete it
    raises(AttributeError, setitem, env, 'a', 1)
    raises(AttributeError, setattr, env, 'a', 1)
    raises(AttributeError, delitem, env, 'a')
    raises(AttributeError, delattr, env, 'a')
    raises(AttributeError, config.Environment.update, env, dict(a=1000))
    # This should be silently ignored
    env.update(dict(a=1000), True)
    assert env.a != 1000


# Random base64-encoded data to simulate a misbehaving config file.
config_bad = """
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
"""

# A config file that tries to override some standard vars:
config_override = """
[global]

key0 = var0
home = /home/sweet/home
key1 = var1
site_packages = planet
key2 = var2
key3 = var3
"""

# A config file that tests the automatic type conversion
config_good = """
[global]

yes = tRUE
no = fALse
number = 42
"""

# A default config file to make sure it does not overwrite the explicit one
config_default = """
[global]

yes = Hello
not_in_other = foo_bar
"""


class test_Env(ClassChecker):
    """
    Test the `ipalib.config.Env` class.
    """

    _cls = config.Env

    def new(self):
        """
        Set os.environ['HOME'] to a tempdir.

        Returns tuple with new Env instance and the TempHome instance.
        """
        home = TempHome()
        return (self.cls(), home)

    def test_init(self):
        """
        Test the `ipalib.config.Env.__init__` method.
        """
        (o, home) = self.new()
        ipalib = path.dirname(path.abspath(config.__file__))
        assert o.ipalib == ipalib
        assert o.site_packages == path.dirname(ipalib)
        assert o.script == path.abspath(sys.argv[0])
        assert o.bin == path.dirname(path.abspath(sys.argv[0]))
        assert o.home == home.path
        assert o.dot_ipa == home.join('.ipa')

    def bootstrap(self, **overrides):
        (o, home) = self.new()
        assert o._isdone('_bootstrap') is False
        o._bootstrap(**overrides)
        assert o._isdone('_bootstrap') is True
        e = raises(StandardError, o._bootstrap)
        assert str(e) == 'Env._bootstrap() already called'
        return (o, home)

    def test_bootstrap(self):
        """
        Test the `ipalib.config.Env._bootstrap` method.
        """
        # Test defaults created by _bootstrap():
        (o, home) = self.new()
        assert 'in_tree' not in o
        assert 'context' not in o
        assert 'conf' not in o
        o._bootstrap()
        assert o.in_tree is False
        assert o.context == 'default'
        assert o.conf == '/etc/ipa/default.conf'
        assert o.conf_default == o.conf

        # Test overriding values created by _bootstrap()
        (o, home) = self.bootstrap(in_tree='true', context='server')
        assert o.in_tree is True
        assert o.context == 'server'
        assert o.conf == home.join('.ipa', 'server.conf')
        (o, home) = self.bootstrap(conf='/my/wacky/whatever.conf')
        assert o.in_tree is False
        assert o.context == 'default'
        assert o.conf == '/my/wacky/whatever.conf'
        assert o.conf_default == '/etc/ipa/default.conf'
        (o, home) = self.bootstrap(conf_default='/my/wacky/default.conf')
        assert o.in_tree is False
        assert o.context == 'default'
        assert o.conf == '/etc/ipa/default.conf'
        assert o.conf_default == '/my/wacky/default.conf'

        # Test various overrides and types conversion
        kw = dict(
            yes=True,
            no=False,
            num=42,
            msg='Hello, world!',
        )
        override = dict(
            (k, u' %s ' % v) for (k, v) in kw.items()
        )
        (o, home) = self.new()
        for key in kw:
            assert key not in o
        o._bootstrap(**override)
        for (key, value) in kw.items():
            assert getattr(o, key) == value
            assert o[key] == value

    def finalize_core(self, **defaults):
        (o, home) = self.new()
        assert o._isdone('_finalize_core') is False
        o._finalize_core(**defaults)
        assert o._isdone('_finalize_core') is True
        e = raises(StandardError, o._finalize_core)
        assert str(e) == 'Env._finalize_core() already called'
        return (o, home)

    def test_finalize_core(self):
        """
        Test the `ipalib.config.Env._finalize_core` method.
        """
        # Check that calls cascade up the chain:
        (o, home) = self.new()
        assert o._isdone('_bootstrap') is False
        assert o._isdone('_finalize_core') is False
        assert o._isdone('_finalize') is False
        o._finalize_core()
        assert o._isdone('_bootstrap') is True
        assert o._isdone('_finalize_core') is True
        assert o._isdone('_finalize') is False

        # Check that it can't be called twice:
        e = raises(StandardError, o._finalize_core)
        assert str(e) == 'Env._finalize_core() already called'

        # Check that _bootstrap() did its job:
        (o, home) = self.bootstrap()
        assert 'in_tree' in o
        assert 'conf' in o
        assert 'context' in o

        # Check that keys _finalize_core() will set are not set yet:
        assert 'log' not in o
        assert 'in_server' not in o

        # Check that _finalize_core() did its job:
        o._finalize_core()
        assert 'in_server' in o
        assert 'log' in o
        assert o.in_tree is False
        assert o.context == 'default'
        assert o.in_server is False
        assert o.log == '/var/log/ipa/default.log'

        # Check log is in ~/.ipa/log when context='cli'
        (o, home) = self.bootstrap(context='cli')
        o._finalize_core()
        assert o.in_tree is False
        assert o.log == home.join('.ipa', 'log', 'cli.log')

        # Check **defaults can't set in_server nor log:
        (o, home) = self.bootstrap(in_server='tRUE')
        o._finalize_core(in_server=False)
        assert o.in_server is True
        (o, home) = self.bootstrap(log='/some/silly/log')
        o._finalize_core(log='/a/different/log')
        assert o.log == '/some/silly/log'

        # Test loading config file, plus test some in-tree stuff
        (o, home) = self.bootstrap(in_tree=True, context='server')
        for key in ('yes', 'no', 'number'):
            assert key not in o
        home.write(config_good, '.ipa', 'server.conf')
        home.write(config_default, '.ipa', 'default.conf')
        o._finalize_core()
        assert o.in_tree is True
        assert o.context == 'server'
        assert o.in_server is True
        assert o.log == home.join('.ipa', 'log', 'server.log')
        assert o.yes is True
        assert o.no is False
        assert o.number == 42
        assert o.not_in_other == 'foo_bar'

        # Test using DEFAULT_CONFIG:
        defaults = dict(constants.DEFAULT_CONFIG)
        (o, home) = self.finalize_core(**defaults)
        assert list(o) == sorted(defaults)
        for (key, value) in defaults.items():
            if value is None:
                continue
            assert o[key] is value

    def test_finalize(self):
        """
        Test the `ipalib.config.Env._finalize` method.
        """
        # Check that calls cascade up the chain:
        (o, home) = self.new()
        assert o._isdone('_bootstrap') is False
        assert o._isdone('_finalize_core') is False
        assert o._isdone('_finalize') is False
        o._finalize()
        assert o._isdone('_bootstrap') is True
        assert o._isdone('_finalize_core') is True
        assert o._isdone('_finalize') is True

        # Check that it can't be called twice:
        e = raises(StandardError, o._finalize)
        assert str(e) == 'Env._finalize() already called'

        # Check that _finalize() calls __lock__()
        (o, home) = self.new()
        assert o.__islocked__() is False
        o._finalize()
        assert o.__islocked__() is True
        e = raises(StandardError, o.__lock__)
        assert str(e) == 'Env.__lock__() already called'

        # Check that **lastchance works
        (o, home) = self.finalize_core()
        key = 'just_one_more_key'
        value = 'with one more value'
        lastchance = {key: value}
        assert key not in o
        assert o._isdone('_finalize') is False
        o._finalize(**lastchance)
        assert key in o
        assert o[key] is value

    def test_merge_config(self):
        """
        Test the `ipalib.config.Env._merge_config` method.
        """
        tmp = TempDir()
        assert callable(tmp.join)

        # Test a config file that doesn't exist
        no_exist = tmp.join('no_exist.conf')
        assert not path.exists(no_exist)
        o = self.cls()
        keys = tuple(o)
        orig = dict((k, o[k]) for k in o)
        assert o._merge_config(no_exist) is None
        assert tuple(o) == keys

        # Test an empty config file
        empty = tmp.touch('empty.conf')
        assert path.isfile(empty)
        assert o._merge_config(empty) is None
        assert tuple(o) == keys

        # Test a mal-formed config file:
        bad = tmp.join('bad.conf')
        open(bad, 'w').write(config_bad)
        assert path.isfile(bad)
        assert o._merge_config(bad) is None
        assert tuple(o) == keys

        # Test a valid config file that tries to override
        override = tmp.join('override.conf')
        open(override, 'w').write(config_override)
        assert path.isfile(override)
        assert o._merge_config(override) == (4, 6)
        for (k, v) in orig.items():
            assert o[k] is v
        assert list(o) == sorted(keys + ('key0', 'key1', 'key2', 'key3'))
        for i in xrange(4):
            assert o['key%d' % i] == ('var%d' % i)
        keys = tuple(o)

        # Test a valid config file with type conversion
        good = tmp.join('good.conf')
        open(good, 'w').write(config_good)
        assert path.isfile(good)
        assert o._merge_config(good) == (3, 3)
        assert list(o) == sorted(keys + ('yes', 'no', 'number'))
        assert o.yes is True
        assert o.no is False
        assert o.number == 42

    def test_lock(self):
        """
        Test the `ipalib.config.Env.__lock__` method.
        """
        o = self.cls()
        assert o._Env__locked is False
        o.__lock__()
        assert o._Env__locked is True
        e = raises(StandardError, o.__lock__)
        assert str(e) == 'Env.__lock__() already called'

    def test_getattr(self):
        """
        Test the `ipalib.config.Env.__getattr__` method.

        Also tests the `ipalib.config.Env.__getitem__` method.
        """
        o = self.cls()
        value = 'some value'
        o.key = value
        assert o.key is value
        assert o['key'] is value
        o.call = lambda: 'whatever'
        assert o.call == 'whatever'
        assert o['call'] == 'whatever'
        for name in ('one', 'two'):
            e = raises(AttributeError, getattr, o, name)
            assert str(e) == 'Env.%s' % name
            e = raises(KeyError, getitem, o, name)
            assert str(e) == repr(name)

    def test_setattr(self):
        """
        Test the `ipalib.config.Env.__setattr__` method.

        Also tests the `ipalib.config.Env.__setitem__` method.
        """
        items = [
            ('one', 1),
            ('two', lambda: 2),
            ('three', 3),
            ('four', lambda: 4),
        ]
        for setvar in (setattr, setitem):
            o = self.cls()
            for (i, (name, value)) in enumerate(items):
                setvar(o, name, value)
                assert getattr(o, name) == i + 1
                assert o[name] == i + 1
                if callable(value):
                    assert name not in dir(o)
                else:
                    assert name in dir(o)
                e = raises(AttributeError, setvar, o, name, 42)
                assert str(e) == 'cannot overwrite Env.%s with 42' % name
            o = self.cls()
            o.__lock__()
            for (name, value) in items:
                e = raises(AttributeError, setvar, o, name, value)
                assert str(e) == \
                    'locked: cannot set Env.%s to %r' % (name, value)
            o = self.cls()
            setvar(o, 'yes', ' true ')
            assert o.yes is True
            setvar(o, 'no', ' false ')
            assert o.no is False
            setvar(o, 'msg', u' Hello, world! ')
            assert o.msg == 'Hello, world!'
            assert type(o.msg) is str
            setvar(o, 'num', ' 42 ')
            assert o.num == 42

    def test_delattr(self):
        """
        Test the `ipalib.config.Env.__delattr__` method.

        This also tests that ``__delitem__`` is not implemented.
        """
        o = self.cls()
        o.one = 1
        assert o.one == 1
        for key in ('one', 'two'):
            e = raises(AttributeError, delattr, o, key)
            assert str(e) == 'cannot del Env.%s' % key
            e = raises(AttributeError, delitem, o, key)
            assert str(e) == '__delitem__'

    def test_contains(self):
        """
        Test the `ipalib.config.Env.__contains__` method.
        """
        o = self.cls()
        items = [
            ('one', 1),
            ('two', lambda: 2),
            ('three', 3),
            ('four', lambda: 4),
        ]
        for (key, value) in items:
            assert key not in o
            o[key] = value
            assert key in o

    def test_iter(self):
        """
        Test the `ipalib.config.Env.__iter__` method.
        """
        o = self.cls()
        default_keys = tuple(o)
        keys = ('one', 'two', 'three', 'four', 'five')
        for key in keys:
            o[key] = 'the value'
        assert list(o) == sorted(keys + default_keys)


def test_set_default_env():
    """
    Test the `ipalib.config.set_default_env` function.
    """

    # Make sure we don't overwrite any properties
    d = dict(
        query_dns = False,
        server = ('first', 'second'),
        realm = 'myrealm',
        # test right conversions
        server_context = 'off',
    )
    env = config.Environment()
    config.set_default_env(env)
    env.update(d)
    assert env['server_context'] == False
    assert env['query_dns'] == False

    # Make sure the servers is overwrote properly (that it is still LazyProp)
    iter = env['server']
    assert iter.next() == 'first'
    assert iter.next() == 'second'


def test_LazyProp():
    """
    Test the `ipalib.config.LazyProp` class.
    """

    def dummy():
        return 1

    # Basic sanity testing with no initial value
    prop = config.LazyProp(int, dummy)
    assert prop.get_value() == 1
    prop.set_value(2)
    assert prop.get_value() == 2

    # Basic sanity testing with initial value
    prop = config.LazyProp(int, dummy, 3)
    assert prop.get_value() == 3
    prop.set_value(4)
    assert prop.get_value() == 4


def test_LazyIter():
    """
    Test the `ipalib.config.LazyIter` class.
    """

    def dummy():
        yield 1
        yield 2

    # Basic sanity testing with no initial value
    prop = config.LazyIter(int, dummy)
    iter = prop.get_value()
    assert iter.next() == 1
    assert iter.next() == 2
    raises(StopIteration, iter.next)

    # Basic sanity testing with initial value
    prop = config.LazyIter(int, dummy, 0)
    iter = prop.get_value()
    assert iter.next() == 0
    assert iter.next() == 1
    assert iter.next() == 2
    raises(StopIteration, iter.next)


def test_read_config():
    """
    Test the `ipalib.config.read_config` class.
    """

    raises(AssertionError, config.read_config, 1)
