# Authors:
#   Martin Nagy <mnagy@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Test the `ipalib.config` module.
"""

from os import path
import sys
from ipatests.util import raises, delitem, ClassChecker
from ipatests.util import getitem
from ipatests.util import TempDir, TempHome
from ipalib.constants import OVERRIDE_ERROR, SET_ERROR, DEL_ERROR
from ipalib.constants import NAME_REGEX, NAME_ERROR
from ipalib import config, constants, base

import pytest

pytestmark = pytest.mark.tier0

# Valid environment variables in (key, raw, value) tuples:
#    key: the name of the environment variable
#    raw: the value being set (possibly a string repr)
#    value: the expected value after the lightweight conversion
good_vars = (
    ('a_string', u'Hello world!', u'Hello world!'),
    ('trailing_whitespace', u' value  ', u'value'),
    ('an_int', 42, 42),
    ('int_repr', ' 42 ', 42),
    ('not_a_float', '3.14', u'3.14'),
    ('true', True, True),
    ('true_repr', ' True ', True),
    ('false', False, False),
    ('false_repr', ' False ', False),
    ('none', None, None),
    ('none_repr', ' None ', None),
    ('empty', '', None),

    # These verify that the implied conversion is case-sensitive:
    ('not_true', u' true ', u'true'),
    ('not_false', u' false ', u'false'),
    ('not_none', u' none ', u'none'),
)


bad_names = (
    ('CamelCase', u'value'),
    ('_leading_underscore', u'value'),
    ('trailing_underscore_', u'value'),
)


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

string = Hello world!
null = None
yes = True
no = False
number = 42
floating = 3.14
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

    def test_init(self):
        """
        Test the `ipalib.config.Env.__init__` method.
        """
        o = self.cls()
        assert list(o) == []
        assert len(o) == 0
        assert o.__islocked__() is False

    def test_lock(self):
        """
        Test the `ipalib.config.Env.__lock__` method.
        """
        o = self.cls()
        assert o.__islocked__() is False
        o.__lock__()
        assert o.__islocked__() is True
        e = raises(Exception, o.__lock__)
        assert str(e) == 'Env.__lock__() already called'

        # Also test with base.lock() function:
        o = self.cls()
        assert o.__islocked__() is False
        assert base.lock(o) is o
        assert o.__islocked__() is True
        e = raises(AssertionError, base.lock, o)
        assert str(e) == 'already locked: %r' % o

    def test_islocked(self):
        """
        Test the `ipalib.config.Env.__islocked__` method.
        """
        o = self.cls()
        assert o.__islocked__() is False
        assert base.islocked(o) is False
        o.__lock__()
        assert o.__islocked__() is True
        assert base.islocked(o) is True

    def test_setattr(self):
        """
        Test the `ipalib.config.Env.__setattr__` method.
        """
        o = self.cls()
        for (name, raw, value) in good_vars:
            # Test setting the value:
            setattr(o, name, raw)
            result = getattr(o, name)
            assert type(result) is type(value)
            assert result == value
            assert result is o[name]

            # Test that value cannot be overridden once set:
            e = raises(AttributeError, setattr, o, name, raw)
            assert str(e) == OVERRIDE_ERROR % ('Env', name, value, raw)

        # Test that values cannot be set once locked:
        o = self.cls()
        o.__lock__()
        for (name, raw, value) in good_vars:
            e = raises(AttributeError, setattr, o, name, raw)
            assert str(e) == SET_ERROR % ('Env', name, raw)

        # Test that name is tested with check_name():
        o = self.cls()
        for (name, value) in bad_names:
            e = raises(ValueError, setattr, o, name, value)
            assert str(e) == NAME_ERROR % (NAME_REGEX, name)

    def test_setitem(self):
        """
        Test the `ipalib.config.Env.__setitem__` method.
        """
        o = self.cls()
        for (key, raw, value) in good_vars:
            # Test setting the value:
            o[key] = raw
            result = o[key]
            assert type(result) is type(value)
            assert result == value
            assert result is getattr(o, key)

            # Test that value cannot be overridden once set:
            e = raises(AttributeError, o.__setitem__, key, raw)
            assert str(e) == OVERRIDE_ERROR % ('Env', key, value, raw)

        # Test that values cannot be set once locked:
        o = self.cls()
        o.__lock__()
        for (key, raw, value) in good_vars:
            e = raises(AttributeError, o.__setitem__, key, raw)
            assert str(e) == SET_ERROR % ('Env', key, raw)

        # Test that name is tested with check_name():
        o = self.cls()
        for (key, value) in bad_names:
            e = raises(ValueError, o.__setitem__, key, value)
            assert str(e) == NAME_ERROR % (NAME_REGEX, key)

    def test_getitem(self):
        """
        Test the `ipalib.config.Env.__getitem__` method.
        """
        o = self.cls()
        value = u'some value'
        o.key = value
        assert o.key is value
        assert o['key'] is value
        for name in ('one', 'two'):
            e = raises(KeyError, getitem, o, name)
            assert str(e) == repr(name)

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
            assert str(e) == DEL_ERROR % ('Env', key)
            e = raises(AttributeError, delitem, o, key)
            assert str(e) == '__delitem__'

    def test_contains(self):
        """
        Test the `ipalib.config.Env.__contains__` method.
        """
        o = self.cls()
        items = [
            ('one', 1),
            ('two', 2),
            ('three', 3),
            ('four', 4),
        ]
        for (key, value) in items:
            assert key not in o
            o[key] = value
            assert key in o

    def test_len(self):
        """
        Test the `ipalib.config.Env.__len__` method.
        """
        o = self.cls()
        assert len(o) == 0
        for i in range(1, 11):
            key = 'key%d' % i
            value = u'value %d' % i
            o[key] = value
            assert o[key] is value
            assert len(o) == i

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

    def test_merge(self):
        """
        Test the `ipalib.config.Env._merge` method.
        """
        group1 = (
            ('key1', u'value 1'),
            ('key2', u'value 2'),
            ('key3', u'value 3'),
            ('key4', u'value 4'),
        )
        group2 = (
            ('key0', u'Value 0'),
            ('key2', u'Value 2'),
            ('key4', u'Value 4'),
            ('key5', u'Value 5'),
        )
        o = self.cls()
        assert o._merge(**dict(group1)) == (4, 4)
        assert len(o) == 4
        assert list(o) == list(key for (key, value) in group1)
        for (key, value) in group1:
            assert getattr(o, key) is value
            assert o[key] is value
        assert o._merge(**dict(group2)) == (2, 4)
        assert len(o) == 6
        expected = dict(group2)
        expected.update(dict(group1))
        assert list(o) == sorted(expected)
        assert expected['key2'] == 'value 2'  # And not 'Value 2'
        for (key, value) in expected.items():
            assert getattr(o, key) is value
            assert o[key] is value
        assert o._merge(**expected) == (0, 6)
        assert len(o) == 6
        assert list(o) == sorted(expected)

    def test_merge_from_file(self):
        """
        Test the `ipalib.config.Env._merge_from_file` method.
        """
        tmp = TempDir()
        assert callable(tmp.join)

        # Test a config file that doesn't exist
        no_exist = tmp.join('no_exist.conf')
        assert not path.exists(no_exist)
        o = self.cls()
        o._bootstrap()
        keys = tuple(o)
        orig = dict((k, o[k]) for k in o)
        assert o._merge_from_file(no_exist) is None
        assert tuple(o) == keys

        # Test an empty config file
        empty = tmp.touch('empty.conf')
        assert path.isfile(empty)
        assert o._merge_from_file(empty) == (0, 0)
        assert tuple(o) == keys

        # Test a mal-formed config file:
        bad = tmp.join('bad.conf')
        open(bad, 'w').write(config_bad)
        assert path.isfile(bad)
        assert o._merge_from_file(bad) is None
        assert tuple(o) == keys

        # Test a valid config file that tries to override
        override = tmp.join('override.conf')
        open(override, 'w').write(config_override)
        assert path.isfile(override)
        assert o._merge_from_file(override) == (4, 6)
        for (k, v) in orig.items():
            assert o[k] is v
        assert list(o) == sorted(keys + ('key0', 'key1', 'key2', 'key3', 'config_loaded'))
        for i in range(4):
            assert o['key%d' % i] == ('var%d' % i)
        keys = tuple(o)

        # Test a valid config file with type conversion
        good = tmp.join('good.conf')
        open(good, 'w').write(config_good)
        assert path.isfile(good)
        assert o._merge_from_file(good) == (6, 6)
        added = ('string', 'null', 'yes', 'no', 'number', 'floating')
        assert list(o) == sorted(keys + added)
        assert o.string == 'Hello world!'
        assert o.null is None
        assert o.yes is True
        assert o.no is False
        assert o.number == 42
        assert o.floating == '3.14'

    def new(self, in_tree=False):
        """
        Set os.environ['HOME'] to a tempdir.

        Returns tuple with new Env instance and the TempHome instance.  This
        helper method is used in testing the bootstrap related methods below.
        """
        home = TempHome()
        o = self.cls()
        if in_tree:
            o.in_tree = True
        return (o, home)

    def bootstrap(self, **overrides):
        """
        Helper method used in testing bootstrap related methods below.
        """
        (o, home) = self.new()
        assert o._isdone('_bootstrap') is False
        o._bootstrap(**overrides)
        assert o._isdone('_bootstrap') is True
        e = raises(Exception, o._bootstrap)
        assert str(e) == 'Env._bootstrap() already called'
        return (o, home)

    def test_bootstrap(self):
        """
        Test the `ipalib.config.Env._bootstrap` method.
        """
        # Test defaults created by _bootstrap():
        (o, home) = self.new()
        o._bootstrap()
        ipalib = path.dirname(path.abspath(config.__file__))
        assert o.ipalib == ipalib
        assert o.site_packages == path.dirname(ipalib)
        assert o.script == path.abspath(sys.argv[0])
        assert o.bin == path.dirname(path.abspath(sys.argv[0]))
        assert o.home == home.path
        assert o.dot_ipa == home.join('.ipa')
        assert o.in_tree is False
        assert o.context == 'default'
        assert o.confdir == '/etc/ipa'
        assert o.conf == '/etc/ipa/default.conf'
        assert o.conf_default == o.conf

        # Test overriding values created by _bootstrap()
        (o, home) = self.bootstrap(in_tree='True', context='server')
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

    def finalize_core(self, ctx, **defaults):
        """
        Helper method used in testing `Env._finalize_core`.
        """
        # We must force in_tree=True so we don't load possible config files in
        # /etc/ipa/, whose contents could break this test:
        (o, home) = self.new(in_tree=True)
        if ctx:
            o.context = ctx

        # Check that calls cascade down the chain:
        set_here = ('in_server', 'logdir', 'log')
        assert o._isdone('_bootstrap') is False
        assert o._isdone('_finalize_core') is False
        assert o._isdone('_finalize') is False
        for key in set_here:
            assert key not in o
        o._finalize_core(**defaults)
        assert o._isdone('_bootstrap') is True
        assert o._isdone('_finalize_core') is True
        assert o._isdone('_finalize') is False  # Should not cascade
        for key in set_here:
            assert key in o

        # Check that it can't be called twice:
        e = raises(Exception, o._finalize_core)
        assert str(e) == 'Env._finalize_core() already called'

        return (o, home)

    def test_finalize_core(self):
        """
        Test the `ipalib.config.Env._finalize_core` method.
        """
        # Test that correct defaults are generated:
        (o, home) = self.finalize_core(None)
        assert o.in_server is False
        assert o.logdir == home.join('.ipa', 'log')
        assert o.log == home.join('.ipa', 'log', 'default.log')

        # Test with context='server'
        (o, home) = self.finalize_core('server')
        assert o.in_server is True
        assert o.logdir == home.join('.ipa', 'log')
        assert o.log == home.join('.ipa', 'log', 'server.log')

        # Test that **defaults can't set in_server, logdir, nor log:
        (o, home) = self.finalize_core(None,
            in_server='IN_SERVER',
            logdir='LOGDIR',
            log='LOG',
        )
        assert o.in_server is False
        assert o.logdir == home.join('.ipa', 'log')
        assert o.log == home.join('.ipa', 'log', 'default.log')

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
        assert o.logdir == home.join('.ipa', 'log')
        assert o.log == home.join('.ipa', 'log', 'server.log')
        assert o.yes is True
        assert o.no is False
        assert o.number == 42
        assert o.not_in_other == 'foo_bar'

        # Test using DEFAULT_CONFIG:
        defaults = dict(constants.DEFAULT_CONFIG)
        (o, home) = self.finalize_core(None, **defaults)
        list_o = [key for key in o if key != 'fips_mode']
        assert list_o == sorted(defaults)
        for (key, value) in defaults.items():
            if value is object:
                continue
            if key == 'mode':
                continue
            assert o[key] == value, '%r is %r; should be %r' % (key, o[key], value)

    def test_finalize(self):
        """
        Test the `ipalib.config.Env._finalize` method.
        """
        # Check that calls cascade up the chain:
        o, _home = self.new(in_tree=True)
        assert o._isdone('_bootstrap') is False
        assert o._isdone('_finalize_core') is False
        assert o._isdone('_finalize') is False
        o._finalize()
        assert o._isdone('_bootstrap') is True
        assert o._isdone('_finalize_core') is True
        assert o._isdone('_finalize') is True

        # Check that it can't be called twice:
        e = raises(Exception, o._finalize)
        assert str(e) == 'Env._finalize() already called'

        # Check that _finalize() calls __lock__()
        o, _home = self.new(in_tree=True)
        assert o.__islocked__() is False
        o._finalize()
        assert o.__islocked__() is True
        e = raises(Exception, o.__lock__)
        assert str(e) == 'Env.__lock__() already called'

        # Check that **lastchance works
        o, _home = self.finalize_core(None)
        key = 'just_one_more_key'
        value = u'with one more value'
        lastchance = {key: value}
        assert key not in o
        assert o._isdone('_finalize') is False
        o._finalize(**lastchance)
        assert key in o
        assert o[key] is value
