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

from tests.util import raises, setitem, delitem
#from tests.util import getitem, setitem, delitem
from ipalib import config


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
