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

from tests.tstutil import raises
from ipalib import config


def test_generate_env():
    """
    Test the `config.generate_env` function
    """

    # Make sure we don't overwrite any properties
    env = dict(
        query_dns = False,
        server = ('first', 'second'),
        realm = 'myrealm',
    )
    d = config.generate_env(env)
    assert d['query_dns'] == False

    # Make sure the servers is overwrote properly (that it is still LazyProp)
    iter = d['server'].get_value()
    assert iter.next() == 'first'
    assert iter.next() == 'second'


def test_LazyProp():
    """
    Test the `config.LazyProp` class
    """

    def dummy():
        return 1

    # Basic sanity testing with no initial value
    prop = config.LazyProp(dummy)
    assert prop.get_value() == 1
    prop.set_value(2)
    assert prop.get_value() == 2

    # Basic sanity testing with initial value
    prop = config.LazyProp(dummy, 3)
    assert prop.get_value() == 3
    prop.set_value(4)
    assert prop.get_value() == 4


def test_LazyIter():
    """
    Test the `config.LazyIter` class
    """

    def dummy():
        yield 1
        yield 2

    # Basic sanity testing with no initial value
    prop = config.LazyIter(dummy)
    iter = prop.get_value()
    assert iter.next() == 1
    assert iter.next() == 2
    raises(StopIteration, iter.next)

    # Basic sanity testing with initial value
    prop = config.LazyIter(dummy, 0)
    iter = prop.get_value()
    assert iter.next() == 0
    assert iter.next() == 1
    assert iter.next() == 2
    raises(StopIteration, iter.next)


def test_read_config():
    """
    Test the `config.read_config` class
    """

    raises(AssertionError, config.read_config, 1)
