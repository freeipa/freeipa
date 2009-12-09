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
Test the `tests.util` module.
"""

import util
from util import raises, TYPE, VALUE, LEN, KEYS


class Prop(object):
    def __init__(self, *ops):
        self.__ops = frozenset(ops)
        self.__prop = 'prop value'

    def __get_prop(self):
        if 'get' not in self.__ops:
            raise AttributeError('get prop')
        return self.__prop

    def __set_prop(self, value):
        if 'set' not in self.__ops:
            raise AttributeError('set prop')
        self.__prop = value

    def __del_prop(self):
        if 'del' not in self.__ops:
            raise AttributeError('del prop')
        self.__prop = None

    prop = property(__get_prop, __set_prop, __del_prop)


def test_assert_deepequal():
    f = util.assert_deepequal

    # Test with good scalar values:
    f(u'hello', u'hello', 'foo')
    f(18, 18, 'foo')

    # Test with bad scalar values:
    e = raises(AssertionError, f, u'hello', u'world', 'foo')
    assert str(e) == VALUE % (
        'foo', u'hello', u'world', tuple()
    )

    e = raises(AssertionError, f, 'hello', u'hello', 'foo')
    assert str(e) == TYPE % (
        'foo', str, unicode, 'hello', u'hello', tuple()
    )

    e = raises(AssertionError, f, 18, 18.0, 'foo')
    assert str(e) == TYPE % (
        'foo', int, float, 18, 18.0, tuple()
    )

    # Test with good compound values:
    a = [
        u'hello',
        dict(naughty=u'nurse'),
        18,
    ]
    b = [
        u'hello',
        dict(naughty=u'nurse'),
        18,
    ]
    f(a, b)

    # Test with bad compound values:
    b = [
        'hello',
        dict(naughty=u'nurse'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == TYPE % (
        'foo', unicode, str, u'hello', 'hello', (0,)
    )

    b = [
        u'hello',
        dict(naughty='nurse'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == TYPE % (
        'foo', unicode, str, u'nurse', 'nurse', (1, 'naughty')
    )

    b = [
        u'hello',
        dict(naughty=u'nurse'),
        18.0,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == TYPE % (
        'foo', int, float, 18, 18.0, (2,)
    )

    # List length mismatch
    b = [
        u'hello',
        dict(naughty=u'nurse'),
        18,
        19
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == LEN % (
        'foo', 3, 4, a, b, tuple()
    )

    b = [
        dict(naughty=u'nurse'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == LEN % (
        'foo', 3, 2, a, b, tuple()
    )

    # Dict keys mismatch:

    # Missing
    b = [
        u'hello',
        dict(),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == KEYS % ('foo',
        ['naughty'], [],
        dict(naughty=u'nurse'), dict(),
        (1,)
    )

    # Extra
    b = [
        u'hello',
        dict(naughty=u'nurse', barely=u'legal'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == KEYS % ('foo',
        [], ['barely'],
        dict(naughty=u'nurse'), dict(naughty=u'nurse', barely=u'legal'),
        (1,)
    )

    # Missing + Extra
    b = [
        u'hello',
        dict(barely=u'legal'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == KEYS % ('foo',
        ['naughty'], ['barely'],
        dict(naughty=u'nurse'), dict(barely=u'legal'),
        (1,)
    )


def test_yes_raised():
    f = util.raises

    class SomeError(Exception):
        pass

    class AnotherError(Exception):
        pass

    def callback1():
        'raises correct exception'
        raise SomeError()

    def callback2():
        'raises wrong exception'
        raise AnotherError()

    def callback3():
        'raises no exception'

    f(SomeError, callback1)

    raised = False
    try:
        f(SomeError, callback2)
    except AnotherError:
        raised = True
    assert raised

    raised = False
    try:
        f(SomeError, callback3)
    except util.ExceptionNotRaised:
        raised = True
    assert raised


def test_no_set():
    # Tests that it works when prop cannot be set:
    util.no_set(Prop('get', 'del'), 'prop')

    # Tests that ExceptionNotRaised is raised when prop *can* be set:
    raised = False
    try:
        util.no_set(Prop('set'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised


def test_no_del():
    # Tests that it works when prop cannot be deleted:
    util.no_del(Prop('get', 'set'), 'prop')

    # Tests that ExceptionNotRaised is raised when prop *can* be set:
    raised = False
    try:
        util.no_del(Prop('del'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised


def test_read_only():
    # Test that it works when prop is read only:
    assert util.read_only(Prop('get'), 'prop') == 'prop value'

    # Test that ExceptionNotRaised is raised when prop can be set:
    raised = False
    try:
        util.read_only(Prop('get', 'set'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised

    # Test that ExceptionNotRaised is raised when prop can be deleted:
    raised = False
    try:
        util.read_only(Prop('get', 'del'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised

    # Test that ExceptionNotRaised is raised when prop can be both set and
    # deleted:
    raised = False
    try:
        util.read_only(Prop('get', 'del'), 'prop')
    except util.ExceptionNotRaised:
        raised = True
    assert raised

    # Test that AttributeError is raised when prop can't be read:
    raised = False
    try:
        util.read_only(Prop(), 'prop')
    except AttributeError:
        raised = True
    assert raised
