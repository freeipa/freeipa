# Authors:
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
Test the `tests.util` module.
"""

import re

import six

from ipatests import util
from ipatests.util import raises, TYPE, VALUE, LEN, KEYS
import pytest

if six.PY3:
    unicode = str

pytestmark = pytest.mark.tier0


# pytest >= 2.10 supports yield based fixtures with pytest.fixture. In
# pytest < 2.10 pytest.yield_fixture is required. But that function
# also raises a deprecation warning in pytest >= 3.0.
PYTEST_VERSION = tuple(int(p) for p in pytest.__version__.split('.'))

if PYTEST_VERSION < (2, 10):
    yield_fixture = pytest.yield_fixture
else:
    yield_fixture = pytest.fixture


pattern_type = type(re.compile(""))


class Prop:
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


class test_Fuzzy:
    klass = util.Fuzzy

    def test_init(self):
        inst = self.klass()
        assert inst.regex is None
        assert inst.type is None
        assert inst.test is None
        assert inst.re is None

        inst = self.klass('(foo|bar)')
        assert inst.regex == '(foo|bar)'
        assert inst.type is unicode
        assert inst.test is None
        assert isinstance(inst.re, pattern_type)

        inst = self.klass('(foo|bar)', type=str)
        assert inst.regex == '(foo|bar)'
        assert inst.type is str
        assert inst.test is None
        assert isinstance(inst.re, pattern_type)

        t = lambda other: other > 500

        inst = self.klass(test=t)
        assert inst.regex is None
        assert inst.type is None
        assert inst.test is t
        assert inst.re is None

        inst = self.klass(type=(int, float), test=t)
        assert inst.regex is None
        assert inst.type == (int, float)
        assert inst.test is t
        assert inst.re is None

    def test_repr(self):
        s = 'Fuzzy(%r, %r, %r)'
        t = lambda other: 0.0 <= other <= 1.0

        inst = self.klass()
        assert repr(inst) == s % (None, None, None)

        inst = self.klass('foo')
        assert repr(inst) == s % ('foo', unicode, None)

        inst = self.klass(type=(int, float))
        assert repr(inst) == s % (None, (int, float), None)

        inst = self.klass(type=(int, float), test=t)
        assert repr(inst) == s % (None, (int, float), t)

        inst = self.klass(test=t)
        assert repr(inst) == s % (None, None, t)

    def test_eq(self):
        assert (self.klass('bar') == u'foobar') is True
        assert (self.klass('^bar') == u'foobar') is False
        assert (self.klass('bar', type=bytes) == u'foobar') is False

        assert ('18' == self.klass()) is True
        assert ('18' == self.klass(type=int)) is False
        assert (18 == self.klass(type=int)) is True
        assert ('18' == self.klass(type=(int, str))) is True

        assert (self.klass() == '18') is True
        assert (self.klass(type=int) == '18') is False
        assert (self.klass(type=int) == 18) is True
        assert (self.klass(type=(int, str)) == '18') is True

        t = lambda other: other.endswith('bar')
        assert (self.klass(test=t) == 'foobar') is True
        assert (self.klass(test=t, type=unicode) == b'foobar') is False
        assert (self.klass(test=t) == 'barfoo') is False

        assert (False == self.klass()) is True
        assert (True == self.klass()) is True
        assert (None == self.klass()) is True


def test_assert_deepequal(pytestconfig):
    f = util.assert_deepequal
    try:  # pylint: disable=no-member
        pretty = pytestconfig.getoption("pretty_print")
    except (AttributeError, ValueError):
        pretty = False

    # LEN and KEYS formats use special function to pretty print structures
    # depending on a pytest environment settings
    def got_str(s):
        return util.struct_to_string(s, util.GOT_LEN) if pretty else str(s)

    def exp_str(s):
        ret = util.struct_to_string(s, util.EXPECTED_LEN) if pretty else str(s)
        return ret

    # Test with good scalar values:
    f(u'hello', u'hello')
    f(util.Fuzzy(), u'hello')
    f(util.Fuzzy(type=unicode), u'hello')
    f(util.Fuzzy('ell'), u'hello')
    f(util.Fuzzy(test=lambda other: other.endswith('llo')), u'hello')
    f(18, 18)
    f(util.Fuzzy(), 18)
    f(util.Fuzzy(type=int), 18)
    f(util.Fuzzy(type=(int, float), test=lambda other: other > 17.9), 18)

    # Test with bad scalar values:
    e = raises(AssertionError, f, u'hello', u'world', 'foo')
    assert str(e) == VALUE % (
        'foo', u'hello', u'world', tuple()
    )

    e = raises(AssertionError, f, b'hello', u'hello', 'foo')
    assert str(e) == TYPE % (
        'foo', bytes, unicode, b'hello', u'hello', tuple()
    )

    e = raises(AssertionError, f, 18, 18.0, 'foo')
    assert str(e) == TYPE % (
        'foo', int, float, 18, 18.0, tuple()
    )

    # Test with good compound values:
    a = [
        u'hello',
        dict(profession=u'nurse'),
        18,
    ]
    b = [
        u'hello',
        dict(profession=u'nurse'),
        18,
    ]
    f(a, b)

    # Test with bad compound values:
    b = [
        b'hello',
        dict(profession=u'nurse'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == TYPE % (
        'foo', unicode, bytes, u'hello', b'hello', (2 if six.PY2 else 0,)
    )

    b = [
        u'hello',
        dict(profession=b'nurse'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == TYPE % (
        'foo', unicode, bytes, u'nurse', b'nurse', (1, 'profession')
    )

    b = [
        u'hello',
        dict(profession=u'nurse'),
        18.0,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == TYPE % (
        'foo', int, float, 18, 18.0, (0 if six.PY2 else 2,)
    )

    # List length mismatch
    b = [
        u'hello',
        dict(profession=u'nurse'),
        18,
        19
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == LEN % (
        'foo', 3, 4, exp_str(a), got_str(b), tuple()
    )

    b = [
        dict(profession=u'nurse'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == LEN % (
        'foo', 3, 2, exp_str(a), got_str(b), tuple()
    )

    # Dict keys mismatch:

    # Missing
    b = [
        u'hello',
        dict(),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == KEYS % (
        'foo',
        ['profession'], [],
        exp_str(dict(profession=u'nurse')), got_str(dict()),
        (1,)
    )

    # Extra
    b = [
        u'hello',
        dict(profession=u'nurse', status=u'RN'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == KEYS % (
        'foo',
        [], ['status'],
        exp_str(dict(profession=u'nurse')),
        got_str(dict(profession=u'nurse', status=u'RN')),
        (1,)
    )

    # Missing + Extra
    b = [
        u'hello',
        dict(status=u'RN'),
        18,
    ]
    e = raises(AssertionError, f, a, b, 'foo')
    assert str(e) == KEYS % (
        'foo',
        ['profession'], ['status'],
        exp_str(dict(profession=u'nurse')), got_str(dict(status=u'RN')),
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
