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
Unit tests for `ipalib.errors` module.
"""

from tstutil import raises, ClassChecker
from ipalib import errors


type_format = '%s: need a %r; got %r'


def check_TypeError(f, value, type_, name, **kw):
    e = raises(TypeError, f, value, type_, name, **kw)
    assert e.value is value
    assert e.type is type_
    assert e.name is name
    assert str(e) == type_format % (name, type_, value)


def test_raise_TypeError():
    """
    Tests the `errors.raise_TypeError` function.
    """
    f = errors.raise_TypeError
    value = 'Hello.'
    type_ = unicode
    name = 'message'

    check_TypeError(f, value, type_, name)

    # name not an str
    fail_name = 42
    e = raises(AssertionError, f, value, type_, fail_name)
    assert str(e) == type_format % ('name', str, fail_name), str(e)

    # type_ not a type:
    fail_type = unicode()
    e = raises(AssertionError, f, value, fail_type, name)
    assert str(e) == type_format % ('type_', type, fail_type)

    # type(value) is type_:
    fail_value = u'How are you?'
    e = raises(AssertionError, f, fail_value, type_, name)
    assert str(e) == 'value: %r is a %r' % (fail_value, type_)


def test_check_type():
    """
    Tests the `errors.check_type` function.
    """
    f = errors.check_type
    value = 'How are you?'
    type_ = str
    name = 'greeting'

    # Should pass:
    assert value is f(value, type_, name)
    assert None is f(None, type_, name, allow_None=True)

    # Should raise TypeError
    check_TypeError(f, None, type_, name)
    check_TypeError(f, value, basestring, name)
    check_TypeError(f, value, unicode, name)

    # name not an str
    fail_name = unicode(name)
    e = raises(AssertionError, f, value, type_, fail_name)
    assert str(e) == type_format % ('name', str, fail_name)

    # type_ not a type:
    fail_type = 42
    e = raises(AssertionError, f, value, fail_type, name)
    assert str(e) == type_format % ('type_', type, fail_type)

    # allow_None not a bool:
    fail_bool = 0
    e = raises(AssertionError, f, value, type_, name, allow_None=fail_bool)
    assert str(e) == type_format % ('allow_None', bool, fail_bool)


def test_check_isinstance():
    """
    Tests the `errors.check_isinstance` function.
    """
    f = errors.check_isinstance
    value = 'How are you?'
    type_ = str
    name = 'greeting'

    # Should pass:
    assert value is f(value, type_, name)
    assert value is f(value, basestring, name)
    assert None is f(None, type_, name, allow_None=True)

    # Should raise TypeError
    check_TypeError(f, None, type_, name)
    check_TypeError(f, value, unicode, name)

    # name not an str
    fail_name = unicode(name)
    e = raises(AssertionError, f, value, type_, fail_name)
    assert str(e) == type_format % ('name', str, fail_name)

    # type_ not a type:
    fail_type = 42
    e = raises(AssertionError, f, value, fail_type, name)
    assert str(e) == type_format % ('type_', type, fail_type)

    # allow_None not a bool:
    fail_bool = 0
    e = raises(AssertionError, f, value, type_, name, allow_None=fail_bool)
    assert str(e) == type_format % ('allow_None', bool, fail_bool)
