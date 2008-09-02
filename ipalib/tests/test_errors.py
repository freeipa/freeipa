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

def check_TypeError(f, name, type_, value, **kw):
    e = raises(TypeError, f, name, type_, value, **kw)
    assert e.name is name
    assert e.type is type_
    assert e.value is value
    assert str(e) == type_format % (name, type_, value)


def test_raise_TypeError():
    """
    Tests the `errors.raise_TypeError` function.
    """
    f = errors.raise_TypeError
    name = 'message'
    type_ = unicode
    value = 'Hello.'

    check_TypeError(f, name, type_, value)

    # name not an str:
    fail = 42
    e = raises(AssertionError, f, fail, type_, value)
    assert str(e) == type_format % ('name', str, fail)

    # type_ not a type:
    fail = unicode()
    e = raises(AssertionError, f, name, fail, value)
    assert str(e) == type_format % ('type_', type, fail)

    # type(value) is type_:
    fail = u'How are you?'
    e = raises(AssertionError, f, name, type_, fail)
    assert str(e) == 'value: %r is a %r' % (fail, type_)


def test_check_type():
    """
    Tests the `errors.check_type` function.
    """
    f = errors.check_type
    name = 'greeting'
    value = 'How are you?'

    # Should pass:
    assert value is f(name, str, value)
    assert None is f(name, str, None, allow_None=True)

    # Should raise TypeError
    check_TypeError(f, name, str, None)
    check_TypeError(f, name, basestring, value)
    check_TypeError(f, name, unicode, value)

    # name not an str
    fail = unicode(name)
    e = raises(AssertionError, f, fail, str, value)
    assert str(e) == type_format % ('name', str, fail)

    # type_ not a type:
    fail = 42
    e = raises(AssertionError, f, name, fail, value)
    assert str(e) == type_format % ('type_', type, fail)

    # allow_None not a bool:
    fail = 0
    e = raises(AssertionError, f, name, str, value, allow_None=fail)
    assert str(e) == type_format % ('allow_None', bool, fail)


def test_check_isinstance():
    """
    Tests the `errors.check_isinstance` function.
    """
    f = errors.check_isinstance
    name = 'greeting'
    value = 'How are you?'

    # Should pass:
    assert value is f(name, str, value)
    assert value is f(name, basestring, value)
    assert None is f(name, str, None, allow_None=True)

    # Should raise TypeError
    check_TypeError(f, name, str, None)
    check_TypeError(f, name, unicode, value)

    # name not an str
    fail = unicode(name)
    e = raises(AssertionError, f, fail, str, value)
    assert str(e) == type_format % ('name', str, fail)

    # type_ not a type:
    fail = 42
    e = raises(AssertionError, f, name, fail, value)
    assert str(e) == type_format % ('type_', type, fail)

    # allow_None not a bool:
    fail = 0
    e = raises(AssertionError, f, name, str, value, allow_None=fail)
    assert str(e) == type_format % ('allow_None', bool, fail)
