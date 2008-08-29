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


def test_raise_TypeError():
    """
    Tests the `errors.raise_TypeError` function.
    """
    f = errors.raise_TypeError
    format = '%s: need a %r; got %r'
    name = 'message'
    type_ = unicode
    value = 'Hello.'
    e = raises(TypeError, f, name, type_, value)
    assert e.name is name
    assert e.type is type_
    assert e.value is value
    assert str(e) == format % (name, type_, value)

    # name not an str:
    fail = 42
    e = raises(AssertionError, f, fail, type_, value)
    assert str(e) == format % ('name', str, fail)

    # type_ not a type:
    fail = unicode()
    e = raises(AssertionError, f, name, fail, value)
    assert str(e) == format % ('type_', type, fail)

    # type(value) is type_:
    fail = u'How are you?'
    e = raises(AssertionError, f, name, type_, fail)
    assert str(e) == 'value: %r is a %r' % (fail, type_)
