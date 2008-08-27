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
Unit tests for `ipalib.ipa_types` module.
"""

from tstutil import raises, getitem, no_set, no_del, read_only, ClassChecker
from ipalib import ipa_types, errors, plugable


def test_check_min_max():
    """
    Tests the `ipa_types.check_min_max` function.
    """
    f = ipa_types.check_min_max
    okay = [
            (None, -5),
            (-20, None),
            (-20, -5),
    ]
    for (l, h) in okay:
        assert f(l, h, 'low', 'high') is None
    fail_type = [
        '10',
        10.0,
        10L,
        True,
        False,
        object,
    ]
    for value in fail_type:
        e = raises(TypeError, f, value, None, 'low', 'high')
        assert str(e) == 'low must be an int or None, got: %r' % value
        e = raises(TypeError, f, None, value, 'low', 'high')
        assert str(e) == 'high must be an int or None, got: %r' % value
    fail_value = [
        (10, 5),
        (-5, -10),
        (5, -10),
    ]
    for (l, h) in fail_value:
        e = raises(ValueError, f, l, h, 'low', 'high')
        assert str(e) == 'low > high: low=%r, high=%r' % (l, h)


class test_Type(ClassChecker):
    """
    Tests the `ipa_types.Type` class.
    """
    _cls = ipa_types.Type

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)


class test_Int(ClassChecker):
    _cls = ipa_types.Int

    def test_class(self):
        assert self.cls.__bases__ == (ipa_types.Type,)
        assert self.cls.type is int

    def test_init(self):
        o = self.cls()
        assert o.name == 'Int'
        assert o.min_value is None
        assert o.max_value is None

        okay = [
            (None, -5),
            (-20, None),
            (-20, -5),
        ]
        for (l, h) in okay:
            o = self.cls(min_value=l, max_value=h)
            assert o.min_value is l
            assert o.max_value is h

        fail_type = [
            '10',
            10.0,
            10L,
            True,
            False,
            object,
        ]
        for value in fail_type:
            e = raises(TypeError, self.cls, min_value=value)
            assert str(e) == (
                'min_value must be an int or None, got: %r' % value
            )
            e = raises(TypeError, self.cls, max_value=value)
            assert str(e) == (
                'max_value must be an int or None, got: %r' % value
            )

        fail_value = [
            (10, 5),
            (5, -5),
            (-5, -10),
        ]
        for (l, h) in fail_value:
            e = raises(ValueError, self.cls, min_value=l, max_value=h)
            assert str(e) == (
                'min_value > max_value: min_value=%d, max_value=%d' % (l, h)
            )

    def test_validate(self):
        o = self.cls(min_value=2, max_value=7)
        assert o.validate(2) is None
        assert o.validate(5) is None
        assert o.validate(7) is None
        assert o.validate(1) == 'Cannot be smaller than 2'
        assert o.validate(8) == 'Cannot be larger than 7'
        for val in ['5', 5.0, 5L, None, True, False, object]:
            assert o.validate(val) == 'Must be an integer'


class test_Unicode(ClassChecker):
    _cls = ipa_types.Unicode

    def test_init(self):
        o = self.cls()
        assert o.name == 'Unicode'
        assert o.min_length is None
        assert o.max_length is None
        assert o.pattern is None
        assert o.regex is None

        # Test min_length, max_length:
        okay = (
            (0, 1),
            (8, 8),
        )
        for (l, h) in okay:
            o = self.cls(min_length=l, max_length=h)
            assert o.min_length == l
            assert o.max_length == h

        fail_type = [
            '10',
            10.0,
            10L,
            True,
            False,
            object,
        ]
        for value in fail_type:
            e = raises(TypeError, self.cls, min_length=value)
            assert str(e) == (
                'min_length must be an int or None, got: %r' % value
            )
            e = raises(TypeError, self.cls, max_length=value)
            assert str(e) == (
                'max_length must be an int or None, got: %r' % value
            )

        fail_value = [
            (10, 5),
            (5, -5),
            (0, -10),
        ]
        for (l, h) in fail_value:
            e = raises(ValueError, self.cls, min_length=l, max_length=h)
            assert str(e) == (
                'min_length > max_length: min_length=%d, max_length=%d' % (l, h)
            )

        for (key, lower) in [('min_length', 0), ('max_length', 1)]:
            value = lower - 1
            kw = {key: value}
            e = raises(ValueError, self.cls, **kw)
            assert str(e) == '%s must be >= %d, got: %d' % (key, lower, value)
