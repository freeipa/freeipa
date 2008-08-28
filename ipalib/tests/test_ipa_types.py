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

    def test_init(self):
        okay = (bool, int, float, unicode)
        for t in okay:
            o = self.cls(t)
            assert o.__islocked__() is True
            assert read_only(o, 'type') is t
            assert read_only(o, 'name') is 'Type'

        type_errors = (None, True, 8, 8.0, u'hello')
        for t in type_errors:
            e = raises(TypeError, self.cls, t)
            assert str(e) == '%r is not %r' % (type(t), type)

        value_errors = (long, complex, str, tuple, list, dict, set, frozenset)
        for t in value_errors:
            e = raises(ValueError, self.cls, t)
            assert str(e) == 'not an allowed type: %r' % t


class test_Int(ClassChecker):
    _cls = ipa_types.Int

    def test_class(self):
        assert self.cls.__bases__ == (ipa_types.Type,)

    def test_init(self):
        o = self.cls()
        assert o.__islocked__() is True
        assert read_only(o, 'type') is int
        assert read_only(o, 'name') == 'Int'
        assert read_only(o, 'min_value') is None
        assert read_only(o, 'max_value') is None

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

    def test_call(self):
        o = self.cls()

        # Test calling with None
        e = raises(TypeError, o, None)
        assert str(e) == 'value cannot be None'

        # Test with values that can be converted:
        okay = [
            3,
            '3',
            ' 3 ',
            3L,
            3.0,
        ]
        for value in okay:
            assert o(value) == 3

        # Test with values that cannot be converted:
        fail = [
            object,
            '3.0',
            '3L',
            'whatever',
        ]
        for value in fail:
            assert o(value) is None


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

    def test_class(self):
        assert self.cls.__bases__ == (ipa_types.Type,)

    def test_init(self):
        o = self.cls()
        assert o.__islocked__() is True
        assert read_only(o, 'type') is unicode
        assert read_only(o, 'name') == 'Unicode'
        assert read_only(o, 'min_length') is None
        assert read_only(o, 'max_length') is None
        assert read_only(o, 'pattern') is None
        assert read_only(o, 'regex') is None

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

        # Test pattern:
        okay = [
            '(hello|world)',
            u'(take the blue pill|take the red pill)',
        ]
        for value in okay:
            o = self.cls(pattern=value)
            assert o.pattern is value
            assert o.regex is not None

        fail = [
            42,
            True,
            False,
            object,
        ]
        for value in fail:
            e = raises(TypeError, self.cls, pattern=value)
            assert str(e) == (
                'pattern must be a basestring or None, got: %r' % value
            )

        # Test regex:
        pat = '^(hello|world)$'
        o = self.cls(pattern=pat)
        for value in ('hello', 'world'):
            m = o.regex.match(value)
            assert m.group(1) == value
        for value in ('hello beautiful', 'world!'):
            assert o.regex.match(value) is None

    def test_validate(self):
        pat = '^a_*b$'
        o = self.cls(min_length=3, max_length=4, pattern=pat)
        assert o.validate(u'a_b') is None
        assert o.validate(u'a__b') is None
        assert o.validate('a_b') == 'Must be a string'
        assert o.validate(u'ab') == 'Must be at least 3 characters long'
        assert o.validate(u'a___b') == 'Can be at most 4 characters long'
        assert o.validate(u'a-b') == 'Must match %r' % pat
        assert o.validate(u'a--b') == 'Must match %r' % pat
