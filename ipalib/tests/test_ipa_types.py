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
    fail_type = [
        '10',
        10.0,
        10L,
        True,
        False,
        object,
    ]
    for value in fail_type:
        e = raises(TypeError, f, 'low', value, 'high', None)
        assert str(e) == 'low must be an int or None, got: %r' % value
        e = raises(TypeError, f, 'low', None, 'high', value)
        assert str(e) == 'high must be an int or None, got: %r' % value



class test_Type(ClassChecker):
    """
    Tests the `ipa_types.Type` class.
    """
    _cls = ipa_types.Type

    def test_class(self):
        assert self.cls.__bases__ == (plugable.ReadOnly,)



class test_Int(ClassChecker):
    _cls = ipa_types.Int

    def test_init(self):
        o = self.cls()
        assert o.min_value is None
        assert o.max_value is None
        okay = [
            (None, -5),
            (-20, None),
            (-20, -5),
        ]
        fail_type = [
            (None, 10L),
            (5L, None),
            (None, '10'),
            ('5', None),
        ]
        fail_value = [
            (10, 5),
            (5, -5),
            (-5, -10),
        ]
        for (l, h) in okay:
            o = self.cls(min_value=l, max_value=h)
            assert o.min_value is l
            assert o.max_value is h
        for (l, h) in fail_type:
            raises(TypeError, self.cls, min_value=l, max_value=h)
        for (l, h) in fail_value:
            raises(ValueError, self.cls, min_value=l, max_value=h)

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
        assert o.min_length is None
        assert o.max_length is None
        assert o.pattern is None
