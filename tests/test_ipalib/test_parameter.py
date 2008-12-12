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
Test the `ipalib.parameter` module.
"""

from tests.util import raises, ClassChecker, read_only
from tests.data import binary_bytes, utf8_bytes, unicode_str
from ipalib import parameter
from ipalib.constants import TYPE_ERROR, CALLABLE_ERROR


class test_DefaultFrom(ClassChecker):
    """
    Test the `ipalib.parameter.DefaultFrom` class.
    """
    _cls = parameter.DefaultFrom

    def test_init(self):
        """
        Test the `ipalib.parameter.DefaultFrom.__init__` method.
        """
        def callback(*args):
            return args
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        assert read_only(o, 'callback') is callback
        assert read_only(o, 'keys') == keys
        lam = lambda first, last: first[0] + last
        o = self.cls(lam)
        assert read_only(o, 'keys') == ('first', 'last')

    def test_call(self):
        """
        Test the `ipalib.parameter.DefaultFrom.__call__` method.
        """
        def callback(givenname, sn):
            return givenname[0] + sn[0]
        keys = ('givenname', 'sn')
        o = self.cls(callback, *keys)
        kw = dict(
            givenname='John',
            sn='Public',
            hello='world',
        )
        assert o(**kw) == 'JP'
        assert o() is None
        for key in ('givenname', 'sn'):
            kw_copy = dict(kw)
            del kw_copy[key]
            assert o(**kw_copy) is None

        # Test using implied keys:
        o = self.cls(lambda first, last: first[0] + last)
        assert o(first='john', last='doe') == 'jdoe'
        assert o(first='', last='doe') is None
        assert o(one='john', two='doe') is None

        # Test that co_varnames slice is used:
        def callback2(first, last):
            letter = first[0]
            return letter + last
        o = self.cls(callback2)
        assert o.keys == ('first', 'last')
        assert o(first='john', last='doe') == 'jdoe'


def test_parse_param_spec():
    """
    Test the `ipalib.parameter.parse_param_spec` function.
    """
    f = parameter.parse_param_spec
    assert f('name') == ('name', dict(required=True, multivalue=False))
    assert f('name?') == ('name', dict(required=False, multivalue=False))
    assert f('name*') == ('name', dict(required=False, multivalue=True))
    assert f('name+') == ('name', dict(required=True, multivalue=True))
    # Make sure other "funny" endings are *not* treated special:
    assert f('name^') == ('name^', dict(required=True, multivalue=False))


class test_Param(ClassChecker):
    """
    Test the `ipalib.parameter.Param` class.
    """
    _cls = parameter.Param

    def test_init(self):
        """
        Test the `ipalib.parameter.Param.__init__` method.
        """
        name = 'my_param'
        o = self.cls(name)
        assert o.name is name
        assert o.__islocked__() is True

        # Test default rules:
        assert o.rules == tuple()

        # Test default kwarg values:
        assert o.cli_name is name
        assert o.doc == ''
        assert o.required is True
        assert o.multivalue is False
        assert o.primary_key is False
        assert o.normalizer is None
        assert o.default is None
        assert o.default_from is None
        assert o.flags == frozenset()

        # Test that ValueError is raised when a kwarg from a subclass
        # conflicts with an attribute:
        class Subclass(self.cls):
            kwargs = self.cls.kwargs + (
                ('convert', callable, None),
            )
        e = raises(ValueError, Subclass, name)
        assert str(e) == "kwarg 'convert' conflicts with attribute on Subclass"

        # Test type validation of keyword arguments:
        class Subclass(self.cls):
            kwargs = self.cls.kwargs + (
                ('extra1', bool, True),
                ('extra2', str, 'Hello'),
                ('extra3', (int, float), 42),
                ('extra4', callable, lambda whatever: whatever + 7),
            )
        o = Subclass('my_param')  # Test with no **kw:
        for (key, kind, default) in o.kwargs:
            # Test with a type invalid for all:
            value = object()
            kw = {key: value}
            e = raises(TypeError, Subclass, 'my_param', **kw)
            if kind is callable:
                assert str(e) == CALLABLE_ERROR % (key, value, type(value))
            else:
                assert str(e) == TYPE_ERROR % (key, kind, value, type(value))
            # Test with None:
            kw = {key: None}
            Subclass('my_param', **kw)

        # Test when using unknown kwargs:
        e = raises(TypeError, self.cls, 'my_param',
            flags=['hello', 'world'],
            whatever=u'Hooray!',
        )
        assert str(e) == \
            "Param('my_param'): takes no such kwargs: 'whatever'"
        e = raises(TypeError, self.cls, 'my_param', great='Yes', ape='he is!')
        assert str(e) == \
            "Param('my_param'): takes no such kwargs: 'ape', 'great'"

    def test_convert_scalar(self):
        """
        Test the `ipalib.parameter.Param._convert_scalar` method.
        """
        o = self.cls('my_param')
        e = raises(NotImplementedError, o._convert_scalar, 'some value')
        assert str(e) == 'Param._convert_scalar()'
        class Subclass(self.cls):
            pass
        o = Subclass('my_param')
        e = raises(NotImplementedError, o._convert_scalar, 'some value')
        assert str(e) == 'Subclass._convert_scalar()'


class test_Bytes(ClassChecker):
    """
    Test the `ipalib.parameter.Bytes` class.
    """
    _cls = parameter.Bytes

    def test_init(self):
        """
        Test the `ipalib.parameter.Bytes.__init__` method.
        """
        o = self.cls('my_bytes')
        assert o.type is str
        assert o.rules == tuple()
        assert o.minlength is None
        assert o.maxlength is None
        assert o.length is None
        assert o.pattern is None

        # Test mixing length with minlength or maxlength:
        o = self.cls('my_bytes', length=5)
        assert o.length == 5
        assert len(o.rules) == 1
        permutations = [
            dict(minlength=3),
            dict(maxlength=7),
            dict(minlength=3, maxlength=7),
        ]
        for kw in permutations:
            o = self.cls('my_bytes', **kw)
            assert len(o.rules) == len(kw)
            for (key, value) in kw.iteritems():
                assert getattr(o, key) == value
            e = raises(ValueError, self.cls, 'my_bytes', length=5, **kw)
            assert str(e) == \
                "Bytes('my_bytes'): cannot mix length with minlength or maxlength"

        # Test when minlength or maxlength are less than 1:
        e = raises(ValueError, self.cls, 'my_bytes', minlength=0)
        assert str(e) == "Bytes('my_bytes'): minlength must be >= 1; got 0"
        e = raises(ValueError, self.cls, 'my_bytes', maxlength=0)
        assert str(e) == "Bytes('my_bytes'): maxlength must be >= 1; got 0"

        # Test when minlength > maxlength:
        e = raises(ValueError, self.cls, 'my_bytes', minlength=22, maxlength=15)
        assert str(e) == \
            "Bytes('my_bytes'): minlength > maxlength (minlength=22, maxlength=15)"

        # Test when minlength == maxlength
        e = raises(ValueError, self.cls, 'my_bytes', minlength=7, maxlength=7)
        assert str(e) == \
            "Bytes('my_bytes'): minlength == maxlength; use length=7 instead"


class test_Str(ClassChecker):
    """
    Test the `ipalib.parameter.Str` class.
    """
    _cls = parameter.Str

    def test_init(self):
        """
        Test the `ipalib.parameter.Str.__init__` method.
        """
        o = self.cls('my_str')
        assert o.type is unicode
        assert o.minlength is None
        assert o.maxlength is None
        assert o.length is None
        assert o.pattern is None

    def test_convert_scalar(self):
        """
        Test the `ipalib.parameter.Str._convert_scalar` method.
        """
        o = self.cls('my_str')
        for value in (u'Hello', 42, 1.2, True):
            assert o._convert_scalar(value) == unicode(value)
        for value in ('Hello', None, [u'42', '42'], dict(hello=u'world')):
            e = raises(TypeError, o._convert_scalar, value)
            assert str(e) == \
                'Can only implicitly convert int, float, or bool; got %r' % value
