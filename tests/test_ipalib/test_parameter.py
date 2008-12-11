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

from tests.util import raises, ClassChecker
from tests.data import binary_bytes, utf8_bytes, unicode_str
from ipalib import parameter


def test_parse_param_spec():
    """
    Test the `ipalib.parameter.parse_param_spec` function.
    """
    f = parameter.parse_param_spec
    assert f('name') == ('name', dict(required=True, multivalue=False))
    assert f('name?') == ('name', dict(required=False, multivalue=False))
    assert f('name*') == ('name', dict(required=False, multivalue=True))
    assert f('name+') == ('name', dict(required=True, multivalue=True))


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
