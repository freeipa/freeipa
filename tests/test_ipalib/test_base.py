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
Test the `ipalib.base` module.
"""

from tests.util import ClassChecker, raises
from ipalib.constants import NAME_REGEX
from ipalib.constants import TYPE_ERROR, SET_ERROR, DEL_ERROR
from ipalib import base


class test_ReadOnly(ClassChecker):
    """
    Test the `ipalib.base.ReadOnly` class
    """
    _cls = base.ReadOnly

    def test_lock(self):
        """
        Test the `ipalib.base.ReadOnly.__lock__` method.
        """
        o = self.cls()
        assert o._ReadOnly__locked is False
        o.__lock__()
        assert o._ReadOnly__locked is True
        e = raises(AssertionError, o.__lock__) # Can only be locked once
        assert str(e) == '__lock__() can only be called once'
        assert o._ReadOnly__locked is True # This should still be True

    def test_islocked(self):
        """
        Test the `ipalib.base.ReadOnly.__islocked__` method.
        """
        o = self.cls()
        assert o.__islocked__() is False
        o.__lock__()
        assert o.__islocked__() is True

    def test_setattr(self):
        """
        Test the `ipalib.base.ReadOnly.__setattr__` method.
        """
        o = self.cls()
        o.attr1 = 'Hello, world!'
        assert o.attr1 == 'Hello, world!'
        o.__lock__()
        for name in ('attr1', 'attr2'):
            e = raises(AttributeError, setattr, o, name, 'whatever')
            assert str(e) == SET_ERROR % ('ReadOnly', name, 'whatever')
        assert o.attr1 == 'Hello, world!'

    def test_delattr(self):
        """
        Test the `ipalib.base.ReadOnly.__delattr__` method.
        """
        o = self.cls()
        o.attr1 = 'Hello, world!'
        o.attr2 = 'How are you?'
        assert o.attr1 == 'Hello, world!'
        assert o.attr2 == 'How are you?'
        del o.attr1
        assert not hasattr(o, 'attr1')
        o.__lock__()
        e = raises(AttributeError, delattr, o, 'attr2')
        assert str(e) == DEL_ERROR % ('ReadOnly', 'attr2')
        assert o.attr2 == 'How are you?'


def test_check_name():
    """
    Test the `ipalib.base.check_name` function.
    """
    f = base.check_name
    okay = [
        'user_add',
        'stuff2junk',
        'sixty9',
    ]
    nope = [
        '_user_add',
        '__user_add',
        'user_add_',
        'user_add__',
        '_user_add_',
        '__user_add__',
        '60nine',
    ]
    for name in okay:
        assert name is f(name)
        e = raises(TypeError, f, unicode(name))
        assert str(e) == TYPE_ERROR % ('name', str, unicode(name), unicode)
    error = 'name must match %r; got %r'
    for name in nope:
        e = raises(ValueError, f, name)
        assert str(e) == error % (NAME_REGEX, name)
    for name in okay:
        e = raises(ValueError, f, name.upper())
        assert str(e) == error % (NAME_REGEX, name.upper())
