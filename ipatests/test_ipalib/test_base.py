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
Test the `ipalib.base` module.
"""

import six
import pytest

from ipatests.util import ClassChecker, raises
from ipalib.constants import NAME_REGEX, NAME_ERROR
from ipalib.constants import TYPE_ERROR, SET_ERROR, DEL_ERROR, OVERRIDE_ERROR
from ipalib import base

if six.PY3:
    unicode = str


pytestmark = pytest.mark.tier0


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


def test_lock():
    """
    Test the `ipalib.base.lock` function
    """
    f = base.lock

    # Test with ReadOnly instance:
    o = base.ReadOnly()
    assert o.__islocked__() is False
    assert f(o) is o
    assert o.__islocked__() is True
    e = raises(AssertionError, f, o)
    assert str(e) == 'already locked: %r' % o

    # Test with another class implemented locking protocol:
    class Lockable:
        __locked = False
        def __lock__(self):
            self.__locked = True
        def __islocked__(self):
            return self.__locked
    o = Lockable()
    assert o.__islocked__() is False
    assert f(o) is o
    assert o.__islocked__() is True
    e = raises(AssertionError, f, o)
    assert str(e) == 'already locked: %r' % o

    # Test with a class incorrectly implementing the locking protocol:
    class Broken:
        def __lock__(self):
            pass
        def __islocked__(self):
            return False
    o = Broken()
    e = raises(AssertionError, f, o)
    assert str(e) == 'failed to lock: %r' % o


def test_islocked():
    """
    Test the `ipalib.base.islocked` function.
    """
    f = base.islocked

    # Test with ReadOnly instance:
    o = base.ReadOnly()
    assert f(o) is False
    o.__lock__()
    assert f(o) is True

    # Test with another class implemented locking protocol:
    class Lockable:
        __locked = False
        def __lock__(self):
            self.__locked = True
        def __islocked__(self):
            return self.__locked
    o = Lockable()
    assert f(o) is False
    o.__lock__()
    assert f(o) is True

    # Test with a class incorrectly implementing the locking protocol:
    class Broken:
        __lock__ = False
        def __islocked__(self):
            return False
    o = Broken()
    e = raises(AssertionError, f, o)
    assert str(e) == 'no __lock__() method: %r' % o


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
        if six.PY2:
            bad_type = unicode
            bad_value = unicode(name)
        else:
            bad_type = bytes
            bad_value = name.encode('ascii')
        e = raises(TypeError, f, bad_value)
        assert str(e) == TYPE_ERROR % ('name', str, bad_value, bad_type)
    for name in nope:
        e = raises(ValueError, f, name)
        assert str(e) == NAME_ERROR % (NAME_REGEX, name)
    for name in okay:
        e = raises(ValueError, f, name.upper())
        assert str(e) == NAME_ERROR % (NAME_REGEX, name.upper())


def membername(i):
    return 'member%03d' % i


class DummyMember:
    def __init__(self, i):
        self.i = i
        self.name = self.__name__ = membername(i)


def gen_members(*indexes):
    return tuple(DummyMember(i) for i in indexes)


class test_NameSpace(ClassChecker):
    """
    Test the `ipalib.base.NameSpace` class.
    """
    _cls = base.NameSpace

    def new(self, count, sort=True):
        members = tuple(DummyMember(i) for i in range(count, 0, -1))
        assert len(members) == count
        o = self.cls(members, sort=sort)
        return (o, members)

    def test_init(self):
        """
        Test the `ipalib.base.NameSpace.__init__` method.
        """
        o = self.cls([])
        assert len(o) == 0
        assert list(o) == []
        assert list(o()) == []

        # Test members as attribute and item:
        for cnt in (3, 42):
            for sort in (True, False):
                (o, members) = self.new(cnt, sort=sort)
                assert len(members) == cnt
                for m in members:
                    assert getattr(o, m.name) is m
                    assert o[m.name] is m

        # Test that TypeError is raised if sort is not a bool:
        e = raises(TypeError, self.cls, [], sort=None)
        assert str(e) == TYPE_ERROR % ('sort', bool, None, type(None))

        # Test that AttributeError is raised with duplicate member name:
        members = gen_members(0, 1, 2, 1, 3)
        e = raises(AttributeError, self.cls, members)
        assert str(e) == OVERRIDE_ERROR % (
            'NameSpace', membername(1), members[1], members[3]
        )

    def test_len(self):
        """
        Test the `ipalib.base.NameSpace.__len__` method.
        """
        for count in (5, 18, 127):
            o, _members = self.new(count)
            assert len(o) == count
            o, _members = self.new(count, sort=False)
            assert len(o) == count

    def test_iter(self):
        """
        Test the `ipalib.base.NameSpace.__iter__` method.
        """
        (o, members) = self.new(25)
        assert list(o) == sorted(m.name for m in members)
        (o, members) = self.new(25, sort=False)
        assert list(o) == list(m.name for m in members)

    def test_call(self):
        """
        Test the `ipalib.base.NameSpace.__call__` method.
        """
        (o, members) = self.new(25)
        assert list(o()) == sorted(members, key=lambda m: m.name)
        (o, members) = self.new(25, sort=False)
        assert tuple(o()) == members

    def test_contains(self):
        """
        Test the `ipalib.base.NameSpace.__contains__` method.
        """
        yes = (99, 3, 777)
        no = (9, 333, 77)
        for sort in (True, False):
            members = gen_members(*yes)
            o = self.cls(members, sort=sort)
            for i in yes:
                assert membername(i) in o
                assert membername(i).upper() not in o
                assert DummyMember(i) in o
            for i in no:
                assert membername(i) not in o
                assert DummyMember(i) not in o

    def test_getitem(self):
        """
        Test the `ipalib.base.NameSpace.__getitem__` method.
        """
        cnt = 17
        for sort in (True, False):
            (o, members) = self.new(cnt, sort=sort)
            assert len(members) == cnt
            if sort is True:
                members = tuple(sorted(members, key=lambda m: m.name))

            # Test str keys:
            for m in members:
                assert o[m.name] is m
            e = raises(KeyError, o.__getitem__, 'nope')

            # Test int indexes:
            for i in range(cnt):
                assert o[i] is members[i]
            e = raises(IndexError, o.__getitem__, cnt)

            # Test negative int indexes:
            for i in range(1, cnt + 1):
                assert o[-i] is members[-i]
            e = raises(IndexError, o.__getitem__, -(cnt + 1))

            # Test slicing:
            assert o[3:] == members[3:]
            assert o[:10] == members[:10]
            assert o[3:10] == members[3:10]
            assert o[-9:] == members[-9:]
            assert o[:-4] == members[:-4]
            assert o[-9:-4] == members[-9:-4]

            # Test retrieval by value
            for member in members:
                assert o[DummyMember(member.i)] is member

            # Test that TypeError is raised with wrong type
            e = raises(TypeError, o.__getitem__, 3.0)
            assert str(e) == TYPE_ERROR % (
                'key', (str, int, slice, 'object with __name__'),
                3.0, float)

    def test_repr(self):
        """
        Test the `ipalib.base.NameSpace.__repr__` method.
        """
        for cnt in (0, 1, 2):
            for sort in (True, False):
                o, _members = self.new(cnt, sort=sort)
                if cnt == 1:
                    assert repr(o) == \
                        'NameSpace(<%d member>, sort=%r)' % (cnt, sort)
                else:
                    assert repr(o) == \
                        'NameSpace(<%d members>, sort=%r)' % (cnt, sort)

    def test_todict(self):
        """
        Test the `ipalib.base.NameSpace.__todict__` method.
        """
        for cnt in (3, 101):
            for sort in (True, False):
                (o, members) = self.new(cnt, sort=sort)
                d = o.__todict__()
                assert d == dict((m.name, m) for m in members)

                # Test that a copy is returned:
                assert o.__todict__() is not d
