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
Test the `ipalib.util` module.
"""

from xmlrpclib import Binary
from tests.util import raises
from ipalib import util


def test_xmlrpc_marshal():
    """
    Test the `ipalib.util.xmlrpc_marshal` function.
    """
    f = util.xmlrpc_marshal
    assert f() == ({},)
    assert f('one', 'two') == ({}, 'one', 'two')
    assert f(one=1, two=2) == (dict(one=1, two=2),)
    assert f('one', 'two', three=3, four=4) == \
        (dict(three=3, four=4), 'one', 'two')


def test_xmlrpc_unmarshal():
    """
    Test the `ipalib.util.xmlrpc_unmarshal` function.
    """
    f = util.xmlrpc_unmarshal
    assert f() == (tuple(), {})
    assert f({}, 'one', 'two') == (('one', 'two'), {})
    assert f(dict(one=1, two=2)) == (tuple(), dict(one=1, two=2))
    assert f(dict(three=3, four=4), 'one', 'two') == \
        (('one', 'two'), dict(three=3, four=4))


def test_xmlrpc_wrap():
    """
    Test the `ipalib.util.xmlrpc_wrap` function.
    """
    f = util.xmlrpc_wrap
    assert f([]) == tuple()
    assert f({}) == dict()
    b = f('hello')
    assert isinstance(b, Binary)
    assert b.data == 'hello'
    u = f(u'hello')
    assert type(u) is unicode
    assert u == u'hello'
    value = f([dict(one=False, two=u'hello'), None, 'hello'])


def test_xmlrpc_unwrap():
    """
    Test the `ipalib.util.xmlrpc_unwrap` function.
    """
    f = util.xmlrpc_unwrap
    assert f([]) == tuple()
    assert f({}) == dict()
    utf8_bytes = '\xd0\x9f\xd0\xb0\xd0\xb2\xd0\xb5\xd0\xbb'
    unicode_chars = u'\u041f\u0430\u0432\u0435\u043b'
    value = f(Binary(utf8_bytes))
    assert type(value) is str
    assert value == utf8_bytes
    value = f(utf8_bytes)
    assert type(value) is unicode
    assert value == unicode_chars
    value = f([True, Binary('hello'), dict(one=1, two=utf8_bytes, three=None)])
    assert value == (True, 'hello', dict(one=1, two=unicode_chars, three=None))
    assert type(value[1]) is str
    assert type(value[2]['two']) is unicode


def test_make_repr():
    """
    Test the `ipalib.util.make_repr` function.
    """
    f = util.make_repr
    assert f('my') == 'my()'
    assert f('my', True, u'hello') == "my(True, u'hello')"
    assert f('my', one=1, two='two') == "my(one=1, two='two')"
    assert f('my', None, 3, dog='animal', apple='fruit') == \
        "my(None, 3, apple='fruit', dog='animal')"
