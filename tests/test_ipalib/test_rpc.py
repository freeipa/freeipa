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
Test the `ipalib.rpc` module.
"""

from xmlrpclib import Binary, dumps, loads
from tests.util import raises
from tests.data import binary_bytes, utf8_bytes, unicode_str
from ipalib import rpc


def dump_n_load(value):
    (param, method) = loads(
        dumps((value,))
    )
    return param[0]


def round_trip(value):
    return rpc.xmlrpc_unwrap(
        dump_n_load(rpc.xmlrpc_wrap(value))
    )


def test_round_trip():
    """
    Test `ipalib.rpc.xmlrpc_wrap` and `ipalib.rpc.xmlrpc_unwrap`.

    This tests the two functions together with ``xmlrpclib.dumps()`` and
    ``xmlrpclib.loads()`` in a full wrap/dumps/loads/unwrap round trip.
    """
    # We first test that our assumptions about xmlrpclib module in the Python
    # standard library are correct:
    assert dump_n_load(utf8_bytes) == unicode_str
    assert dump_n_load(unicode_str) == unicode_str
    assert dump_n_load(Binary(binary_bytes)).data == binary_bytes
    assert isinstance(dump_n_load(Binary(binary_bytes)), Binary)
    assert type(dump_n_load('hello')) is str
    assert type(dump_n_load(u'hello')) is str

    # Now we test our wrap and unwrap methods in combination with dumps, loads:
    # All str should come back str (because they get wrapped in
    # xmlrpclib.Binary().  All unicode should come back unicode because str
    # explicity get decoded by rpc.xmlrpc_unwrap() if they weren't already
    # decoded by xmlrpclib.loads().
    assert round_trip(utf8_bytes) == utf8_bytes
    assert round_trip(unicode_str) == unicode_str
    assert round_trip(binary_bytes) == binary_bytes
    assert type(round_trip('hello')) is str
    assert type(round_trip(u'hello')) is unicode
    assert round_trip('') == ''
    assert round_trip(u'') == u''
    compound = [utf8_bytes, unicode_str, binary_bytes,
        dict(utf8=utf8_bytes, chars=unicode_str, data=binary_bytes)
    ]
    assert round_trip(compound) == tuple(compound)


def test_xmlrpc_wrap():
    """
    Test the `ipalib.rpc.xmlrpc_wrap` function.
    """
    f = rpc.xmlrpc_wrap
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
    Test the `ipalib.rpc.xmlrpc_unwrap` function.
    """
    f = rpc.xmlrpc_unwrap
    assert f([]) == tuple()
    assert f({}) == dict()
    value = f(Binary(utf8_bytes))
    assert type(value) is str
    assert value == utf8_bytes
    assert f(utf8_bytes) == unicode_str
    assert f(unicode_str) == unicode_str
    value = f([True, Binary('hello'), dict(one=1, two=utf8_bytes, three=None)])
    assert value == (True, 'hello', dict(one=1, two=unicode_str, three=None))
    assert type(value[1]) is str
    assert type(value[2]['two']) is unicode
