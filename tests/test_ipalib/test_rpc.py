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
import struct
from tests.util import raises
from ipalib import rpc

# FIXME: These constants should be imported from tests.data

# A string that should have bytes 'x\00' through '\xff':
BINARY_BYTES = ''.join(struct.pack('B', d) for d in xrange(256))
assert '\x00' in BINARY_BYTES and '\xff' in BINARY_BYTES
assert type(BINARY_BYTES) is str and len(BINARY_BYTES) == 256

# A UTF-8 encoded str:
UTF8_BYTES = '\xd0\x9f\xd0\xb0\xd0\xb2\xd0\xb5\xd0\xbb'

# The same UTF-8 data decoded (a unicode instance):
UNICODE_CHARS = u'\u041f\u0430\u0432\u0435\u043b'
assert UTF8_BYTES.decode('UTF-8') == UNICODE_CHARS
assert UNICODE_CHARS.encode('UTF-8') == UTF8_BYTES



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
    assert dump_n_load(UTF8_BYTES) == UNICODE_CHARS
    assert dump_n_load(UNICODE_CHARS) == UNICODE_CHARS
    assert dump_n_load(Binary(BINARY_BYTES)).data == BINARY_BYTES
    assert isinstance(dump_n_load(Binary(BINARY_BYTES)), Binary)
    assert type(dump_n_load('hello')) is str
    assert type(dump_n_load(u'hello')) is str

    # Now we test our wrap and unwrap methods in combination with dumps, loads:
    # All str should come back str (because they get wrapped in
    # xmlrpclib.Binary().  All unicode should come back unicode because str
    # explicity get decoded by rpc.xmlrpc_unwrap() if they weren't already
    # decoded by xmlrpclib.loads().
    assert round_trip(UTF8_BYTES) == UTF8_BYTES
    assert round_trip(UNICODE_CHARS) == UNICODE_CHARS
    assert round_trip(BINARY_BYTES) == BINARY_BYTES
    assert type(round_trip('hello')) is str
    assert type(round_trip(u'hello')) is unicode
    assert round_trip('') == ''
    assert round_trip(u'') == u''
    compound = [UTF8_BYTES, UNICODE_CHARS, BINARY_BYTES,
        dict(utf8=UTF8_BYTES, chars=UNICODE_CHARS, data=BINARY_BYTES)
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
    value = f(Binary(UTF8_BYTES))
    assert type(value) is str
    assert value == UTF8_BYTES
    assert f(UTF8_BYTES) == UNICODE_CHARS
    assert f(UNICODE_CHARS) == UNICODE_CHARS
    value = f([True, Binary('hello'), dict(one=1, two=UTF8_BYTES, three=None)])
    assert value == (True, 'hello', dict(one=1, two=UNICODE_CHARS, three=None))
    assert type(value[1]) is str
    assert type(value[2]['two']) is unicode
