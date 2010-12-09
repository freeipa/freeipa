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
Test the `ipalib.rpc` module.
"""

import threading
from xmlrpclib import Binary, Fault, dumps, loads, ServerProxy
from tests.util import raises, assert_equal, PluginTester, DummyClass
from tests.data import binary_bytes, utf8_bytes, unicode_str
from ipalib.frontend import Command
from ipalib.request import context, Connection
from ipalib import rpc, errors


std_compound = (binary_bytes, utf8_bytes, unicode_str)


def dump_n_load(value):
    (param, method) = loads(
        dumps((value,), allow_none=True)
    )
    return param[0]


def round_trip(value):
    return rpc.xml_unwrap(
        dump_n_load(rpc.xml_wrap(value))
    )


def test_round_trip():
    """
    Test `ipalib.rpc.xml_wrap` and `ipalib.rpc.xml_unwrap`.

    This tests the two functions together with ``xmlrpclib.dumps()`` and
    ``xmlrpclib.loads()`` in a full wrap/dumps/loads/unwrap round trip.
    """
    # We first test that our assumptions about xmlrpclib module in the Python
    # standard library are correct:
    assert_equal(dump_n_load(utf8_bytes), unicode_str)
    assert_equal(dump_n_load(unicode_str), unicode_str)
    assert_equal(dump_n_load(Binary(binary_bytes)).data, binary_bytes)
    assert isinstance(dump_n_load(Binary(binary_bytes)), Binary)
    assert type(dump_n_load('hello')) is str
    assert type(dump_n_load(u'hello')) is str
    assert_equal(dump_n_load(''), '')
    assert_equal(dump_n_load(u''), '')
    assert dump_n_load(None) is None

    # Now we test our wrap and unwrap methods in combination with dumps, loads:
    # All str should come back str (because they get wrapped in
    # xmlrpclib.Binary().  All unicode should come back unicode because str
    # explicity get decoded by rpc.xml_unwrap() if they weren't already
    # decoded by xmlrpclib.loads().
    assert_equal(round_trip(utf8_bytes), utf8_bytes)
    assert_equal(round_trip(unicode_str), unicode_str)
    assert_equal(round_trip(binary_bytes), binary_bytes)
    assert type(round_trip('hello')) is str
    assert type(round_trip(u'hello')) is unicode
    assert_equal(round_trip(''), '')
    assert_equal(round_trip(u''), u'')
    assert round_trip(None) is None
    compound = [utf8_bytes, None, binary_bytes, (None, unicode_str),
        dict(utf8=utf8_bytes, chars=unicode_str, data=binary_bytes)
    ]
    assert round_trip(compound) == tuple(compound)


def test_xml_wrap():
    """
    Test the `ipalib.rpc.xml_wrap` function.
    """
    f = rpc.xml_wrap
    assert f([]) == tuple()
    assert f({}) == dict()
    b = f('hello')
    assert isinstance(b, Binary)
    assert b.data == 'hello'
    u = f(u'hello')
    assert type(u) is unicode
    assert u == u'hello'
    value = f([dict(one=False, two=u'hello'), None, 'hello'])


def test_xml_unwrap():
    """
    Test the `ipalib.rpc.xml_unwrap` function.
    """
    f = rpc.xml_unwrap
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


def test_xml_dumps():
    """
    Test the `ipalib.rpc.xml_dumps` function.
    """
    f = rpc.xml_dumps
    params = (binary_bytes, utf8_bytes, unicode_str, None)

    # Test serializing an RPC request:
    data = f(params, 'the_method')
    (p, m) = loads(data)
    assert_equal(m, u'the_method')
    assert type(p) is tuple
    assert rpc.xml_unwrap(p) == params

    # Test serializing an RPC response:
    data = f((params,), methodresponse=True)
    (tup, m) = loads(data)
    assert m is None
    assert len(tup) == 1
    assert type(tup) is tuple
    assert rpc.xml_unwrap(tup[0]) == params

    # Test serializing an RPC response containing a Fault:
    fault = Fault(69, unicode_str)
    data = f(fault, methodresponse=True)
    e = raises(Fault, loads, data)
    assert e.faultCode == 69
    assert_equal(e.faultString, unicode_str)


def test_xml_loads():
    """
    Test the `ipalib.rpc.xml_loads` function.
    """
    f = rpc.xml_loads
    params = (binary_bytes, utf8_bytes, unicode_str, None)
    wrapped = rpc.xml_wrap(params)

    # Test un-serializing an RPC request:
    data = dumps(wrapped, 'the_method', allow_none=True)
    (p, m) = f(data)
    assert_equal(m, u'the_method')
    assert_equal(p, params)

    # Test un-serializing an RPC response:
    data = dumps((wrapped,), methodresponse=True, allow_none=True)
    (tup, m) = f(data)
    assert m is None
    assert len(tup) == 1
    assert type(tup) is tuple
    assert_equal(tup[0], params)

    # Test un-serializing an RPC response containing a Fault:
    for error in (unicode_str, u'hello'):
        fault = Fault(69, error)
        data = dumps(fault, methodresponse=True, allow_none=True, encoding='UTF-8')
        e = raises(Fault, f, data)
        assert e.faultCode == 69
        assert_equal(e.faultString, error)
        assert type(e.faultString) is unicode


class test_xmlclient(PluginTester):
    """
    Test the `ipalib.rpc.xmlclient` plugin.
    """
    _plugin = rpc.xmlclient

    def test_forward(self):
        """
        Test the `ipalib.rpc.xmlclient.forward` method.
        """
        class user_add(Command):
            pass

        # Test that ValueError is raised when forwarding a command that is not
        # in api.Command:
        (o, api, home) = self.instance('Backend', in_server=False)
        e = raises(ValueError, o.forward, 'user_add')
        assert str(e) == '%s.forward(): %r not in api.Command' % (
            'xmlclient', 'user_add'
        )

        (o, api, home) = self.instance('Backend', user_add, in_server=False)
        args = (binary_bytes, utf8_bytes, unicode_str)
        kw = dict(one=binary_bytes, two=utf8_bytes, three=unicode_str)
        params = [args, kw]
        result = (unicode_str, binary_bytes, utf8_bytes)
        conn = DummyClass(
            (
                'user_add',
                rpc.xml_wrap(params),
                {},
                rpc.xml_wrap(result),
            ),
            (
                'user_add',
                rpc.xml_wrap(params),
                {},
                Fault(3007, u"'four' is required"),  # RequirementError
            ),
            (
                'user_add',
                rpc.xml_wrap(params),
                {},
                Fault(700, u'no such error'),  # There is no error 700
            ),

        )
        context.xmlclient = Connection(conn, lambda: None)

        # Test with a successful return value:
        assert o.forward('user_add', *args, **kw) == result

        # Test with an errno the client knows:
        e = raises(errors.RequirementError, o.forward, 'user_add', *args, **kw)
        assert_equal(e.args[0], u"'four' is required")

        # Test with an errno the client doesn't know
        e = raises(errors.UnknownError, o.forward, 'user_add', *args, **kw)
        assert_equal(e.code, 700)
        assert_equal(e.error, u'no such error')

        assert context.xmlclient.conn._calledall() is True
