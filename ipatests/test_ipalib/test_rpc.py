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
from __future__ import print_function

import unittest

import pytest
import six
# pylint: disable=import-error
from six.moves.xmlrpc_client import Binary, Fault, dumps, loads
# pylint: enable=import-error
from six.moves import urllib

from ipatests.util import raises, assert_equal, PluginTester, DummyClass
from ipatests.util import Fuzzy
from ipatests.data import binary_bytes, utf8_bytes, unicode_str
from ipalib.frontend import Command
from ipalib.request import context, Connection
from ipalib import rpc, errors, api, request
from ipapython.version import API_VERSION

if six.PY3:
    unicode = str


std_compound = (binary_bytes, utf8_bytes, unicode_str)


def dump_n_load(value):
    param, _method = loads(
        dumps((value,), allow_none=True)
    )
    return param[0]


def round_trip(value):
    return rpc.xml_unwrap(
        dump_n_load(rpc.xml_wrap(value, API_VERSION))
    )


def test_round_trip():
    """
    Test `ipalib.rpc.xml_wrap` and `ipalib.rpc.xml_unwrap`.

    This tests the two functions together with ``xmlrpc.client.dumps()`` and
    ``xmlrpc.client.loads()`` in a full wrap/dumps/loads/unwrap round trip.
    """
    # We first test that our assumptions about xmlrpc.client module in the Python
    # standard library are correct:
    if six.PY2:
        output_binary_type = bytes
    else:
        output_binary_type = Binary

    if six.PY2:
        assert_equal(dump_n_load(utf8_bytes), unicode_str)
    assert_equal(dump_n_load(unicode_str), unicode_str)
    # "Binary" is not "str". pylint: disable=no-member
    assert_equal(dump_n_load(Binary(binary_bytes)).data, binary_bytes)
    assert isinstance(dump_n_load(Binary(binary_bytes)), Binary)
    assert type(dump_n_load(b'hello')) is output_binary_type
    assert type(dump_n_load(u'hello')) is str
    assert_equal(dump_n_load(b''), output_binary_type(b''))
    assert_equal(dump_n_load(u''), str())
    assert dump_n_load(None) is None

    # Now we test our wrap and unwrap methods in combination with dumps, loads:
    # All bytes should come back bytes (because they get wrapped in
    # xmlrpc.client.Binary().  All unicode should come back unicode because str
    # explicity get decoded by rpc.xml_unwrap() if they weren't already
    # decoded by xmlrpc.client.loads().
    assert_equal(round_trip(utf8_bytes), utf8_bytes)
    assert_equal(round_trip(unicode_str), unicode_str)
    assert_equal(round_trip(binary_bytes), binary_bytes)
    assert type(round_trip(b'hello')) is bytes
    assert type(round_trip(u'hello')) is unicode
    assert_equal(round_trip(b''), b'')
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
    assert f([], API_VERSION) == tuple()
    assert f({}, API_VERSION) == dict()
    b = f(b'hello', API_VERSION)
    assert isinstance(b, Binary)
    # "Binary" is not "dict" or "tuple". pylint: disable=no-member
    assert b.data == b'hello'
    u = f(u'hello', API_VERSION)
    assert type(u) is unicode
    assert u == u'hello'
    f([dict(one=False, two=u'hello'), None, b'hello'], API_VERSION)


def test_xml_unwrap():
    """
    Test the `ipalib.rpc.xml_unwrap` function.
    """
    f = rpc.xml_unwrap
    assert f([]) == tuple()
    assert f({}) == dict()
    value = f(Binary(utf8_bytes))
    assert type(value) is bytes
    assert value == utf8_bytes
    assert f(utf8_bytes) == unicode_str
    assert f(unicode_str) == unicode_str
    value = f([True, Binary(b'hello'), dict(one=1, two=utf8_bytes, three=None)])
    assert value == (True, b'hello', dict(one=1, two=unicode_str, three=None))
    assert type(value[1]) is bytes
    assert type(value[2]['two']) is unicode


def test_xml_dumps():
    """
    Test the `ipalib.rpc.xml_dumps` function.
    """
    f = rpc.xml_dumps
    params = (binary_bytes, utf8_bytes, unicode_str, None)

    # Test serializing an RPC request:
    data = f(params, API_VERSION, 'the_method')
    (p, m) = loads(data)
    assert_equal(m, u'the_method')
    assert type(p) is tuple
    assert rpc.xml_unwrap(p) == params

    # Test serializing an RPC response:
    data = f((params,), API_VERSION, methodresponse=True)
    (tup, m) = loads(data)
    assert m is None
    assert len(tup) == 1
    assert type(tup) is tuple
    assert rpc.xml_unwrap(tup[0]) == params

    # Test serializing an RPC response containing a Fault:
    fault = Fault(69, unicode_str)
    data = f(fault, API_VERSION, methodresponse=True)
    e = raises(Fault, loads, data)
    assert e.faultCode == 69
    assert_equal(e.faultString, unicode_str)


def test_xml_loads():
    """
    Test the `ipalib.rpc.xml_loads` function.
    """
    f = rpc.xml_loads
    params = (binary_bytes, utf8_bytes, unicode_str, None)
    wrapped = rpc.xml_wrap(params, API_VERSION)

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

        o, _api, _home = self.instance('Backend', user_add, in_server=False)
        args = (binary_bytes, utf8_bytes, unicode_str)
        kw = dict(one=binary_bytes, two=utf8_bytes, three=unicode_str)
        params = [args, kw]
        result = (unicode_str, binary_bytes, utf8_bytes)
        conn = DummyClass(
            (
                'user_add',
                rpc.xml_wrap(params, API_VERSION),
                {},
                rpc.xml_wrap(result, API_VERSION),
            ),
            (
                'user_add',
                rpc.xml_wrap(params, API_VERSION),
                {},
                Fault(3007, u"'four' is required"),  # RequirementError
            ),
            (
                'user_add',
                rpc.xml_wrap(params, API_VERSION),
                {},
                Fault(700, u'no such error'),  # There is no error 700
            ),

        )

        # Create connection for the current thread
        setattr(context, o.id, Connection(conn, lambda: None))
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


@pytest.mark.skip_ipaclient_unittest
@pytest.mark.needs_ipaapi
class test_xml_introspection(object):
    @classmethod
    def setup_class(cls):
        try:
            api.Backend.xmlclient.connect()
        except (errors.NetworkError, IOError):
            raise unittest.SkipTest('%r: Server not available: %r' %
                                (__name__, api.env.xmlrpc_uri))

    @classmethod
    def teardown_class(cls):
        request.destroy_context()

    def test_list_methods(self):
        result = api.Backend.xmlclient.conn.system.listMethods()
        assert len(result)
        assert 'ping' in result
        assert 'user_add' in result
        assert 'system.listMethods' in result
        assert 'system.methodSignature' in result
        assert 'system.methodHelp' in result

    def test_list_methods_many_params(self):
        try:
            api.Backend.xmlclient.conn.system.listMethods('foo')
        except Fault as f:
            print(f)
            assert f.faultCode == 3003
            assert f.faultString == (
                "command 'system.listMethods' takes no arguments")
        else:
            raise AssertionError('did not raise')

    def test_ping_signature(self):
        result = api.Backend.xmlclient.conn.system.methodSignature('ping')
        assert result == [['struct', 'array', 'struct']]


    def test_ping_help(self):
        result = api.Backend.xmlclient.conn.system.methodHelp('ping')
        assert result == 'Ping a remote server.'

    def test_signature_no_params(self):
        try:
            api.Backend.xmlclient.conn.system.methodSignature()
        except Fault as f:
            print(f)
            assert f.faultCode == 3007
            assert f.faultString == "'method name' is required"
        else:
            raise AssertionError('did not raise')

    def test_signature_many_params(self):
        try:
            api.Backend.xmlclient.conn.system.methodSignature('a', 'b')
        except Fault as f:
            print(f)
            assert f.faultCode == 3004
            assert f.faultString == (
                "command 'system.methodSignature' takes at most 1 argument")
        else:
            raise AssertionError('did not raise')

    def test_help_no_params(self):
        try:
            api.Backend.xmlclient.conn.system.methodHelp()
        except Fault as f:
            print(f)
            assert f.faultCode == 3007
            assert f.faultString == "'method name' is required"
        else:
            raise AssertionError('did not raise')

    def test_help_many_params(self):
        try:
            api.Backend.xmlclient.conn.system.methodHelp('a', 'b')
        except Fault as f:
            print(f)
            assert f.faultCode == 3004
            assert f.faultString == (
                "command 'system.methodHelp' takes at most 1 argument")
        else:
            raise AssertionError('did not raise')


@pytest.mark.skip_ipaclient_unittest
@pytest.mark.needs_ipaapi
class test_rpcclient_context(PluginTester):
    """
    Test the context in `ipalib.rpc.rpcclient` plugin.
    """
    def setup(self):
        try:
            api.Backend.rpcclient.connect(ca_certfile='foo')
        except (errors.NetworkError, IOError):
            raise unittest.SkipTest('%r: Server not available: %r' %
                                (__name__, api.env.xmlrpc_uri))

    def teardown(self):
        if api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.disconnect()

    def test_context_cafile(self):
        """
        Test that ca_certfile is set in `ipalib.rpc.rpcclient.connect`
        """
        ca_certfile = getattr(context, 'ca_certfile', None)
        assert_equal(ca_certfile, 'foo')

    def test_context_principal(self):
        """
        Test that principal is set in `ipalib.rpc.rpcclient.connect`
        """
        principal = getattr(context, 'principal', None)
        assert_equal(principal, 'admin@%s' % api.env.realm)

    def test_context_request_url(self):
        """
        Test that request_url is set in `ipalib.rpc.rpcclient.connect`
        """
        request_url = getattr(context, 'request_url', None)
        assert_equal(request_url, 'https://%s/ipa/session/json' % api.env.host)

    def test_context_session_cookie(self):
        """
        Test that session_cookie is set in `ipalib.rpc.rpcclient.connect`
        """
        fuzzy_cookie = Fuzzy(
            r'^ipa_session=MagBearerToken=[A-Za-z0-9+\/]+=*;$')

        session_cookie = getattr(context, 'session_cookie', None)
        # pylint-2 is incorrectly spewing Too many positional arguments
        # pylint: disable=E1121
        unquoted = urllib.parse.unquote(session_cookie)
        assert(unquoted == fuzzy_cookie)
