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
Test the `ipaserver.rpc` module.
"""

import json
from io import BytesIO

import pytest


from ipatests.util import assert_equal, raises, PluginTester
from ipalib import errors
from ipaserver import rpcserver

pytestmark = pytest.mark.tier0


class StartResponse:
    def __init__(self):
        self.reset()

    def reset(self):
        self.status = None
        self.headers = None

    def __call__(self, status, headers):
        assert self.status is None
        assert self.headers is None
        assert isinstance(status, str)
        assert isinstance(headers, list)
        self.status = status
        self.headers = headers


def _environ_with_body(body, content_type='application/x-www-form-urlencoded',
                       method='POST', content_length=None):
    if isinstance(body, str):
        body = body.encode('utf-8')
    if content_length is None:
        content_length = len(body)
    return {
        'REQUEST_METHOD': method,
        'CONTENT_TYPE': content_type,
        'CONTENT_LENGTH': str(content_length),
        'QUERY_STRING': '',
        'wsgi.input': BytesIO(body),
    }


def test_request_body_too_large():
    api = 'the api instance'
    f = rpcserver.HTTP_Status(api)
    t = rpcserver._request_body_too_large_template
    s = StartResponse()

    assert_equal(
        f.request_body_too_large(None, s),
        [(t % dict(message='Request body too large')).encode('utf-8')]
    )
    assert s.status == rpcserver.HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE
    assert s.headers == [('Content-Type', 'text/html; charset=utf-8')]


def test_check_request_body_size():
    max_size = 16

    # Within and exact max size are allowed without reading the body
    rpcserver.check_request_body_size(
        {'CONTENT_LENGTH': str(max_size)}, max_size
    )
    rpcserver.check_request_body_size(
        {'CONTENT_LENGTH': str(max_size - 1)}, max_size
    )

    # Oversized Content-Length raises before any body read
    raises(rpcserver.RequestBodyTooLarge,
           rpcserver.check_request_body_size,
           {'CONTENT_LENGTH': str(max_size + 1)}, max_size)

    # Missing, invalid, or negative Content-Length is ignored here
    rpcserver.check_request_body_size({'CONTENT_LENGTH': None}, max_size)
    rpcserver.check_request_body_size(
        {'CONTENT_LENGTH': 'not-a-number'}, max_size
    )
    rpcserver.check_request_body_size({'CONTENT_LENGTH': '-1'}, max_size)


def test_read_input():
    max_size = 16
    body = b'abcdefghijklmnop'

    # Valid body within the limit
    environ = _environ_with_body(body[:8])
    assert_equal(rpcserver.read_input(environ, max_size), 'abcdefgh')

    # Exact max size is allowed
    environ = _environ_with_body(body)
    assert_equal(rpcserver.read_input(environ, max_size), body.decode('utf-8'))

    # Oversized Content-Length raises RequestBodyTooLarge
    environ = _environ_with_body(body + b'x', content_length=max_size + 1)
    raises(rpcserver.RequestBodyTooLarge,
           rpcserver.read_input, environ, max_size)

    # Missing Content-Length returns None (not 413)
    environ = {
        'CONTENT_LENGTH': None,
        'wsgi.input': BytesIO(body),
    }
    assert rpcserver.read_input(environ, max_size) is None

    # Invalid Content-Length returns None
    environ = {
        'CONTENT_LENGTH': 'not-a-number',
        'wsgi.input': BytesIO(body),
    }
    assert rpcserver.read_input(environ, max_size) is None

    # Negative Content-Length returns None
    environ = {
        'CONTENT_LENGTH': '-1',
        'wsgi.input': BytesIO(body),
    }
    assert rpcserver.read_input(environ, max_size) is None


def test_extract_query_request_body_size():
    max_size = 64

    # Oversized POST body propagates RequestBodyTooLarge
    environ = _environ_with_body(
        'a=' + ('x' * max_size), content_length=max_size + 1
    )
    raises(rpcserver.RequestBodyTooLarge,
           rpcserver.extract_query, environ, max_size)

    # Content-Type with charset must still enforce the body size limit
    environ = _environ_with_body(
        'a=' + ('x' * max_size),
        content_type='application/x-www-form-urlencoded; charset=UTF-8',
        content_length=max_size + 1,
    )
    raises(rpcserver.RequestBodyTooLarge,
           rpcserver.extract_query, environ, max_size)

    # Missing Content-Length yields an empty query (not 413)
    environ = _environ_with_body('user=tuser')
    environ['CONTENT_LENGTH'] = None
    assert_equal(rpcserver.extract_query(environ, max_size), {})

    # Exact max size does not raise RequestBodyTooLarge
    environ = _environ_with_body('x' * max_size)
    try:
        rpcserver.extract_query(environ, max_size)
    except rpcserver.RequestBodyTooLarge:
        raise AssertionError(
            'exact max-size body raised RequestBodyTooLarge'
        )


def test_not_found():
    api = 'the api instance'
    f = rpcserver.HTTP_Status(api)
    t = rpcserver._not_found_template
    s = StartResponse()

    # Test with an innocent URL:
    url = '/ipa/foo/stuff'
    assert_equal(
        f.not_found(None, s, url, None),
        [(t % dict(url='/ipa/foo/stuff')).encode('utf-8')]
    )
    assert s.status == '404 Not Found'
    assert s.headers == [('Content-Type', 'text/html; charset=utf-8')]

    # Test when URL contains any of '<>&'
    s.reset()
    url ='&nbsp;' + '<script>do_bad_stuff();</script>'
    assert_equal(
        f.not_found(None, s, url, None),
        [(t % dict(
            url='&amp;nbsp;&lt;script&gt;do_bad_stuff();&lt;/script&gt;')
        ).encode('utf-8')]
    )
    assert s.status == '404 Not Found'
    assert s.headers == [('Content-Type', 'text/html; charset=utf-8')]


def test_bad_request():
    api = 'the api instance'
    f = rpcserver.HTTP_Status(api)
    t = rpcserver._bad_request_template
    s = StartResponse()

    assert_equal(
        f.bad_request(None, s, 'illegal request'),
        [(t % dict(message='illegal request')).encode('utf-8')]
    )
    assert s.status == '400 Bad Request'
    assert s.headers == [('Content-Type', 'text/html; charset=utf-8')]


def test_internal_error():
    api = 'the api instance'
    f = rpcserver.HTTP_Status(api)
    t = rpcserver._internal_error_template
    s = StartResponse()

    assert_equal(
        f.internal_error(None, s, 'request failed'),
        [(t % dict(message='request failed')).encode('utf-8')]
    )
    assert s.status == '500 Internal Server Error'
    assert s.headers == [('Content-Type', 'text/html; charset=utf-8')]


def test_unauthorized_error():
    api = 'the api instance'
    f = rpcserver.HTTP_Status(api)
    t = rpcserver._unauthorized_template
    s = StartResponse()

    assert_equal(
        f.unauthorized(None, s, 'unauthorized', 'password-expired'),
        [(t % dict(message='unauthorized')).encode('utf-8')]
    )
    assert s.status == '401 Unauthorized'
    assert s.headers == [('Content-Type', 'text/html; charset=utf-8'),
                         ('X-IPA-Rejection-Reason', 'password-expired')]


def test_params_2_args_options():
    """
    Test the `ipaserver.rpcserver.params_2_args_options` function.
    """
    f = rpcserver.params_2_args_options
    args = ('Hello', 'world!')
    options = dict(one=1, two='Two', three='Three')
    assert f(tuple()) == (tuple(), dict())
    assert f([args]) == (args, dict())
    assert f([args, options]) == (args, options)


class test_session:
    klass = rpcserver.wsgi_dispatch

    def test_route(self):
        def app1(environ, start_response):
            return (
                'from 1',
                [environ[k] for k in ('SCRIPT_NAME', 'PATH_INFO')]
            )

        def app2(environ, start_response):
            return (
                'from 2',
                [environ[k] for k in ('SCRIPT_NAME', 'PATH_INFO')]
            )

        api = 'the api instance'
        inst = self.klass(api)
        inst.mount(app1, '/foo/stuff')
        inst.mount(app2, '/bar')

        d = dict(SCRIPT_NAME='/ipa', PATH_INFO='/foo/stuff')
        assert inst.route(d, None) == ('from 1', ['/ipa', '/foo/stuff'])

        d = dict(SCRIPT_NAME='/ipa', PATH_INFO='/bar')
        assert inst.route(d, None) == ('from 2', ['/ipa', '/bar'])

    def test_mount(self):
        def app1(environ, start_response):
            pass

        def app2(environ, start_response):
            pass

        # Test that mount works:
        api = 'the api instance'
        inst = self.klass(api)
        inst.mount(app1, 'foo')
        assert inst['foo'] is app1
        assert list(inst) == ['foo']

        # Test that Exception is raise if trying override a mount:
        e = raises(Exception, inst.mount, app2, 'foo')
        assert str(e) == '%s.mount(): cannot replace %r with %r at %r' % (
            'wsgi_dispatch', app1, app2, 'foo'
        )

        # Test mounting a second app:
        inst.mount(app2, 'bar')
        assert inst['bar'] is app2
        assert list(inst) == ['bar', 'foo']


class test_xmlserver(PluginTester):
    """
    Test the `ipaserver.rpcserver.xmlserver` plugin.
    """

    _plugin = rpcserver.xmlserver

    def test_marshaled_dispatch(self): # FIXME
        self.instance('Backend', in_server=True)


class test_jsonserver(PluginTester):
    """
    Test the `ipaserver.rpcserver.jsonserver` plugin.
    """

    _plugin = rpcserver.jsonserver

    def test_unmarshal(self):
        """
        Test the `ipaserver.rpcserver.jsonserver.unmarshal` method.
        """
        o, _api, _home = self.instance('Backend', in_server=True)

        # Test with invalid JSON-data:
        e = raises(errors.JSONError, o.unmarshal, 'this wont work')
        assert str(e.error).startswith('Expecting value: ')

        # Test with non-dict type:
        e = raises(errors.JSONError, o.unmarshal, json.dumps([1, 2, 3]))
        assert str(e.error) == 'Request must be a dict'

        params = [[1, 2], dict(three=3, four=4)]
        # Test with missing method:
        d = dict(params=params, id=18)
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert str(e.error) == 'Request is missing "method"'

        # Test with missing params:
        d = dict(method='echo', id=18)
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert str(e.error) == 'Request is missing "params"'

        # Test with non-list params:
        for p in ('hello', dict(args=tuple(), options=dict())):
            d = dict(method='echo', id=18, params=p)
            e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
            assert str(e.error) == 'params must be a list'

        # Test with other than 2 params:
        for p in ([], [tuple()], [None, dict(), tuple()]):
            d = dict(method='echo', id=18, params=p)
            e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
            assert str(e.error) == 'params must contain [args, options]'

        # Test when args is not a list:
        d = dict(method='echo', id=18, params=['args', dict()])
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert str(e.error) == 'params[0] (aka args) must be a list'

        # Test when options is not a dict:
        d = dict(method='echo', id=18, params=[('hello', 'world'), 'options'])
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert str(e.error) == 'params[1] (aka options) must be a dict'

        # Test with valid values:
        args = ['jdoe']
        options = dict(givenname='John', sn='Doe')
        d = dict(method='user_add', params=(args, options), id=18)
        assert o.unmarshal(json.dumps(d)) == ('user_add', args, options, 18)
