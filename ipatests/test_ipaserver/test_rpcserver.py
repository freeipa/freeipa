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
import pytest

import six

from ipatests.util import assert_equal, raises, PluginTester
from ipalib import errors
from ipaserver import rpcserver

if six.PY3:
    unicode = str

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
    args = ('Hello', u'world!')
    options = dict(one=1, two=u'Two', three='Three')
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
        if six.PY2:
            assert unicode(e.error) == 'No JSON object could be decoded'
        else:
            assert str(e.error).startswith('Expecting value: ')

        # Test with non-dict type:
        e = raises(errors.JSONError, o.unmarshal, json.dumps([1, 2, 3]))
        assert unicode(e.error) == 'Request must be a dict'

        params = [[1, 2], dict(three=3, four=4)]
        # Test with missing method:
        d = dict(params=params, id=18)
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert unicode(e.error) == 'Request is missing "method"'

        # Test with missing params:
        d = dict(method='echo', id=18)
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert unicode(e.error) == 'Request is missing "params"'

        # Test with non-list params:
        for p in ('hello', dict(args=tuple(), options=dict())):
            d = dict(method='echo', id=18, params=p)
            e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
            assert unicode(e.error) == 'params must be a list'

        # Test with other than 2 params:
        for p in ([], [tuple()], [None, dict(), tuple()]):
            d = dict(method='echo', id=18, params=p)
            e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
            assert unicode(e.error) == 'params must contain [args, options]'

        # Test when args is not a list:
        d = dict(method='echo', id=18, params=['args', dict()])
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert unicode(e.error) == 'params[0] (aka args) must be a list'

        # Test when options is not a dict:
        d = dict(method='echo', id=18, params=[('hello', 'world'), 'options'])
        e = raises(errors.JSONError, o.unmarshal, json.dumps(d))
        assert unicode(e.error) == 'params[1] (aka options) must be a dict'

        # Test with valid values:
        args = [u'jdoe']
        options = dict(givenname=u'John', sn='Doe')
        d = dict(method=u'user_add', params=(args, options), id=18)
        assert o.unmarshal(json.dumps(d)) == (u'user_add', args, options, 18)
