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
Test the `ipaserver.rpc` module.
"""

from tests.util import create_test_api, assert_equal, raises, PluginTester
from tests.data import unicode_str
from ipalib import errors, Command
from ipaserver import rpcserver
from ipalib.compat import json


class StartResponse(object):
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
    f = rpcserver.not_found
    t = rpcserver._not_found_template
    s = StartResponse()

    # Test with an innocent URL:
    d = dict(SCRIPT_NAME='/ipa', PATH_INFO='/foo/stuff')
    assert_equal(
        f(d, s),
        [t % dict(url='/ipa/foo/stuff')]
    )
    assert s.status == '404 Not Found'
    assert s.headers == [('Content-Type', 'text/html')]

    # Test when URL contains any of '<>&'
    s.reset()
    d = dict(SCRIPT_NAME='&nbsp;', PATH_INFO='<script>do_bad_stuff();</script>')
    assert_equal(
        f(d, s),
        [t % dict(url='&amp;nbsp;&lt;script&gt;do_bad_stuff();&lt;/script&gt;')]
    )
    assert s.status == '404 Not Found'
    assert s.headers == [('Content-Type', 'text/html')]



def test_params_2_args_options():
    """
    Test the `ipaserver.rpcserver.params_2_args_options` function.
    """
    f = rpcserver.params_2_args_options
    args = ('Hello', u'world!')
    options = dict(one=1, two=u'Two', three='Three')
    assert f(tuple()) == (tuple(), dict())
    assert f(args) == (args, dict())
    assert f((options,)) == (tuple(), options)
    assert f(args + (options,)) == (args, options)
    assert f((options,) + args) == ((options,) + args, dict())


class test_session(object):
    klass = rpcserver.session

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

        inst = self.klass()
        inst.mount(app1, 'foo')
        inst.mount(app2, 'bar')

        d = dict(SCRIPT_NAME='/ipa', PATH_INFO='/foo/stuff')
        assert inst.route(d, None) == ('from 1', ['/ipa/foo', '/stuff'])

        d = dict(SCRIPT_NAME='/ipa', PATH_INFO='/bar')
        assert inst.route(d, None) == ('from 2', ['/ipa/bar', ''])

    def test_mount(self):
        def app1(environ, start_response):
            pass

        def app2(environ, start_response):
            pass

        # Test that mount works:
        inst = self.klass()
        inst.mount(app1, 'foo')
        assert inst['foo'] is app1
        assert list(inst) == ['foo']

        # Test that StandardError is raise if trying override a mount:
        e = raises(StandardError, inst.mount, app2, 'foo')
        assert str(e) == '%s.mount(): cannot replace %r with %r at %r' % (
            'session', app1, app2, 'foo'
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

    def test_marshaled_dispatch(self):
        (o, api, home) = self.instance('Backend', in_server=True)


class test_jsonserver(PluginTester):
    """
    Test the `ipaserver.rpcserver.jsonserver` plugin.
    """

    _plugin = rpcserver.jsonserver

    def test_unmarshal(self):
        """
        Test the `ipaserver.rpcserver.jsonserver.unmarshal` method.
        """
        (o, api, home) = self.instance('Backend', in_server=True)

        # Test with invalid JSON-data:
        e = raises(errors.JSONError, o.unmarshal, 'this wont work')
        assert isinstance(e.error, ValueError)
        assert str(e.error) == 'No JSON object could be decoded'

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
        args = [u'jdoe']
        options = dict(givenname=u'John', sn='Doe')
        d = dict(method=u'user_add', params=[args, options], id=18)
        assert o.unmarshal(json.dumps(d)) == (u'user_add', args, options, 18)
