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
Test the `ipa_server.rpc` module.
"""

from tests.util import create_test_api, raises, PluginTester
from tests.data import unicode_str
from ipalib import errors, Command
from ipa_server import rpc


def test_params_2_args_options():
    """
    Test the `ipa_server.rpc.params_2_args_options` function.
    """
    f = rpc.params_2_args_options
    args = ('Hello', u'world!')
    options = dict(one=1, two=u'Two', three='Three')
    assert f(tuple()) == (tuple(), dict())
    assert f(args) == (args, dict())
    assert f((options,)) == (tuple(), options)
    assert f(args + (options,)) == (args, options)
    assert f((options,) + args) == ((options,) + args, dict())


class test_xmlrpc(PluginTester):
    """
    Test the `ipa_server.rpc.xmlrpc` plugin.
    """

    _plugin = rpc.xmlrpc

    def test_dispatch(self):
        """
        Test the `ipa_server.rpc.xmlrpc.dispatch` method.
        """
        (o, api, home) = self.instance('Backend', in_server=True)
        e = raises(errors.CommandError, o.dispatch, 'echo', tuple())
        assert str(e) == "Unknown command 'echo'"
        assert e.kw['name'] == 'echo'

        class echo(Command):
            takes_args = ['arg1', 'arg2+']
            takes_options = ['option1?', 'option2?']
            def execute(self, *args, **options):
                assert type(args[1]) is tuple
                return args + (options,)

        (o, api, home) = self.instance('Backend', echo, in_server=True)
        def call(params):
            response = o.dispatch('echo', params)
            assert type(response) is tuple and len(response) == 1
            return response[0]
        arg1 = unicode_str
        arg2 = (u'Hello', unicode_str, u'world!')
        options = dict(option1=u'How are you?', option2=unicode_str)
        assert call((arg1, arg2, options)) == (arg1, arg2, options)
        assert call((arg1,) + arg2 + (options,)) == (arg1, arg2, options)
