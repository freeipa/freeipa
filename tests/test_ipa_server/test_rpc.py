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
        (o, api, home) = self.instance('Backend')
        e = raises(errors.CommandError, o.dispatch, 'example', tuple())
        assert str(e) == "Unknown command 'example'"
        assert e.kw['name'] == 'example'
