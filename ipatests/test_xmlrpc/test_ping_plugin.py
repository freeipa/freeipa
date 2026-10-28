# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#   Peter Lacko   <placko@redhat.com>
#
# Copyright (C) 2012, 2016  Red Hat
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
Test the `ipaserver/plugins/ping.py` module, and XML-RPC in general.
"""

import pytest

from ipalib import errors, _
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.util import assert_equal, Fuzzy


@pytest.mark.tier1
class TestPing(XMLRPC_test):
    """Test functionality of the `ipalib/plugins/ping.py` module."""
    tracker = Tracker()

    def test_ping(self):
        """Ping the server."""
        result = self.tracker.run_command('ping')
        exp = {'summary': Fuzzy('IPA server version .*. API version .*')}
        assert_equal(result, exp)

    def test_ping_with_argument(self):
        """Try to ping with an argument."""
        with raises_exact(errors.ZeroArgumentError(name='ping')):
            self.tracker.run_command('ping', ['argument'])

    def test_ping_with_option(self):
        """Try to ping with an option."""
        with raises_exact(errors.OptionError(
                _('Unknown option: %(option)s'), option='bad_arg')):
            self.tracker.run_command('ping', bad_arg=True)
