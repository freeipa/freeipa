# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Base class for all cmdline tests
"""

import nose
import ldap
import krbV
from ipalib import api, request
from ipalib import errors
from tests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipaserver.plugins.ldap2 import ldap2
from ipapython import ipautil

# See if our LDAP server is up and we can talk to it over GSSAPI
ccache = krbV.default_context().default_ccache().name

try:
    conn = ldap2(shared_instance=False, ldap_uri=api.env.ldap_uri, base_dn=api.env.basedn)
    conn.connect(ccache=ccache)
    conn.disconnect()
    server_available = True
except errors.DatabaseError:
    server_available = False
except Exception, e:
    server_available = False

class cmdline_test(XMLRPC_test):
    """
    Base class for all command-line tests
    """
    # some reasonable default command
    command = '/bin/ls'

    def setUp(self):
        # raise an error if the command is missing even if the remote
        # server is not available.
        if not ipautil.file_exists(self.command):
            raise AssertionError(
                'Command %r not available' % self.command
            )
        super(cmdline_test, self).setUp()
        if not server_available:
            raise nose.SkipTest(
                'Server not available: %r' % api.env.xmlrpc_uri
            )

    def tearDown(self):
        """
        nose tear-down fixture.
        """
        super(cmdline_test, self).tearDown()
