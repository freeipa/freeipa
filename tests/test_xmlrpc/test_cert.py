# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipalib/plugins/cert.py` module against the selfsign plugin.
"""

import sys
import os
import shutil
from nose.tools import assert_raises  # pylint: disable=E0611

from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors
from ipalib import x509
import tempfile
from ipapython import ipautil
import nose
import base64
from ipapython.dn import DN

# So we can save the cert from issuance and compare it later
cert = None
newcert = None

# Test setup
#
# This test needs a configured CA behind it in order to work properly
# It currently specifically tests for a self-signed CA but there is no
# reason the test wouldn't work with a dogtag CA as well with some
# additional work. This will change when selfsign is no longer the default CA.
#
# To set it up grab the 3 NSS db files from a self-signed CA from
# /etc/httpd/alias to ~/.ipa/alias. Copy /etc/httpd/alias/pwdfile.txt to
# ~/.ipa/alias/.pwd. Change ownership of these files too. That should do it.

class test_cert(XMLRPC_test):

    def run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.reqdir]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

    def setUp(self):
        if 'cert_request' not in api.Command:
            raise nose.SkipTest('cert_request not registered')
        if not ipautil.file_exists(api.env.dot_ipa + os.sep + 'alias' + os.sep + '.pwd'):
            raise nose.SkipTest('developer self-signed CA not configured')
        super(test_cert, self).setUp()
        self.reqdir = tempfile.mkdtemp(prefix = "tmp-")
        self.reqfile = self.reqdir + "/test.csr"
        self.pwname = self.reqdir + "/pwd"

        # Create an empty password file
        fp = open(self.pwname, "w")
        fp.write("\n")
        fp.close()

        # Create our temporary NSS database
        self.run_certutil(["-N", "-f", self.pwname])

        self.subject = DN(('CN', self.host_fqdn), x509.subject_base())

    def tearDown(self):
        super(test_cert, self).tearDown()
        shutil.rmtree(self.reqdir, ignore_errors=True)

    def generateCSR(self, subject):
        self.run_certutil(["-R", "-s", subject,
                           "-o", self.reqfile,
                           "-z", "/etc/group",
                           "-f", self.pwname,
                           "-a",
                           ])
        fp = open(self.reqfile, "r")
        data = fp.read()
        fp.close()
        return data

    """
    Test the `cert` plugin.
    """
    host_fqdn = u'ipatestcert.%s' % api.env.domain
    service_princ = u'test/%s@%s' % (host_fqdn, api.env.realm)

    def test_1_cert_add(self):
        """
        Test the `xmlrpc.cert_request` method without --add.

        This should fail because the service principal doesn't exist
        """
        # First create the host that will use this policy
        res = api.Command['host_add'](self.host_fqdn, force= True)['result']

        csr = unicode(self.generateCSR(str(self.subject)))
        with assert_raises(errors.NotFound):
            res = api.Command['cert_request'](csr, principal=self.service_princ)

    def test_2_cert_add(self):
        """
        Test the `xmlrpc.cert_request` method with --add.
        """
        # Our host should exist from previous test
        global cert

        csr = unicode(self.generateCSR(str(self.subject)))
        res = api.Command['cert_request'](csr, principal=self.service_princ, add=True)['result']
        assert DN(res['subject']) == self.subject
        # save the cert for the service_show/find tests
        cert = res['certificate']

    def test_3_service_show(self):
        """
        Verify that service-show has the right certificate using service-show.
        """
        global cert

        res = api.Command['service_show'](self.service_princ)['result']
        assert base64.b64encode(res['usercertificate'][0]) == cert

    def test_4_service_find(self):
        """
        Verify that service-find has the right certificate using service-find.
        """
        global cert

        # Assume there is only one service
        res = api.Command['service_find'](self.service_princ)['result']
        assert base64.b64encode(res[0]['usercertificate'][0]) == cert

    def test_5_cert_renew(self):
        """
        Issue a new certificate for a service
        """
        global newcert

        csr = unicode(self.generateCSR(str(self.subject)))
        res = api.Command['cert_request'](csr, principal=self.service_princ)['result']
        assert DN(res['subject']) == self.subject
        # save the cert for the service_show/find tests
        newcert = res['certificate']

    def test_6_service_show(self):
        """
        Verify the new certificate with service-show.
        """
        global cert, newcert

        res = api.Command['service_show'](self.service_princ)['result']
        # It should no longer match our old cert
        assert base64.b64encode(res['usercertificate'][0]) != cert
        # And it should match the new one
        assert base64.b64encode(res['usercertificate'][0]) == newcert

    def test_7_cleanup(self):
        """
        Clean up cert test data
        """
        # Now clean things up
        api.Command['host_del'](self.host_fqdn)

        # Verify that the service is gone
        res = api.Command['service_find'](self.service_princ)
        assert res['count'] == 0
