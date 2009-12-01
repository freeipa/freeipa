# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipalib/plugins/cert.py` module against the selfsign plugin.
"""

import sys
import shutil
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors
import tempfile
from ipapython import ipautil


class test_cert(XMLRPC_test):

    def run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.reqdir]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

    def setUp(self):
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
        (hostdn, res) = api.Command['host_add'](self.host_fqdn)

        csr = unicode(self.generateCSR("CN=%s" % self.host_fqdn))
        try:
            (dn, res) = api.Command['cert_request'](csr, principal=self.service_princ)
            api.Command['cert_request'](csr, principal=self.service_princ)
            assert False
        except errors.NotFound:
            pass

    def test_2_cert_add(self):
        """
        Test the `xmlrpc.cert_request` method with --add.
        """
        # Our host should exist from previous test

        csr = unicode(self.generateCSR("CN=%s" % self.host_fqdn))
        res = api.Command['cert_request'](csr, principal=self.service_princ, add=True)
        assert res['subject'] == 'CN=ipatestcert.greyoak.com'

        # Now clean things up
        api.Command['host_del'](self.host_fqdn)
#        api.Command['service_del'](self.service_princ)
