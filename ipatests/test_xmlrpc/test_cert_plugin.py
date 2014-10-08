# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009,2013  Red Hat
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
Test the `ipalib/plugins/cert.py` module against a RA.
"""

import sys
import os
import shutil
from nose.tools import raises, assert_raises  # pylint: disable=E0611

from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors
from ipalib import x509
import tempfile
from ipapython import ipautil
import nose
import base64
from ipaplatform.paths import paths
from ipapython.dn import DN

# So we can save the cert from issuance and compare it later
cert = None
newcert = None

def is_db_configured():
    """
    Raise an exception if we are testing against lite-server and the
    developer cert database is configured.
    """
    aliasdir = api.env.dot_ipa + os.sep + 'alias' + os.sep + '.pwd'

    if (api.env.xmlrpc_uri == u'http://localhost:8888/ipa/xml' and
       not ipautil.file_exists(aliasdir)):
        raise nose.SkipTest('developer CA not configured in %s' % aliasdir)

# Test setup
#
# This test needs a configured CA behind it in order to work properly
#
# To test against Apache directly then no changes are required. Just be
# sure the xmlrpc_uri in ~/.ipa/default.conf points to Apache.
#
# To test against Dogtag CA in the lite-server:
#
# - Copy the 3 NSS db files from /etc/httpd/alias to ~/.ipa/alias
# - Copy /etc/httpd/alias/pwdfile.txt to  ~/.ipa/alias/.pwd.
# - Change ownership of these files to be readable by you.
#
# The API tested depends on the value of ~/.ipa/default/ra_plugin when
# running as the lite-server.

class test_cert(XMLRPC_test):

    @classmethod
    def setup_class(cls):
        super(test_cert, cls).setup_class()

        if 'cert_request' not in api.Command:
            raise nose.SkipTest('cert_request not registered')

        is_db_configured()

    def run_certutil(self, args, stdin=None):
        new_args = [paths.CERTUTIL, "-d", self.reqdir]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

    def setup(self):
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

    def teardown(self):
        shutil.rmtree(self.reqdir, ignore_errors=True)

    def generateCSR(self, subject):
        self.run_certutil(["-R", "-s", subject,
                           "-o", self.reqfile,
                           "-z", paths.GROUP,
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

    def test_0001_cert_add(self):
        """
        Test the `xmlrpc.cert_request` method without --add.

        This should fail because the service principal doesn't exist
        """
        # First create the host that will use this policy
        res = api.Command['host_add'](self.host_fqdn, force= True)['result']

        csr = unicode(self.generateCSR(str(self.subject)))
        with assert_raises(errors.NotFound):
            res = api.Command['cert_request'](csr, principal=self.service_princ)

    def test_0002_cert_add(self):
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

    def test_0003_service_show(self):
        """
        Verify that service-show has the right certificate using service-show.
        """
        global cert

        res = api.Command['service_show'](self.service_princ)['result']
        assert base64.b64encode(res['usercertificate'][0]) == cert

    def test_0004_service_find(self):
        """
        Verify that service-find has the right certificate using service-find.
        """
        global cert

        # Assume there is only one service
        res = api.Command['service_find'](self.service_princ)['result']
        assert base64.b64encode(res[0]['usercertificate'][0]) == cert

    def test_0005_cert_renew(self):
        """
        Issue a new certificate for a service
        """
        global newcert

        csr = unicode(self.generateCSR(str(self.subject)))
        res = api.Command['cert_request'](csr, principal=self.service_princ)['result']
        assert DN(res['subject']) == self.subject
        # save the cert for the service_show/find tests
        newcert = res['certificate']

    def test_0006_service_show(self):
        """
        Verify the new certificate with service-show.
        """
        global cert, newcert

        res = api.Command['service_show'](self.service_princ)['result']
        # It should no longer match our old cert
        assert base64.b64encode(res['usercertificate'][0]) != cert
        # And it should match the new one
        assert base64.b64encode(res['usercertificate'][0]) == newcert

    def test_0007_cleanup(self):
        """
        Clean up cert test data
        """
        # Now clean things up
        api.Command['host_del'](self.host_fqdn)

        # Verify that the service is gone
        res = api.Command['service_find'](self.service_princ)
        assert res['count'] == 0

class test_cert_find(XMLRPC_test):

    @classmethod
    def setup_class(cls):
        super(test_cert_find, cls).setup_class()

        if 'cert_find' not in api.Command:
            raise nose.SkipTest('cert_find not registered')

        if api.env.ra_plugin != 'dogtag':
            raise nose.SkipTest('cert_find for dogtag CA only')

        is_db_configured()

    """
    Test the `cert-find` command.
    """
    short = api.env.host.replace('.' + api.env.domain, '')

    def test_0001_find_all(self):
        """
        Search for all certificates.

        We don't know how many we'll get but there should be at least 10
        by default.
        """
        res = api.Command['cert_find']()
        assert 'count' in res and res['count'] >= 10

    def test_0002_find_CA(self):
        """
        Search for the CA certificate.
        """
        res = api.Command['cert_find'](subject=u'Certificate Authority')
        assert 'count' in res and res['count'] == 1

    def test_0003_find_OCSP(self):
        """
        Search for the OCSP certificate.
        """
        res = api.Command['cert_find'](subject=u'OCSP Subsystem')

    def test_0004_find_this_host(self):
        """
        Find all certificates for this IPA server
        """
        res = api.Command['cert_find'](subject=api.env.host)
        assert 'count' in res and res['count'] > 1

    def test_0005_find_this_host_exact(self):
        """
        Find all certificates for this IPA server (exact)
        """
        res = api.Command['cert_find'](subject=api.env.host, exactly=True)
        assert 'count' in res and res['count'] > 1

    def test_0006_find_this_short_host_exact(self):
        """
        Find all certificates for this IPA server short name (exact)
        """
        res = api.Command['cert_find'](subject=self.short, exactly=True)
        assert 'count' in res and res['count'] == 0

    def test_0007_find_revocation_reason_0(self):
        """
        Find all certificates with revocation reason 0
        """
        res = api.Command['cert_find'](revocation_reason=0)
        assert 'count' in res and res['count'] == 0

    def test_0008_find_revocation_reason_1(self):
        """
        Find all certificates with revocation reason 1
        """
        res = api.Command['cert_find'](revocation_reason=1)
        assert 'count' in res and res['count'] == 0

    def test_0009_find_revocation_reason_2(self):
        """
        Find all certificates with revocation reason 2
        """
        res = api.Command['cert_find'](revocation_reason=2)
        assert 'count' in res and res['count'] == 0

    def test_0010_find_revocation_reason_3(self):
        """
        Find all certificates with revocation reason 3
        """
        res = api.Command['cert_find'](revocation_reason=3)
        assert 'count' in res and res['count'] == 0

    def test_0011_find_revocation_reason_4(self):
        """
        Find all certificates with revocation reason 4

        There is no way to know in advance how many revoked certificates
        we'll have but in the context of make-test we'll have at least one.
        """
        res = api.Command['cert_find'](revocation_reason=4)
        assert 'count' in res and res['count'] >= 1

    def test_0012_find_revocation_reason_5(self):
        """
        Find all certificates with revocation reason 5
        """
        res = api.Command['cert_find'](revocation_reason=5)
        assert 'count' in res and res['count'] == 0

    def test_0013_find_revocation_reason_6(self):
        """
        Find all certificates with revocation reason 6
        """
        res = api.Command['cert_find'](revocation_reason=6)
        assert 'count' in res and res['count'] == 0

    # There is no revocation reason #7

    def test_0014_find_revocation_reason_8(self):
        """
        Find all certificates with revocation reason 8
        """
        res = api.Command['cert_find'](revocation_reason=8)
        assert 'count' in res and res['count'] == 0

    def test_0015_find_revocation_reason_9(self):
        """
        Find all certificates with revocation reason 9
        """
        res = api.Command['cert_find'](revocation_reason=9)
        assert 'count' in res and res['count'] == 0

    def test_0016_find_revocation_reason_10(self):
        """
        Find all certificates with revocation reason 10
        """
        res = api.Command['cert_find'](revocation_reason=10)
        assert 'count' in res and res['count'] == 0

    def test_0017_find_by_issuedon(self):
        """
        Find all certificates issued since 2008
        """
        res = api.Command['cert_find'](issuedon_from=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0018_find_through_issuedon(self):
        """
        Find all certificates issued through 2008
        """
        res = api.Command['cert_find'](issuedon_to=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0019_find_notvalid_before(self):
        """
        Find all certificates valid not before 2008
        """
        res = api.Command['cert_find'](validnotbefore_from=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0020_find_notvalid_before(self):
        """
        Find all certificates valid not before to 2100
        """
        res = api.Command['cert_find'](validnotbefore_to=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0021_find_notvalid_before(self):
        """
        Find all certificates valid not before 2100
        """
        res = api.Command['cert_find'](validnotbefore_from=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0022_find_notvalid_before(self):
        """
        Find all certificates valid not before to 2008
        """
        res = api.Command['cert_find'](validnotbefore_to=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0023_find_notvalid_after(self):
        """
        Find all certificates valid not after 2008
        """
        res = api.Command['cert_find'](validnotafter_from=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0024_find_notvalid_after(self):
        """
        Find all certificates valid not after to 2100
        """
        res = api.Command['cert_find'](validnotafter_to=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 10

    def test_0025_find_notvalid_after(self):
        """
        Find all certificates valid not after 2100
        """
        res = api.Command['cert_find'](validnotafter_from=u'2100-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0026_find_notvalid_after(self):
        """
        Find all certificates valid not after to 2008
        """
        res = api.Command['cert_find'](validnotafter_to=u'2008-01-01',
                                       sizelimit=10)
        assert 'count' in res and res['count'] == 0

    def test_0027_sizelimit_zero(self):
        """
        Search with a sizelimit of 0
        """
        res = api.Command['cert_find'](sizelimit=0)
        assert 'count' in res and res['count'] == 0

    @raises(errors.ValidationError)
    def test_0028_find_negative_size(self):
        """
        Search with a negative sizelimit
        """
        res = api.Command['cert_find'](sizelimit=-100)

    def test_0029_search_for_notfound(self):
        """
        Search for a host that isn't there.
        """
        res = api.Command['cert_find'](subject=u'notfound')
        assert 'count' in res and res['count'] == 0

    def test_0030_search_for_testcerts(self):
        """
        Search for certs created in other tests
        """
        res = api.Command['cert_find'](subject=u'ipatestcert.%s' % api.env.domain)
        assert 'count' in res and res['count'] >= 1

    @raises(errors.ValidationError)
    def test_0031_search_on_invalid_date(self):
        """
        Search using invalid date format
        """
        res = api.Command['cert_find'](issuedon_from=u'xyz')
