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
Test the `pkcs10.py` module.
"""

import os
import sys
import nose
from tests.util import raises, PluginTester
from ipalib import pkcs10
from ipapython import ipautil
import nss.nss as nss
from nss.error import NSPRError

class test_update(object):
    """
    Test the PKCS#10 Parser.
    """

    def setUp(self):
        nss.nss_init_nodb()
        if ipautil.file_exists("test0.csr"):
            self.testdir="./"
        elif ipautil.file_exists("tests/test_pkcs10/test0.csr"):
            self.testdir= "./tests/test_pkcs10/"
        else:
            raise nose.SkipTest("Unable to find test update files")

    def read_file(self, filename):
        fp = open(self.testdir + filename, "r")
        data = fp.read()
        fp.close()
        return data

    def test_0(self):
        """
        Test simple CSR with no attributes
        """
        csr = self.read_file("test0.csr")
        request = pkcs10.load_certificate_request(csr)

        subject = pkcs10.get_subject(request)

        assert(subject.common_name == 'test.example.com')
        assert(subject.state_name == 'California')
        assert(subject.country_name == 'US')

    def test_1(self):
        """
        Test CSR with subject alt name
        """
        csr = self.read_file("test1.csr")
        request = pkcs10.load_certificate_request(csr)

        subject = pkcs10.get_subject(request)

        assert(subject.common_name == 'test.example.com')
        assert(subject.state_name == 'California')
        assert(subject.country_name == 'US')

        for extension in request.extensions:
            if extension.oid_tag == nss.SEC_OID_X509_SUBJECT_ALT_NAME:
                assert nss.x509_alt_name(extension.value)[0] == 'testlow.example.com'

    def test_2(self):
        """
        Test CSR with subject alt name and a list of CRL distribution points
        """
        csr = self.read_file("test2.csr")
        request = pkcs10.load_certificate_request(csr)

        subject = pkcs10.get_subject(request)

        assert(subject.common_name == 'test.example.com')
        assert(subject.state_name == 'California')
        assert(subject.country_name == 'US')

        for extension in request.extensions:
            if extension.oid_tag == nss.SEC_OID_X509_SUBJECT_ALT_NAME:
                assert nss.x509_alt_name(extension.value)[0] == 'testlow.example.com'
            if extension.oid_tag == nss.SEC_OID_X509_CRL_DIST_POINTS:
                pts = nss.CRLDistributionPts(extension.value)
                urls = pts[0].get_general_names()
                assert('http://ca.example.com/my.crl' in urls)
                assert('http://other.example.com/my.crl' in urls)

    def test_3(self):
        """
        Test CSR with base64-encoded bogus data
        """
        csr = self.read_file("test3.csr")

        try:
            request = pkcs10.load_certificate_request(csr)
        except NSPRError, nsprerr:
            # (SEC_ERROR_BAD_DER) security library: improperly formatted DER-encoded message.
            assert(nsprerr. errno== -8183)

    def test_4(self):
        """
        Test CSR with badly formatted base64-encoded data
        """
        csr = self.read_file("test4.csr")
        try:
            request = pkcs10.load_certificate_request(csr)
        except TypeError, typeerr:
            assert(str(typeerr) == 'Incorrect padding')
