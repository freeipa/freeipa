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

import nose
from ipalib import pkcs10
from ipapython import ipautil
import pytest
import os
import cryptography.x509


@pytest.mark.tier0
class test_update(object):
    """
    Test the PKCS#10 Parser.
    """

    def setup(self):
        self.testdir = os.path.abspath(os.path.dirname(__file__))
        if not ipautil.file_exists(os.path.join(self.testdir,
                                                "test0.csr")):
            raise nose.SkipTest("Unable to find test update files")

    def read_file(self, filename):
        with open(os.path.join(self.testdir, filename), "r") as fp:
            data = fp.read()
        return data

    def test_0(self):
        """
        Test simple CSR with no attributes
        """
        csr = pkcs10.load_certificate_request(self.read_file("test0.csr"))

        subject = csr.subject

        cn = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.COMMON_NAME)[-1].value
        assert(cn == 'test.example.com')
        st = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.STATE_OR_PROVINCE_NAME)[-1].value
        assert(st == 'California')
        c = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.COUNTRY_NAME)[-1].value
        assert(c == 'US')

    def test_1(self):
        """
        Test CSR with subject alt name
        """
        csr = self.read_file("test1.csr")
        request = pkcs10.load_certificate_request(csr)

        subject = request.subject

        cn = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.COMMON_NAME)[-1].value
        assert(cn == 'test.example.com')
        st = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.STATE_OR_PROVINCE_NAME)[-1].value
        assert(st == 'California')
        c = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.COUNTRY_NAME)[-1].value
        assert(c == 'US')

        san = request.extensions.get_extension_for_oid(
                cryptography.x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns = san.get_values_for_type(cryptography.x509.DNSName)
        assert dns[0] == 'testlow.example.com'

    def test_2(self):
        """
        Test CSR with subject alt name and a list of CRL distribution points
        """
        csr = self.read_file("test2.csr")
        request = pkcs10.load_certificate_request(csr)

        subject = request.subject

        cn = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.COMMON_NAME)[-1].value
        assert(cn == 'test.example.com')
        st = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.STATE_OR_PROVINCE_NAME)[-1].value
        assert(st == 'California')
        c = subject.get_attributes_for_oid(
                cryptography.x509.NameOID.COUNTRY_NAME)[-1].value
        assert(c == 'US')

        san = request.extensions.get_extension_for_oid(
                cryptography.x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns = san.get_values_for_type(cryptography.x509.DNSName)
        assert dns[0] == 'testlow.example.com'

        crldps = request.extensions.get_extension_for_oid(
                cryptography.x509.ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        gns = []
        for crldp in crldps:
            gns.extend(crldp.full_name)
        uris = [
            u'http://ca.example.com/my.crl',
            u'http://other.example.com/my.crl',
        ]
        for uri in uris:
            assert cryptography.x509.UniformResourceIdentifier(uri) in gns

    def test_3(self):
        """
        Test CSR with base64-encoded bogus data
        """
        csr = self.read_file("test3.csr")

        with pytest.raises(ValueError):
            pkcs10.load_certificate_request(csr)

    def test_4(self):
        """
        Test CSR with badly formatted base64-encoded data
        """
        csr = self.read_file("test4.csr")
        with pytest.raises(ValueError):
            pkcs10.load_certificate_request(csr)
