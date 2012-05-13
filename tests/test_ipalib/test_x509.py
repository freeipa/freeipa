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
Test the `ipalib.x509` module.
"""

import os
from os import path
import sys
from tests.util import raises, setitem, delitem, ClassChecker
from tests.util import getitem, setitem, delitem
from tests.util import TempDir, TempHome
from ipalib.constants import TYPE_ERROR, OVERRIDE_ERROR, SET_ERROR, DEL_ERROR
from ipalib.constants import NAME_REGEX, NAME_ERROR
import base64
from ipalib import x509
from nss.error import NSPRError
from ipapython.dn import DN

# certutil -

# certificate for CN=ipa.example.com,O=IPA
goodcert = 'MIICAjCCAWugAwIBAgICBEUwDQYJKoZIhvcNAQEFBQAwKTEnMCUGA1UEAxMeSVBBIFRlc3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDYyNTEzMDA0MloXDTE1MDYyNTEzMDA0MlowKDEMMAoGA1UEChMDSVBBMRgwFgYDVQQDEw9pcGEuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJcZ+H6+cQaN/BlzR8OYkVeJgaU5tCaV9FF1m7Ws/ftPtTJUaSL1ncp6603rjA4tH1aa/B8i8xdC46+ZbY2au8b9ryGcOsx2uaRpNLEQ2Fy//q1kQC8oM+iD8Nd6osF0a2wnugsgnJHPuJzhViaWxYgzk5DRdP81debokF3f3FX/AgMBAAGjOjA4MBEGCWCGSAGG+EIBAQQEAwIGQDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADgYEALD6X9V9w381AzzQPcHsjIjiX3B/AF9RCGocKZUDXkdDhsD9NZ3PLPEf1AMjkraKG963HPB8scyiBbbSuSh6m7TCp0eDgRpo77zNuvd3U4Qpm0Qk+KEjtHQDjNNG6N4ZnCQPmjFPScElvc/GgW7XMbywJy2euF+3/Uip8cnPgSH4='

# The base64-encoded string 'bad cert'
badcert = 'YmFkIGNlcnQ='

class test_x509(object):
    """
    Test `ipalib.x509`

    I created the contents of this certificate with a self-signed CA with:
      % certutil -R -s "CN=ipa.example.com,O=IPA" -d . -a -o example.csr
      % ./ipa host-add ipa.example.com
      % ./ipa cert-request --add --principal=test/ipa.example.com example.csr
    """

    def test_1_load_base64_cert(self):
        """
        Test loading a base64-encoded certificate.
        """

        # Load a good cert
        cert = x509.load_certificate(goodcert)

        # Load a good cert with headers
        newcert = '-----BEGIN CERTIFICATE-----' + goodcert + '-----END CERTIFICATE-----'
        cert = x509.load_certificate(newcert)

        # Load a good cert with bad headers
        newcert = '-----BEGIN CERTIFICATE-----' + goodcert
        try:
            cert = x509.load_certificate(newcert)
        except TypeError:
            pass

        # Load a bad cert
        try:
            cert = x509.load_certificate(badcert)
        except NSPRError:
            pass

    def test_1_load_der_cert(self):
        """
        Test loading a DER certificate.
        """

        der = base64.b64decode(goodcert)

        # Load a good cert
        cert = x509.load_certificate(der, x509.DER)

    def test_2_get_subject(self):
        """
        Test retrieving the subject
        """
        subject = x509.get_subject(goodcert)
        assert DN(str(subject)) == DN(('CN','ipa.example.com'),('O','IPA'))

        der = base64.b64decode(goodcert)
        subject = x509.get_subject(der, x509.DER)
        assert DN(str(subject)) == DN(('CN','ipa.example.com'),('O','IPA'))

        # We should be able to pass in a tuple/list of certs too
        subject = x509.get_subject((goodcert))
        assert DN(str(subject)) == DN(('CN','ipa.example.com'),('O','IPA'))

        subject = x509.get_subject([goodcert])
        assert DN(str(subject)) == DN(('CN','ipa.example.com'),('O','IPA'))

    def test_2_get_serial_number(self):
        """
        Test retrieving the serial number
        """
        serial = x509.get_serial_number(goodcert)
        assert serial == 1093

        der = base64.b64decode(goodcert)
        serial = x509.get_serial_number(der, x509.DER)
        assert serial == 1093

        # We should be able to pass in a tuple/list of certs too
        serial = x509.get_serial_number((goodcert))
        assert serial == 1093

        serial = x509.get_serial_number([goodcert])
        assert serial == 1093

    def test_3_cert_contents(self):
        """
        Test the contents of a certificate
        """
        # Verify certificate contents. This exercises python-nss more than
        # anything but confirms our usage of it.

        cert = x509.load_certificate(goodcert)

        assert DN(str(cert.subject)) == DN(('CN','ipa.example.com'),('O','IPA'))
        assert DN(str(cert.issuer)) == DN(('CN','IPA Test Certificate Authority'))
        assert cert.serial_number == 1093
        assert cert.valid_not_before_str == 'Fri Jun 25 13:00:42 2010 UTC'
        assert cert.valid_not_after_str == 'Thu Jun 25 13:00:42 2015 UTC'
