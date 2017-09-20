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

import base64
import datetime

import pytest

from ipalib import x509
from ipapython.dn import DN

pytestmark = pytest.mark.tier0

# certutil -

# certificate for CN=ipa.example.com,O=IPA
goodcert = (
    b'MIICAjCCAWugAwIBAgICBEUwDQYJKoZIhvcNAQEFBQAwKTEnMCUGA1UEAxMeSVBB'
    b'IFRlc3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDYyNTEzMDA0MloXDTE1'
    b'MDYyNTEzMDA0MlowKDEMMAoGA1UEChMDSVBBMRgwFgYDVQQDEw9pcGEuZXhhbXBs'
    b'ZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJcZ+H6+cQaN/BlzR8OY'
    b'kVeJgaU5tCaV9FF1m7Ws/ftPtTJUaSL1ncp6603rjA4tH1aa/B8i8xdC46+ZbY2a'
    b'u8b9ryGcOsx2uaRpNLEQ2Fy//q1kQC8oM+iD8Nd6osF0a2wnugsgnJHPuJzhViaW'
    b'xYgzk5DRdP81debokF3f3FX/AgMBAAGjOjA4MBEGCWCGSAGG+EIBAQQEAwIGQDAT'
    b'BgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEF'
    b'BQADgYEALD6X9V9w381AzzQPcHsjIjiX3B/AF9RCGocKZUDXkdDhsD9NZ3PLPEf1'
    b'AMjkraKG963HPB8scyiBbbSuSh6m7TCp0eDgRpo77zNuvd3U4Qpm0Qk+KEjtHQDj'
    b'NNG6N4ZnCQPmjFPScElvc/GgW7XMbywJy2euF+3/Uip8cnPgSH4='
)

goodcert_headers = (
    b'-----BEGIN CERTIFICATE-----\n' +
    goodcert +
    b'\n-----END CERTIFICATE-----'
)
# The base64-encoded string 'bad cert'
badcert = (
    b'-----BEGIN CERTIFICATE-----\n'
    b'YmFkIGNlcnQ=\r\n'
    b'-----END CERTIFICATE-----'
)

good_pkcs7 = (
    b'-----BEGIN PKCS7-----\n'
    b'MIIDvAYJKoZIhvcNAQcCoIIDrTCCA6kCAQExADALBgkqhkiG9w0BBwGgggOPMIID\n'
    b'izCCAnOgAwIBAgIBATANBgkqhkiG9w0BAQsFADA2MRQwEgYDVQQKDAtFWEFNUExF\n'
    b'LkNPTTEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE3MDkyMDIw\n'
    b'NDI1N1oXDTM3MDkyMDIwNDI1N1owNjEUMBIGA1UECgwLRVhBTVBMRS5DT00xHjAc\n'
    b'BgNVBAMMFUNlcnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQAD\n'
    b'ggEPADCCAQoCggEBAMNojX57UCCPTtEn9tQJBS4By5NixwodKm1UqOGsiecDrB0i\n'
    b'Pw7D6uGP6g4b6srYtbh+YsRJnfekB2L08q1dX3LVEItq2TS0WKqgZuRZkw7DvnGl\n'
    b'eANMwjHmE8k6/E0yI3GGxJLAfDZYw6CDspLkyN9anjQwVCz5N5z5bpeqi5BeVwin\n'
    b'O8WVF6FNn3iyL66uwOsTGEzCo3Y5HiwqYgaND73TtdsBHcIqOdRql3CC3IdoXXcW\n'
    b'044w4Lm2E95MuY729pPBHREtyzVkYtyuoKJ8KApghIY5oCklBkRDjyFK4tE7iF/h\n'
    b's+valeT9vcz2bHMIpvbjqAu/kqE8MjcNEFPjLhcCAwEAAaOBozCBoDAfBgNVHSME\n'
    b'GDAWgBTUB04/d1eLhbMtBi4AB65tsAt+2TAPBgNVHRMBAf8EBTADAQH/MA4GA1Ud\n'
    b'DwEB/wQEAwIBxjAdBgNVHQ4EFgQU1AdOP3dXi4WzLQYuAAeubbALftkwPQYIKwYB\n'
    b'BQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vaXBhLWNhLmdyZXlvYWsuY29t\n'
    b'L2NhL29jc3AwDQYJKoZIhvcNAQELBQADggEBADQFwX1uh8tqLq8SqWZWtH95j33o\n'
    b'5Ze2dW7sVppb/wVnNauG0wDQW7uIx+Ynr7GgufXLNBMn1aP/mA2CdHk7NZz2IB1s\n'
    b'ZvbIfE8dVxzkA+Hh9d6cdgk4eU5rGf6Fw8ScEJ/48Mmncea3uGkHcOmt+BGLA8a1\n'
    b'wtruy+iQylOkbv36CbxKV7IsZDP106Zc+cVeOUQZnCLKmvQkotn6UJd8N1X0R2J3\n'
    b'4/qv0rUtcCnyEBNSgpTGCRlYM4kd98Dqc5W7wUpMcsQMFxQMSYY7pFQkdLPfJEx2\n'
    b'Mg63SPawxfAgUeukrdsF3wTIKkIBu1TVse+kvRvgmRRrfF2a4ZOv5qORe2uhADEA\n'
    b'-----END PKCS7-----'
)


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
        x509.load_pem_x509_certificate(goodcert_headers)

        # Load a good cert with headers and leading text
        newcert = (
            b'leading text\n' + goodcert_headers)
        x509.load_pem_x509_certificate(newcert)

        # Load a good cert with bad headers
        newcert = b'-----BEGIN CERTIFICATE-----' + goodcert_headers
        with pytest.raises((TypeError, ValueError)):
            x509.load_pem_x509_certificate(newcert)

        # Load a bad cert
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(badcert)

    def test_1_load_der_cert(self):
        """
        Test loading a DER certificate.
        """

        der = base64.b64decode(goodcert)

        # Load a good cert
        x509.load_der_x509_certificate(der)

    def test_3_cert_contents(self):
        """
        Test the contents of a certificate
        """
        # Verify certificate contents. This exercises python-cryptography
        # more than anything but confirms our usage of it.

        not_before = datetime.datetime(2010, 6, 25, 13, 0, 42)
        not_after = datetime.datetime(2015, 6, 25, 13, 0, 42)
        cert = x509.load_pem_x509_certificate(goodcert_headers)

        assert DN(cert.subject) == DN(('CN', 'ipa.example.com'), ('O', 'IPA'))
        assert DN(cert.issuer) == DN(('CN', 'IPA Test Certificate Authority'))
        assert cert.serial_number == 1093
        assert cert.not_valid_before == not_before
        assert cert.not_valid_after == not_after

    def test_load_pkcs7_pem(self):
        certlist = x509.pkcs7_to_certs(good_pkcs7, datatype=x509.PEM)
        assert len(certlist) == 1
        cert = certlist[0]
        assert DN(cert.subject) == DN('CN=Certificate Authority,O=EXAMPLE.COM')
        assert cert.serial_number == 1
