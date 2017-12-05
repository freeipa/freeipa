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

from cryptography import x509 as crypto_x509
from ipalib import x509
from ipapython.dn import DN

pytestmark = pytest.mark.tier0

# certutil -

# certificate for CN=ipa.example.com,O=IPA
goodcert = 'MIICAjCCAWugAwIBAgICBEUwDQYJKoZIhvcNAQEFBQAwKTEnMCUGA1UEAxMeSVBBIFRlc3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDYyNTEzMDA0MloXDTE1MDYyNTEzMDA0MlowKDEMMAoGA1UEChMDSVBBMRgwFgYDVQQDEw9pcGEuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJcZ+H6+cQaN/BlzR8OYkVeJgaU5tCaV9FF1m7Ws/ftPtTJUaSL1ncp6603rjA4tH1aa/B8i8xdC46+ZbY2au8b9ryGcOsx2uaRpNLEQ2Fy//q1kQC8oM+iD8Nd6osF0a2wnugsgnJHPuJzhViaWxYgzk5DRdP81debokF3f3FX/AgMBAAGjOjA4MBEGCWCGSAGG+EIBAQQEAwIGQDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADgYEALD6X9V9w381AzzQPcHsjIjiX3B/AF9RCGocKZUDXkdDhsD9NZ3PLPEf1AMjkraKG963HPB8scyiBbbSuSh6m7TCp0eDgRpo77zNuvd3U4Qpm0Qk+KEjtHQDjNNG6N4ZnCQPmjFPScElvc/GgW7XMbywJy2euF+3/Uip8cnPgSH4='

# The base64-encoded string 'bad cert'
badcert = 'YmFkIGNlcnQ='

long_oid_cert = '''
-----BEGIN CERTIFICATE-----
MIIFiTCCBHGgAwIBAgITSAAAAAd1bEC5lsOdnQAAAAAABzANBgkqhkiG9w0BAQsF
ADBLMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxEjAQBgoJkiaJk/IsZAEZFgJhZDEe
MBwGA1UEAxMVYWQtV0lOLVBQSzAxNUY5TURRLUNBMB4XDTE3MDUyNTIzNDg0NVoX
DTE5MDUyNTIzNTg0NVowNDESMBAGA1UEChMJSVBBLkxPQ0FMMR4wHAYDVQQDExVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDyyuty6irlL89hdaSW0UyAGLsOOMgAuJwBAeuRUorR159rsSnUXLcTHIsm
EszKhwxp3NkkawRWx/s0UN1m2+RUwMl6gvlw+G80Mz0S77C77M+2lO8HRmZGm+Wu
zBNcc9SANHuDQ1NISfZgLiscMS0+l0T3g6/Iqtg1kPWrq/tMevfh6tJEIedSBGo4
3xKEMSDkrvaeTuSVrgn/QT0m+WNccZa0c7X35L/hgR22/l5sr057Ef8F9vL8zUH5
TttFBIuiWJo8A8XX9I1zYIFhWjW3OVDZPBUnhGHH6yNyXGxXMRfcrrc74eTw8ivC
080AQuRtgwvDErB/JPDJ5w5t/ielAgMBAAGjggJ7MIICdzA9BgkrBgEEAYI3FQcE
MDAuBiYrBgEEAYI3FQiEoqJGhYq1PoGllQqGi+F4nacAgRODs5gfgozzAAIBZAIB
BTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUnSrC
yW3CR0e3ilJdN6kL06P3KHMwHwYDVR0jBBgwFoAUj69xtyUNwp8on+NWO+HlxKyg
X7AwgdgGA1UdHwSB0DCBzTCByqCBx6CBxIaBwWxkYXA6Ly8vQ049YWQtV0lOLVBQ
SzAxNUY5TURRLUNBLENOPVdJTi1QUEswMTVGOU1EUSxDTj1DRFAsQ049UHVibGlj
JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
Qz1hZCxEQz1sb2NhbD9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2Jq
ZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcQGCCsGAQUFBwEBBIG3MIG0
MIGxBggrBgEFBQcwAoaBpGxkYXA6Ly8vQ049YWQtV0lOLVBQSzAxNUY5TURRLUNB
LENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
Tj1Db25maWd1cmF0aW9uLERDPWFkLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFz
ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MDMGA1UdIAQsMCow
KAYmKwYBBAGCNxUIhKKiRoWKtT6BpZUKhovheJ2nAIEThrXzUYabpA4wDQYJKoZI
hvcNAQELBQADggEBAIsFS+Qc/ufTrkuHbMmzksOpxq+OIi9rot8zy9/1Vmj6d+iP
kB+vQ1u4/IhdQArJFNhsBzWSY9Pi8ZclovpepFeEZfXPUenyeRCU43HdMXcHXnlP
YZfyLQWOugdo1WxK6S9qQSOSlC7BSGZWvKkiAPAwr4zNbbS+ROA2w0xaYMv0rr5W
A4UAyzZAdqaGRJBRvCZ/uFHM5wMw0LzNCL4CqKW9jfZX0Fc2tdGx8zbTYxIdgr2D
PL25as32r3S/m4uWqoQaK0lxK5Y97eusK2rrmidy32Jctzwl29UWq8kpjRAuD8iR
CSc7sKqOf+fn3+fKITR2/DcSVvb0SGCr5fVVnjQ=
-----END CERTIFICATE-----
'''

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
        x509.load_certificate(goodcert)

        # Should handle list/tuple
        x509.load_certificate((goodcert,))
        x509.load_certificate([goodcert])

        # Load a good cert with headers
        newcert = '-----BEGIN CERTIFICATE-----' + goodcert + '-----END CERTIFICATE-----'
        x509.load_certificate(newcert)

        # Should handle list/tuple
        x509.load_certificate((newcert,))
        x509.load_certificate([newcert])

        # Load a good cert with headers and leading text
        newcert = (
            'leading text\n-----BEGIN CERTIFICATE-----' +
            goodcert +
            '-----END CERTIFICATE-----')
        x509.load_certificate(newcert)

        # Should handle list/tuple
        x509.load_certificate((newcert,))
        x509.load_certificate([newcert])

        # Load a good cert with bad headers
        newcert = '-----BEGIN CERTIFICATE-----' + goodcert
        with pytest.raises((TypeError, ValueError)):
            x509.load_certificate(newcert)

        # Load a bad cert
        with pytest.raises(ValueError):
            x509.load_certificate(badcert)

    def test_1_load_der_cert(self):
        """
        Test loading a DER certificate.
        """

        der = base64.b64decode(goodcert)

        # Load a good cert
        x509.load_certificate(der, x509.DER)

        # Should handle list/tuple
        x509.load_certificate((der,), x509.DER)
        x509.load_certificate([der], x509.DER)

    def test_3_cert_contents(self):
        """
        Test the contents of a certificate
        """
        # Verify certificate contents. This exercises python-cryptography
        # more than anything but confirms our usage of it.

        not_before = datetime.datetime(2010, 6, 25, 13, 0, 42)
        not_after = datetime.datetime(2015, 6, 25, 13, 0, 42)
        cert = x509.load_certificate(goodcert)

        assert DN(cert.subject) == DN(('CN', 'ipa.example.com'), ('O', 'IPA'))
        assert DN(cert.issuer) == DN(('CN', 'IPA Test Certificate Authority'))
        assert cert.serial_number == 1093
        assert cert.not_valid_before == not_before
        assert cert.not_valid_after == not_after

    def test_long_oid(self):
        """
        Test cerificate with very long OID. In this case we are using a
        certificate from an opened case where one of X509v3 Certificate`s
        Policies OID is longer then 80 chars.
        """
        cert = x509.load_certificate(long_oid_cert)
        ext = cert.extensions.get_extension_for_class(crypto_x509.
                                                      CertificatePolicies)

        assert len(ext.value) == 1
        assert ext.value[0].policy_identifier.dotted_string == (
            u'1.3.6.1.4.1.311.21.8.8950086.10656446.2706058.12775672.480128.'
            '147.13466065.13029902')
