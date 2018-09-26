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
from cryptography.x509.general_name import DNSName
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

long_oid_cert = b'''
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

ipa_demo_crt = b'''\
-----BEGIN CERTIFICATE-----
MIIGFTCCBP2gAwIBAgISA61CoqWtpZoTEyfLCXliPLYFMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xODA3MjUwNTM2NTlaFw0x
ODEwMjMwNTM2NTlaMCAxHjAcBgNVBAMTFWlwYS5kZW1vMS5mcmVlaXBhLm9yZzCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKisvYUdarWE0CS9i+RcNf9Q
41Euw36R4Myf/PUCDVUvGsVXQWSCanbtyxa8Ows4cAHrfqhiKAnSg0IhLqCMJVQ8
8F699FHrP9EfPmZkG3RMLYPxKNrSmOVyNpIEQY9qfkDXZPLung6dk/c225Znoltq
bVWLObXA7eP9C/djupg3gUD7vOAMHFmfZ3OKnx1uktL5p707o2/qlkSiEO4Z5ebD
M8X0dTkN8V3LCCOjzCp88itGUWJM8Tjb86WkmYkJxmeZx6REd37rDXjqgYhwgXOB
bSqDkYKRaihwvd5Up/vE1wApBS1k7b1oEW80teDUbzbaaqp7oBWbZD2Ac1yJF7UC
AwEAAaOCAx0wggMZMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUUmTMI1CB6qFMXc0+
AGmqpfBAwhIwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYB
BQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2Vu
Y3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2Vu
Y3J5cHQub3JnLzAgBgNVHREEGTAXghVpcGEuZGVtbzEuZnJlZWlwYS5vcmcwgf4G
A1UdIASB9jCB8zAIBgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUF
BwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4M
gZtUaGlzIENlcnRpZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJl
bHlpbmcgUGFydGllcyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENl
cnRpZmljYXRlIFBvbGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9y
Zy9yZXBvc2l0b3J5LzCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AMEWSuCnctLU
OS3ICsEHcNTwxJvemRpIQMH6B1Fk9jNgAAABZNAnsSAAAAQDAEcwRQIgHkd/UkTZ
w8iV1Ox8MPHLrpY33cX6i5FV6w9+7YH3H2kCIQCVcrhsr4fokDyE2ueUqSFxkBVH
WND84/w5rFNAPjyO1QB2ACk8UZZUyDlluqpQ/FgH1Ldvv1h6KXLcpMMM9OVFR/R4
AAABZNAnsyUAAAQDAEcwRQIhALDWY2k55abu7IPwnFvMr4Zqd1DYQXEKWZEQLXUP
s4XGAiAabjpUwrLKVXpbp4WNLkTNlFjrSJafOzLG68H9AnoD4zANBgkqhkiG9w0B
AQsFAAOCAQEAfBNuQn/A2olJHxoBGLfMcQCkkNOfvBpfQeKgni2VVM+r1ZY8YVXx
OtVnV6XQ5M+l+6xlRpP1IwDdmJd/yaQgwbmYf4zl94W/s/qq4nlTd9G4ahmJOhlc
mWeIQMoEtAmQlIOqWto+Knfakz6Xyo+HVCQEyeoBmYFGZcakeAm6tp/6qtpkej+4
wBjShMPAdSYDPRaAqnZ3BAK2UmmlpAA5tkNvqOaHBCi760zYoxT6j1an7FotG0v9
2+W0aL34eMWKz/g4qhwk+Jiz45LLQWhHGIgXIUoNSzHgLIVuVOQI8DPsguvT6GHW
QUs1Hx1wL7mL4U8fKCFDKA+ds2B2xWgoZg==
-----END CERTIFICATE-----
'''


class test_x509:
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
        assert cert.san_general_names == []
        assert cert.san_a_label_dns_names == []
        assert cert.extended_key_usage == {'1.3.6.1.5.5.7.3.1'}
        assert cert.extended_key_usage_bytes == (
            b'0\x16\x06\x03U\x1d%\x01\x01\xff\x04\x0c0\n\x06\x08'
            b'+\x06\x01\x05\x05\x07\x03\x01'
        )

    def test_load_pkcs7_pem(self):
        certlist = x509.pkcs7_to_certs(good_pkcs7, datatype=x509.PEM)
        assert len(certlist) == 1
        cert = certlist[0]
        assert DN(cert.subject) == DN('CN=Certificate Authority,O=EXAMPLE.COM')
        assert cert.serial_number == 1

    def test_long_oid(self):
        """
        Test cerificate with very long OID. In this case we are using a
        certificate from an opened case where one of X509v3 Certificate`s
        Policies OID is longer then 80 chars.
        """
        cert = x509.load_pem_x509_certificate(long_oid_cert)
        ext = cert.extensions.get_extension_for_class(crypto_x509.
                                                      CertificatePolicies)

        assert len(ext.value) == 1
        assert ext.value[0].policy_identifier.dotted_string == (
            u'1.3.6.1.4.1.311.21.8.8950086.10656446.2706058.12775672.480128.'
            '147.13466065.13029902')

    def test_ipa_demo_letsencrypt(self):
        cert = x509.load_pem_x509_certificate(ipa_demo_crt)
        assert DN(cert.subject) == DN('CN=ipa.demo1.freeipa.org')
        assert DN(cert.issuer) == DN(
            "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US")
        assert cert.serial_number == 0x03ad42a2a5ada59a131327cb0979623cb605
        not_before = datetime.datetime(2018, 7, 25, 5, 36, 59)
        not_after = datetime.datetime(2018, 10, 23, 5, 36, 59)
        assert cert.not_valid_before == not_before
        assert cert.not_valid_after == not_after
        assert cert.san_general_names == [DNSName('ipa.demo1.freeipa.org')]
        assert cert.san_a_label_dns_names == ['ipa.demo1.freeipa.org']
        assert cert.extended_key_usage == {
            '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'
        }
        assert cert.extended_key_usage_bytes == (
            b'0 \x06\x03U\x1d%\x01\x01\xff\x04\x160\x14\x06\x08+\x06\x01'
            b'\x05\x05\x07\x03\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x02'
        )
