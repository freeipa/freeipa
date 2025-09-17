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
from binascii import hexlify
from configparser import RawConfigParser
import datetime
from io import StringIO
import os
import pickle

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

v1_cert = b'''\
-----BEGIN CERTIFICATE-----
MIICwTCCAakCFG3lgHmtal7cilKoevNM/kD4gIToMA0GCSqGSIb3DQEBCwUAMB8x
HTAbBgNVBAMMFEV4YW1wbGUtVGVzdC1DQS0xMTg4MB4XDTIxMDYxMTE5NTgwNVoX
DTIxMDYxMjE5NTgwNVowGzEZMBcGA1UEAwwQaXBhLmV4YW1wbGUudGVzdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALsi+qZj7MB/okR4QFUYBHgLyFXr
TVd4ENDYERPhHddMkShWsAD6jG7bo/fvrWdaVKdoawghQZymI0o7VVwwuu5+EVA+
gp/vKQM+QiF2fnbprLKVdZHexqdCyo0lMSGDeSobg3iH8iHiq4StYkGyXuUzcbgf
6avajlASGC7b4W7RahTION+GJFrP/eW392Oceu6idY6rl3Joyo9SY+zX+pAR0tDC
+ixaYWkk9UxVuh4ObRToNLlHsnBWs3D6eZUiwBoX5QALWxwtdmsofwEOg3D+a2/h
RihBnZzghQUOf9pjcu/jdgUzd0fsH9FpZVad3HjQmGq2Vgy/rT6STG9ojecCAwEA
ATANBgkqhkiG9w0BAQsFAAOCAQEAMdB8pCPqEsJY5bnJNdr6EXdEIHk/l2P8tWJs
wlpdAcOm5NfeZkOkGVYC4HTPNkMQ+K7K7VqHNT7hDjdNS0Gp/LVoHxBrQPAgsM7I
RTZteGkCqIEBUxXvX2hKnMtuuAe9ljYlVF1P+WsV7qXP/M7RsWb2d+9ubA28mYD/
lhW/TB0/2EzP6QuiMh7bURIoQWw/733cfMIoP7XRVGn5Ux2z+o2hl5oOjHl7KBDa
/6PWd4wOMU/cY2fOPPJQ7eSGJh4VCe64au3S6zAtoTE8XXweo/cDD70NZnmwdeGQ
bswNlxWfohaW0FzTRfTMbIrwoUCWil/Uw2kBYnld15gwzuLDNQ==
-----END CERTIFICATE-----
'''

# Generated by moving the date forward 20 years and running
# certutil -S -d . -x -n cacert -s 'CN=Authority,O=EXAMPLE', \
# -t CT,CT,CT -m 1 -v 1200 -z /etc/group --keyUsage certSigning -2
#
# The answers are Y, 0, Y for CA, 0 pathlen, Y critical
future_crt = b'''\
-----BEGIN CERTIFICATE-----
MIIC7DCCAdSgAwIBAgIBATANBgkqhkiG9w0BAQsFADAmMRAwDgYDVQQKEwdFWEFN
UExFMRIwEAYDVQQDEwlBdXRob3JpdHkwIBcNNDUwODEzMjAzODM1WhgPMjE0NTA4
MTMyMDM4MzVaMCYxEDAOBgNVBAoTB0VYQU1QTEUxEjAQBgNVBAMTCUF1dGhvcml0
eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANEoViGF+AZPbyFuPVcv
IbORShWy0iIPCTw+mdxTp+w3g3wzCQNQP1d0y8kI4xHqm3PTmVf0LdGwAhgKpeTu
CdR97scvjGDNCa8pluQ1kmal2rkSeKYkVEw4BwO0RfBPYj3WIkamLIHcFapD97C3
M2UptAUj6wCpRzRmFG6H2vgujcZZ/J4P5C97sxPa9H8BRYjEPnIXRsmKOof9EM/Q
u/haBJnq27ajSLO+Sz0J0dKG1+aZj0tJw4dWsjdyHQ1S5JBI6xdvOFGmws6XRkgp
9Mr7MS4j9xuNk5tMucP2rsi++wju7hrhaWfqfcfQFf+gSCT3l0FnoT5n0tPEjEiP
1uMCAwEAAaMjMCEwEgYDVR0TAQH/BAgwBgEB/wIBADALBgNVHQ8EBAMCAgQwDQYJ
KoZIhvcNAQELBQADggEBAC/UO/COTCIdA+A7m6YGCcPcdtgvMOQVfKtq5UYAaG/i
zE09mGQqMgiGJh7PWTKT7R6Q9caFFHBnTy2mUkvV0O7xHtKSVyMlkmQ9+ga0jq+D
5uKAKZLrefC+pbjIIgunHTOaSFfggT9Z+i3IP2M1JyA0zMrcRQIM2OyDdn8F4/k5
VegTAUP/W/WgMC6WrvLhKCQqQORPt6zbvuK0GvQXSBTRgG+ctX4N1LaLhv8lF6kL
dyVGK1EGi9Geu5HHfrZTHx6qLgXKD1KbfZVdMtX90vTO/ISXOhnmRzC7EqLi9YEJ
noLqHv5DUjSOIO3gMKTBImvUNg88hPp7zE/3//uSvXc=
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

        not_before = datetime.datetime(2010, 6, 25, 13, 0, 42, 0,
                                       datetime.timezone.utc)
        not_after = datetime.datetime(2015, 6, 25, 13, 0, 42, 0,
                                      datetime.timezone.utc)
        cert = x509.load_pem_x509_certificate(goodcert_headers)

        assert DN(cert.subject) == DN(('CN', 'ipa.example.com'), ('O', 'IPA'))
        assert DN(cert.issuer) == DN(('CN', 'IPA Test Certificate Authority'))
        assert cert.serial_number == 1093
        assert cert.not_valid_before == not_before
        assert cert.not_valid_after == not_after
        assert cert.not_valid_before_utc == not_before
        assert cert.not_valid_after_utc == not_after
        assert cert.san_general_names == []
        assert cert.san_a_label_dns_names == []
        assert cert.extended_key_usage == {'1.3.6.1.5.5.7.3.1'}
        assert cert.extended_key_usage_bytes == (
            b'0\x16\x06\x03U\x1d%\x01\x01\xff\x04\x0c0\n\x06\x08'
            b'+\x06\x01\x05\x05\x07\x03\x01'
        )

    def test_cert_with_timezone(self):
        """
        Test the not_before and not_after values in a diffent timezone

        Test for https://pagure.io/freeipa/issue/9462
        """
        # Store initial timezone, then set to New York
        tz = os.environ.get('TZ', None)
        os.environ['TZ'] = 'America/New_York'
        # Load the cert, extract not before and not after
        cert = x509.load_pem_x509_certificate(goodcert_headers)
        not_before = datetime.datetime(2010, 6, 25, 13, 0, 42, 0,
                                       datetime.timezone.utc)
        not_after = datetime.datetime(2015, 6, 25, 13, 0, 42, 0,
                                      datetime.timezone.utc)
        # Reset timezone to previous value
        if tz:
            os.environ['TZ'] = tz
        else:
            os.environ.pop('TZ', None)
        # ensure the timezone doesn't mess with not_before and not_after
        assert cert.not_valid_before == not_before
        assert cert.not_valid_after == not_after
        assert cert.not_valid_before_utc == not_before
        assert cert.not_valid_after_utc == not_after

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
        not_before = datetime.datetime(2018, 7, 25, 5, 36, 59, 0,
                                       datetime.timezone.utc)
        not_after = datetime.datetime(2018, 10, 23, 5, 36, 59, 0,
                                      datetime.timezone.utc)
        assert cert.not_valid_before == not_before
        assert cert.not_valid_after == not_after
        assert cert.not_valid_before_utc == not_before
        assert cert.not_valid_after_utc == not_after
        assert cert.san_general_names == [DNSName('ipa.demo1.freeipa.org')]
        assert cert.san_a_label_dns_names == ['ipa.demo1.freeipa.org']
        assert cert.extended_key_usage == {
            '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'
        }
        assert cert.extended_key_usage_bytes == (
            b'0 \x06\x03U\x1d%\x01\x01\xff\x04\x160\x14\x06\x08+\x06\x01'
            b'\x05\x05\x07\x03\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x02'
        )

    def test_x509_v1_cert(self):
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(v1_cert)

    def test_future_certificate_dates(self):
        """
        Issue a certificate that is valid after 2038 that will be valid
        after 2016 and validate that it is readable by ipalib.x509.py.
        """
        cert = x509.load_pem_x509_certificate(future_crt)
        assert cert.not_valid_before.year > 2038
        assert cert.not_valid_after.year > 2106


class test_ExternalCAProfile:
    def test_MSCSTemplateV1_good(self):
        o = x509.MSCSTemplateV1("MySubCA")
        assert hexlify(o.get_ext_data()) == b'1e0e004d007900530075006200430041'

    def test_MSCSTemplateV1_bad(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV1("MySubCA:1")

    def test_MSCSTemplateV1_pickle_roundtrip(self):
        o = x509.MSCSTemplateV1("MySubCA")
        s = pickle.dumps(o)
        assert o.get_ext_data() == pickle.loads(s).get_ext_data()

    def test_MSCSTemplateV2_too_few_parts(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4")

    def test_MSCSTemplateV2_too_many_parts(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:100:200:300")

    def test_MSCSTemplateV2_bad_oid(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("not_an_oid:1")

    def test_MSCSTemplateV2_non_numeric_major_version(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:major:200")

    def test_MSCSTemplateV2_non_numeric_minor_version(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:100:minor")

    def test_MSCSTemplateV2_major_version_lt_zero(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:-1:200")

    def test_MSCSTemplateV2_minor_version_lt_zero(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:100:-1")

    def test_MSCSTemplateV2_major_version_gt_max(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:4294967296:200")

    def test_MSCSTemplateV2_minor_version_gt_max(self):
        with pytest.raises(ValueError):
            x509.MSCSTemplateV2("1.2.3.4:100:4294967296")

    def test_MSCSTemplateV2_good_major(self):
        o = x509.MSCSTemplateV2("1.2.3.4:4294967295")
        assert hexlify(o.get_ext_data()) == b'300c06032a0304020500ffffffff'

    def test_MSCSTemplateV2_good_major_minor(self):
        o = x509.MSCSTemplateV2("1.2.3.4:4294967295:0")
        assert hexlify(o.get_ext_data()) \
            == b'300f06032a0304020500ffffffff020100'

    def test_MSCSTemplateV2_pickle_roundtrip(self):
        o = x509.MSCSTemplateV2("1.2.3.4:4294967295:0")
        s = pickle.dumps(o)
        assert o.get_ext_data() == pickle.loads(s).get_ext_data()

    def test_ExternalCAProfile_dispatch(self):
        """
        Test that constructing ExternalCAProfile actually returns an
        instance of the appropriate subclass.
        """
        assert isinstance(
            x509.ExternalCAProfile("MySubCA"),
            x509.MSCSTemplateV1)
        assert isinstance(
            x509.ExternalCAProfile("1.2.3.4:100"),
            x509.MSCSTemplateV2)

    def test_write_pkispawn_config_file_MSCSTemplateV1(self):
        template = x509.MSCSTemplateV1(u"SubCA")
        expected = (
            '[CA]\n'
            'pki_req_ext_oid = 1.3.6.1.4.1.311.20.2\n'
            'pki_req_ext_data = 1e0a00530075006200430041\n\n'
        )
        self._test_write_pkispawn_config_file(template, expected)

    def test_write_pkispawn_config_file_MSCSTemplateV2(self):
        template = x509.MSCSTemplateV2(u"1.2.3.4:4294967295")
        expected = (
            '[CA]\n'
            'pki_req_ext_oid = 1.3.6.1.4.1.311.21.7\n'
            'pki_req_ext_data = 300c06032a0304020500ffffffff\n\n'
        )
        self._test_write_pkispawn_config_file(template, expected)

    def _test_write_pkispawn_config_file(self, template, expected):
        """
        Test that the values we read from an ExternalCAProfile
        object can be used to produce a reasonable-looking pkispawn
        configuration.
        """
        config = RawConfigParser()
        config.optionxform = str
        config.add_section("CA")
        config.set("CA", "pki_req_ext_oid", template.ext_oid)
        config.set("CA", "pki_req_ext_data",
                   hexlify(template.get_ext_data()).decode('ascii'))
        out = StringIO()
        config.write(out)
        assert out.getvalue() == expected
