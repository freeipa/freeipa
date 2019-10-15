# Authors:
#   Endi S. Dewata <edewata@redhat.com>
#
# Copyright (C) 2015  Red Hat
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
Test the `ipaserver/plugins/vault.py` module.
"""

import pytest
import six

from ipalib import api
from ipatests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_bytes


vault_name = u'test_vault'
service_name = u'HTTP/server.example.com'
user_name = u'testuser'

standard_vault_name = u'standard_test_vault'
symmetric_vault_name = u'symmetric_test_vault'
asymmetric_vault_name = u'asymmetric_test_vault'

# binary data from \x00 to \xff
if six.PY2:
    secret = b''.join(chr(c) for c in range(0, 256))
else:
    secret = bytes(range(0, 256))

password = u'password'
other_password = u'other_password'

public_key = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT61EFxUOQgCJdM0tmw/
pRRPDPGchTClnU1eBtiQD3ItKYf1+weMGwGOSJXPtkto7NlE7Qs8WHAr0UjyeBDe
k/zeB6nSVdk47OdaW1AHrJL+44r238Jbm/+7VO5lTu6Z4N5p0VqoWNLi0Uh/CkqB
tsxXaaAgjMp0AGq2U/aO/akeEYWQOYIdqUKVgAEKX5MmIA8tmbmoYIQ+B4Q3vX7N
otG4eR6c2o9Fyjd+M4Gai5Ce0fSrigRvxAYi8xpRkQ5yQn5gf4WVrn+UKTfOIjLO
pVThop+Xivcre3SpI0kt6oZPhBw9i8gbMnqifVmGFpVdhq+QVBqp+MVJvTbhRPG6
3wIDAQAB
-----END PUBLIC KEY-----
"""

private_key = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAnT61EFxUOQgCJdM0tmw/pRRPDPGchTClnU1eBtiQD3ItKYf1
+weMGwGOSJXPtkto7NlE7Qs8WHAr0UjyeBDek/zeB6nSVdk47OdaW1AHrJL+44r2
38Jbm/+7VO5lTu6Z4N5p0VqoWNLi0Uh/CkqBtsxXaaAgjMp0AGq2U/aO/akeEYWQ
OYIdqUKVgAEKX5MmIA8tmbmoYIQ+B4Q3vX7NotG4eR6c2o9Fyjd+M4Gai5Ce0fSr
igRvxAYi8xpRkQ5yQn5gf4WVrn+UKTfOIjLOpVThop+Xivcre3SpI0kt6oZPhBw9
i8gbMnqifVmGFpVdhq+QVBqp+MVJvTbhRPG63wIDAQABAoIBAQCD2bXnfxPcMnvi
jaPwpvoDCPF0EBBHmk/0g5ApO2Qon3uBDJFUqbJwXrCY6o2d9MOJfnGONlKmcYA8
X+d4h+SqwGjIkjxdYeSauS+Jy6Rzr1ptH/P8EjPQrfG9uJxYQDflV3nxYwwwVrx7
8kccMPdteRB+8Bb7FzOHufMimmayCNFETnVT5CKH2PrYoPB+fr0itCipWOenDp33
e73OV+K9U3rclmtHaoRxGohqByKfQRUkipjw4m+T3qfZZc5eN77RGW8J+oL1GVom
fwtiH7N1HVte0Dmd13nhiASg355kjqRPcIMPsRHvXkOpgg5HRUTKG5elqAyvvm27
Fzj1YdeRAoGBAMnE61+FYh8qCyEGe8r6RGjO8iuoyk1t+0gBWbmILLBiRnj4K8Tc
k7HBG/pg3XCNbCuRwiLg8tk3VAAXzn6o+IJr3QnKbNCGa1lKfYU4mt11sBEyuL5V
NpZcZ8IiPhMlGyDA9cFbTMKOE08RqbOIdxOmTizFt0R5sYZAwOjEvBIZAoGBAMeC
N/P0bdrScFZGeS51wEdiWme/CO0IyGoqU6saI8L0dbmMJquiaAeIEjIKLqxH1RON
axhsyk97e0PCcc5QK62Utf50UUAbL/v7CpIG+qdSRYDO4bVHSCkwF32N3pYh/iVU
EsEBEkZiJi0dWa/0asDbsACutxcHda3RI5pi7oO3AoGAcbGNs/CUHt1xEfX2UaT+
YVSjb2iYPlNH8gYYygvqqqVl8opdF3v3mYUoP8jPXrnCBzcF/uNk1HNx2O+RQxvx
lIQ1NGwlLsdfvBvWaPhBg6LqSHadVVrs/IMrUGA9PEp/Y9B3arIIqeSnCrn4Nxsh
higDCwWKRIKSPwVD7qXVGBkCgYEAu5/CASIRIeYgEXMLSd8hKcDcJo8o1MoauIT/
1Hyrvw9pm0qrn2QHk3WrLvYWeJzBTTcEzZ6aEG+fN9UodA8/VGnzUc6QDsrCsKWh
hj0cArlDdeSZrYLQ4TNCFCiUePqU6QQM8weP6TMqlejxTKF+t8qi1bF5rCWuzP1P
D0UU7DcCgYAUvmEGckugS+FTatop8S/rmkcQ4Bf5M/YCZfsySavucDiHcBt0QtXt
Swh0XdDsYS3W1yj2XqqsQ7R58KNaffCHjjulWFzb5IiuSvvdxzWtiXHisOpO36MJ
kUlCMj24a8XsShzYTWBIyW2ngvGe3pQ9PfjkUdm0LGZjYITCBvgOKw==
-----END RSA PRIVATE KEY-----
"""

other_public_key = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7E/QLVyKjrgDctZ50U7
rmtL7Ks1QLoccp9WvZJ6WI1rYd0fX5FySS4dI6QTNZc6qww8NeNuZtkoxT9m1wkk
Rl/3wK7fWNLenH/+VHOaTQc20exg7ztfsO7JIsmKmigtticdR5C4jLfjcOp+WjLH
w3zrmrO5SIZ8njxMoDcQJa2vu/t281U/I7ti8ue09FSitIECU05vgmPS+MnXR8HK
PxXqrNkjl29mXNbPiByWwlse3Prwved9I7fwgpiHJqUBFudD/0tZ4DWyLG7t9wM1
O8gRaRg1r+ENVpmMSvXo4+8+bR3rEYddD5zU7nKXafeuthXlXplae/8uZmCiSI63
TwIDAQAB
-----END PUBLIC KEY-----
"""

other_private_key = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAv7E/QLVyKjrgDctZ50U7rmtL7Ks1QLoccp9WvZJ6WI1rYd0f
X5FySS4dI6QTNZc6qww8NeNuZtkoxT9m1wkkRl/3wK7fWNLenH/+VHOaTQc20exg
7ztfsO7JIsmKmigtticdR5C4jLfjcOp+WjLHw3zrmrO5SIZ8njxMoDcQJa2vu/t2
81U/I7ti8ue09FSitIECU05vgmPS+MnXR8HKPxXqrNkjl29mXNbPiByWwlse3Prw
ved9I7fwgpiHJqUBFudD/0tZ4DWyLG7t9wM1O8gRaRg1r+ENVpmMSvXo4+8+bR3r
EYddD5zU7nKXafeuthXlXplae/8uZmCiSI63TwIDAQABAoIBAQCA+0GFR9F+isjx
Xy+qBpKmxLl8kKKvX8r+cSpLOkEqTlW/rqqKgnI0vVuL/L2UJKKsLvpghBxoBZyC
RCvtatBGrhIlS0UrHg/9m73Ek1hylfUUAQokTn4PrkwWJSgmm/xOATmZSs5ymNTn
yFCmXl69sdNR77YvD5bQXeBtOT+bKXy7yQ1TmYPwwSjL+WSlMV6ZfE3HNVmxPTpk
CTFS638cJblWk9MUIy8HIlhu6If2P4RnHr7ZGGivhREayvs0zXcAfqhIyFHruxSE
yYnmqH9paWjv5mP3YyLoKr+NUvvxnBr/9wCTt0TKgG8G6rpkHuPDLQni9wUGnew8
QdMgFEohAoGBAPH4vaVB5gDVfvIqwJBsBLHpPq72GvxjrM/exD0jIIpXZxz9gCql
CmC5b1RS1uy8PMoc/RO4CE7UTLaTesciP6LjTD1RhH3rLLJO8/iVC1RXgMrCLHLm
ZQnDhIQGGNQxpvBjQy5ZOWat2dFxYhHN630IFPOtrWsOmJ5HsL1JrjzxAoGBAMrO
R1zNwQ42VbJS6AFshZVjmUV2h3REGh4zG/9IqL0Hz493hyCTGoDPLLXIbtkqNqzQ
XibSZ9RMVPKKTiNQTx91DTgh4Anz8xUr84tA2iAf3ayNWKi3Y3GhmP2EWp1qYeom
kV8Uq0lt4dHZuEo3LuqvbtbzlF9qUXqKS5qy6Tg/AoGBAKCp02o2HjzxhS/QeTmr
r1ZeE7PiTzrECAuh01TwzPtuW1XhcEdgfEqK9cPcmT5pIkflBZkhOcr1pdYYiI5O
TEigeY/BX6KoE251hALLG9GtpCN82DyWhAH+oy9ySOwj5793eTT+I2HtD1LE4SQH
QVQsmJTP/fS2pVl7KnwUvy9RAoGBAKzo2qchNewsHzx+uxgbsnkABfnXaP2T4sDE
yqYJCPTB6BFl02vOf9Y6zN/gF8JH333P2bY3xhaXTgXMLXqmSg+D+NVW7HEP8Lyo
UGj1zgN9p74qdODEGqETKiFb6vYzcW/1mhP6x18/tDz658k+611kXZge7O288+MK
bhNjXrx5AoGBAMox25PcxVgOjCd9+LdUcIOG6LQ971eCH1NKL9YAekICnwMrStbK
veCYju6ok4ZWnMiH8MR1jgC39RWtjJZwynCuPXUP2/vZkoVf1tCZyz7dSm8TdS/2
5NdOHVy7+NQcEPSm7/FmXdpcR9ZSGAuxMBfnEUibdyz5LdJGnFUN/+HS
-----END RSA PRIVATE KEY-----
"""


@pytest.mark.tier1
class test_vault_plugin(Declarative):
    @pytest.fixture(autouse=True, scope="class")
    def vault_plugin_setup(self, declarative_setup):
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not api.Command.kra_is_enabled()['result']:
            pytest.skip('KRA service is not enabled')

    cleanup_commands = [
        ('vault_del', [vault_name], {'continue': True}),
        ('vault_del', [vault_name], {
            'service': service_name,
            'continue': True
        }),
        ('vault_del', [vault_name], {'shared': True, 'continue': True}),
        ('vault_del', [vault_name], {'username': user_name, 'continue': True}),
        ('vault_del', [standard_vault_name], {'continue': True}),
        ('vault_del', [symmetric_vault_name], {'continue': True}),
        ('vault_del', [asymmetric_vault_name], {'continue': True}),
    ]

    tests = [

        {
            'desc': 'Create private vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'ipavaulttype': u'standard',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': 'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,cn=kra,%s'
                          % (vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Find private vaults',
            'command': (
                'vault_find',
                [],
                {},
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,cn=kra,%s'
                              % (vault_name, api.env.basedn),
                        'cn': [vault_name],
                        'ipavaulttype': [u'standard'],
                        'username': u'admin',
                    },
                ],
            },
        },

        {
            'desc': 'Show private vault',
            'command': (
                'vault_show',
                [vault_name],
                {},
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,cn=kra,%s'
                          % (vault_name, api.env.basedn),
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Modify private vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Delete private vault',
            'command': (
                'vault_del',
                [vault_name],
                {},
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create service vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'ipavaulttype': u'standard',
                    'service': service_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=%s@%s,cn=services,cn=vaults,cn=kra,%s'
                          % (vault_name, service_name, api.env.realm,
                             api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'service': "%s@%s" % (service_name, api.env.realm),
                },
            },
        },

        {
            'desc': 'Find service vaults',
            'command': (
                'vault_find',
                [],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=%s@%s,cn=services,cn=vaults,cn=kra,%s'
                              % (vault_name, service_name, api.env.realm,
                                 api.env.basedn),
                        'cn': [vault_name],
                        'ipavaulttype': [u'standard'],
                        'service': '%s@%s' % (service_name, api.env.realm),
                    },
                ],
            },
        },

        {
            'desc': 'Show service vault',
            'command': (
                'vault_show',
                [vault_name],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=%s@%s,cn=services,cn=vaults,cn=kra,%s'
                          % (vault_name, service_name, api.env.realm,
                             api.env.basedn),
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'service': "%s@%s" % (service_name, api.env.realm),
                },
            },
        },

        {
            'desc': 'Modify service vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'service': service_name,
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'service': "%s@%s" % (service_name, api.env.realm),
                },
            },
        },

        {
            'desc': 'Delete service vault',
            'command': (
                'vault_del',
                [vault_name],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create shared vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'ipavaulttype': u'standard',
                    'shared': True
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=shared,cn=vaults,cn=kra,%s'
                          % (vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'shared': True,
                },
            },
        },

        {
            'desc': 'Find shared vaults',
            'command': (
                'vault_find',
                [],
                {
                    'shared': True
                },
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=shared,cn=vaults,cn=kra,%s'
                              % (vault_name, api.env.basedn),
                        'cn': [vault_name],
                        'ipavaulttype': [u'standard'],
                        'shared': True,
                    },
                ],
            },
        },

        {
            'desc': 'Show shared vault',
            'command': (
                'vault_show',
                [vault_name],
                {
                    'shared': True
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=shared,cn=vaults,cn=kra,%s'
                          % (vault_name, api.env.basedn),
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'shared': True,
                },
            },
        },

        {
            'desc': 'Modify shared vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'shared': True,
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'shared': True,
                },
            },
        },

        {
            'desc': 'Delete shared vault',
            'command': (
                'vault_del',
                [vault_name],
                {
                    'shared': True
                },
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create user vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'ipavaulttype': u'standard',
                    'username': user_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=%s,cn=users,cn=vaults,cn=kra,%s'
                          % (vault_name, user_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': user_name,
                },
            },
        },

        {
            'desc': 'Find user vaults',
            'command': (
                'vault_find',
                [],
                {
                    'username': user_name,
                },
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=%s,cn=users,cn=vaults,cn=kra,%s'
                              % (vault_name, user_name, api.env.basedn),
                        'cn': [vault_name],
                        'ipavaulttype': [u'standard'],
                        'username': user_name,
                    },
                ],
            },
        },

        {
            'desc': 'Show user vault',
            'command': (
                'vault_show',
                [vault_name],
                {
                    'username': user_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=%s,cn=users,cn=vaults,cn=kra,%s'
                          % (vault_name, user_name, api.env.basedn),
                    'cn': [vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': user_name,
                },
            },
        },

        {
            'desc': 'Modify user vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'username': user_name,
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': user_name,
                },
            },
        },

        {
            'desc': 'Delete user vault',
            'command': (
                'vault_del',
                [vault_name],
                {
                    'username': user_name,
                },
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create standard vault',
            'command': (
                'vault_add',
                [standard_vault_name],
                {
                    'ipavaulttype': u'standard',
                },
            ),
            'expected': {
                'value': standard_vault_name,
                'summary': 'Added vault "%s"' % standard_vault_name,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,cn=kra,%s'
                          % (standard_vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [standard_vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Archive secret into standard vault',
            'command': (
                'vault_archive',
                [standard_vault_name],
                {
                    'data': secret,
                },
            ),
            'expected': {
                'value': standard_vault_name,
                'summary': 'Archived data into vault "%s"'
                           % standard_vault_name,
                'result': {},
            },
        },

        {
            'desc': 'Retrieve secret from standard vault',
            'command': (
                'vault_retrieve',
                [standard_vault_name],
                {},
            ),
            'expected': {
                'value': standard_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % standard_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Change standard vault to symmetric vault',
            'command': (
                'vault_mod',
                [standard_vault_name],
                {
                    'ipavaulttype': u'symmetric',
                    'new_password': password,
                },
            ),
            'expected': {
                'value': standard_vault_name,
                'summary': u'Modified vault "%s"' % standard_vault_name,
                'result': {
                    'cn': [standard_vault_name],
                    'ipavaulttype': [u'symmetric'],
                    'ipavaultsalt': [fuzzy_bytes],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Retrieve secret from standard vault converted to '
                    'symmetric vault',
            'command': (
                'vault_retrieve',
                [standard_vault_name],
                {
                    'password': password,
                },
            ),
            'expected': {
                'value': standard_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % standard_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Create symmetric vault',
            'command': (
                'vault_add',
                [symmetric_vault_name],
                {
                    'ipavaulttype': u'symmetric',
                    'password': password,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': 'Added vault "%s"' % symmetric_vault_name,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,cn=kra,%s'
                          % (symmetric_vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [symmetric_vault_name],
                    'ipavaulttype': [u'symmetric'],
                    'ipavaultsalt': [fuzzy_bytes],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Archive secret into symmetric vault',
            'command': (
                'vault_archive',
                [symmetric_vault_name],
                {
                    'password': password,
                    'data': secret,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': 'Archived data into vault "%s"'
                           % symmetric_vault_name,
                'result': {},
            },
        },

        {
            'desc': 'Retrieve secret from symmetric vault',
            'command': (
                'vault_retrieve',
                [symmetric_vault_name],
                {
                    'password': password,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % symmetric_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Change symmetric vault password',
            'command': (
                'vault_mod',
                [symmetric_vault_name],
                {
                    'old_password': password,
                    'new_password': other_password,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': u'Modified vault "%s"' % symmetric_vault_name,
                'result': {
                    'cn': [symmetric_vault_name],
                    'ipavaulttype': [u'symmetric'],
                    'ipavaultsalt': [fuzzy_bytes],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Retrieve secret from symmetric vault with new password',
            'command': (
                'vault_retrieve',
                [symmetric_vault_name],
                {
                    'password': other_password,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % symmetric_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Change symmetric vault to asymmetric vault',
            'command': (
                'vault_mod',
                [symmetric_vault_name],
                {
                    'ipavaulttype': u'asymmetric',
                    'old_password': other_password,
                    'ipavaultpublickey': public_key,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': u'Modified vault "%s"' % symmetric_vault_name,
                'result': {
                    'cn': [symmetric_vault_name],
                    'ipavaulttype': [u'asymmetric'],
                    'ipavaultpublickey': [public_key],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Retrieve secret from symmetric vault converted to '
                    'asymmetric vault',
            'command': (
                'vault_retrieve',
                [symmetric_vault_name],
                {
                    'private_key': private_key,
                },
            ),
            'expected': {
                'value': symmetric_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % symmetric_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Create asymmetric vault',
            'command': (
                'vault_add',
                [asymmetric_vault_name],
                {
                    'ipavaulttype': u'asymmetric',
                    'ipavaultpublickey': public_key,
                },
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': 'Added vault "%s"' % asymmetric_vault_name,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,cn=kra,%s'
                          % (asymmetric_vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [asymmetric_vault_name],
                    'ipavaulttype': [u'asymmetric'],
                    'ipavaultpublickey': [public_key],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Archive secret into asymmetric vault',
            'command': (
                'vault_archive',
                [asymmetric_vault_name],
                {
                    'data': secret,
                },
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': 'Archived data into vault "%s"'
                           % asymmetric_vault_name,
                'result': {},
            },
        },

        {
            'desc': 'Retrieve secret from asymmetric vault',
            'command': (
                'vault_retrieve',
                [asymmetric_vault_name],
                {
                    'private_key': private_key,
                },
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % asymmetric_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Change asymmetric vault keys',
            'command': (
                'vault_mod',
                [asymmetric_vault_name],
                {
                    'private_key': private_key,
                    'ipavaultpublickey': other_public_key,
                },
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': u'Modified vault "%s"' % asymmetric_vault_name,
                'result': {
                    'cn': [asymmetric_vault_name],
                    'ipavaulttype': [u'asymmetric'],
                    'ipavaultpublickey': [other_public_key],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Retrieve secret from asymmetric vault with new keys',
            'command': (
                'vault_retrieve',
                [asymmetric_vault_name],
                {
                    'private_key': other_private_key,
                },
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % asymmetric_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

        {
            'desc': 'Change asymmetric vault to standard vault',
            'command': (
                'vault_mod',
                [asymmetric_vault_name],
                {
                    'ipavaulttype': u'standard',
                    'private_key': other_private_key,
                },
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': u'Modified vault "%s"' % asymmetric_vault_name,
                'result': {
                    'cn': [asymmetric_vault_name],
                    'ipavaulttype': [u'standard'],
                    'owner_user': [u'admin'],
                    'username': u'admin',
                },
            },
        },

        {
            'desc': 'Retrieve secret from asymmetric vault converted to '
                    'standard vault',
            'command': (
                'vault_retrieve',
                [asymmetric_vault_name],
                {},
            ),
            'expected': {
                'value': asymmetric_vault_name,
                'summary': 'Retrieved data from vault "%s"'
                           % asymmetric_vault_name,
                'result': {
                    'data': secret,
                },
            },
        },

    ]
