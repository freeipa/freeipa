# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2011  Red Hat
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
Test kerberos ticket policy
"""

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
from ipapython.dn import DN
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
import pytest

user1 = u'tuser1'

invalid_values = [(u'abc123', 'must be an integer'),
                  (u'2147483648', 'can be at most 2147483647'),
                  (u'0', 'must be at least 1'),
                  (u'-1', 'must be at least 1')]
parameters = [('krbauthindmaxrenewableage_radius', 'radius_maxrenew'),
              ('krbauthindmaxticketlife_radius', 'radius_maxlife'),
              ('krbauthindmaxrenewableage_pkinit', 'pkinit_maxrenew'),
              ('krbauthindmaxticketlife_pkinit', 'pkinit_maxlife'),
              ('krbauthindmaxrenewableage_otp', 'otp_maxrenew'),
              ('krbauthindmaxticketlife_otp', 'otp_maxlife'),
              ('krbauthindmaxrenewableage_hardened', 'hardened_maxrenew'),
              ('krbauthindmaxticketlife_hardened', 'hardened_maxlife'),
              ]


def create_dict(desc, param, param_name, value, error):
    cmd_args = dict()
    cmd_args[param] = value
    if value != u'abc123':
        return dict(desc=desc, command=('krbtpolicy_mod', [user1], cmd_args),
                    expected=errors.ValidationError(name=param_name,
                                                    error=error))
    else:
        return dict(desc=desc, command=('krbtpolicy_mod', [user1], cmd_args),
                    expected=errors.ConversionError(name=param_name,
                                                    error=error))


@pytest.mark.tier1
class test_krbtpolicy(Declarative):
    cleanup_commands = [
        ('user_del', [user1], {}),
        ('krbtpolicy_reset', [], {}),
    ]

    tests = [


        dict(
            desc='Reset global policy',
            command=(
                'krbtpolicy_reset', [], {}
            ),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'86400'],
                    krbmaxrenewableage=[u'604800'],
                ),
            ),
        ),


        dict(
            desc='Show global policy',
            command=(
                'krbtpolicy_show', [], {}
            ),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    dn=DN(('cn',api.env.domain),('cn','kerberos'),
                          api.env.basedn),
                    krbmaxticketlife=[u'86400'],
                    krbmaxrenewableage=[u'604800'],
                ),
            ),
        ),


        dict(
            desc='Update global policy',
            command=(
                'krbtpolicy_mod', [], dict(krbmaxticketlife=3600)
            ),
            expected=dict(
                value=None,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbmaxrenewableage=[u'604800'],
                ),
            ),
        ),


        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),


        dict(
                desc='Update user ticket policy',
            command=(
                'krbtpolicy_mod', [user1], dict(krbmaxticketlife=3600)
            ),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                ),
            ),
        ),

        dict(
            desc='Update user ticket policy for auth indicator pkinit',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxticketlife_pkinit=3800)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                ),
            ),
        ),


        dict(
            desc='Update user ticket policy for auth indicator otp',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxticketlife_otp=3700)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                ),
            ),
        ),

        dict(
            desc='Update user ticket policy for auth indicator radius',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxticketlife_radius=1)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_radius=[u'1'],
                ),
            ),
        ),

        dict(
            desc='Update user ticket policy for auth indicator hardened',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxticketlife_hardened=2147483647)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_radius=[u'1'],
                    krbauthindmaxticketlife_hardened=[u'2147483647'],
                ),
            ),
        ),

        dict(
            desc='Update maxrenew user ticket policy for '
                 'auth indicator hardened',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxrenewableage_hardened=2147483647)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_radius=[u'1'],
                    krbauthindmaxticketlife_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_hardened=[u'2147483647'],
                ),
            ),
        ),
        dict(
            desc='Update maxrenew user ticket policy for '
                 'auth indicator otp',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxrenewableage_otp=3700)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_radius=[u'1'],
                    krbauthindmaxticketlife_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_otp=[u'3700'],
                ),
            ),
        ),
        dict(
            desc='Update maxrenew user ticket policy for '
                 'auth indicator radius',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxrenewableage_radius=1)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_radius=[u'1'],
                    krbauthindmaxticketlife_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_otp=[u'3700'],
                    krbauthindmaxrenewableage_radius=[u'1'],
                ),
            ),
        ),
        dict(
            desc='Update maxrenew user ticket policy for '
                 'auth indicator pkinit',
            command=('krbtpolicy_mod', [user1],
                     dict(krbauthindmaxrenewableage_pkinit=3800)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_otp=[u'3700'],
                    krbauthindmaxticketlife_pkinit=[u'3800'],
                    krbauthindmaxticketlife_radius=[u'1'],
                    krbauthindmaxticketlife_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_hardened=[u'2147483647'],
                    krbauthindmaxrenewableage_otp=[u'3700'],
                    krbauthindmaxrenewableage_radius=[u'1'],
                    krbauthindmaxrenewableage_pkinit=[u'3800'],
                ),
            ),
        ),

        dict(
            desc='Try updating other user attribute',
            command=(
                'krbtpolicy_mod', [user1], dict(setattr=u'givenname=Pete')
            ),
            expected=errors.ObjectclassViolation(info='attribute "givenname" not allowed'),
        ),
    ]
    for (value, error) in invalid_values:
        for (param, param_name) in parameters:
            tests.append(create_dict(desc='Try updating invalid {0} with {1}'.
                                     format(param_name, value),
                                     param=param, param_name=param_name,
                                     value=value, error=error))
