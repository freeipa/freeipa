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
                     dict(krbauthindmaxticketlife_pkinit=3600)),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    krbmaxticketlife=[u'3600'],
                    krbauthindmaxticketlife_pkinit=[u'3600'],
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
