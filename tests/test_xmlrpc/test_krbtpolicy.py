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
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipapython.dn import DN

user1 = u'tuser1'

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
                value=u'',
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
                value=u'',
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
                value=u'',
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
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'%s@%s' % (user1, api.env.domain)],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn','global_policy'),('cn',api.env.realm),
                                              ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=[DN(('cn',user1),('cn','groups'),('cn','accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=DN(('uid',user1),('cn','users'),('cn','accounts'), api.env.basedn)
                ),
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
            desc='Try updating other user attribute',
            command=(
                'krbtpolicy_mod', [user1], dict(setattr=u'givenname=Pete')
            ),
            expected=errors.ObjectclassViolation(info='attribute "givenname" not allowed'),
        ),


    ]
