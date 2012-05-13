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
Test the modlist replace logic. Some attributes require a MOD_REPLACE
while others are fine using ADD/DELETE.

Note that member management in other tests also exercises the
gen_modlist code.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipapython.dn import DN

user1=u'tuser1'


class test_replace(Declarative):

    cleanup_commands = [
        ('user_del', [user1], {}),
    ]

    tests = [

        dict(
            desc='Create %r with 2 e-mail accounts' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                    mail=[u'test1@example.com', u'test2@example.com'])
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "tuser1"',
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
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    mail=[u'test1@example.com', u'test2@example.com'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn','global_policy'),('cn',api.env.realm),('cn','kerberos'),
                                              api.env.basedn)],
                    mepmanagedentry=[DN(('cn',user1),('cn','groups'),('cn','accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                          api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Drop one e-mail account, add another to %r' % user1,
            command=(
                'user_mod', [user1], dict(mail=[u'test1@example.com', u'test3@example.com'])
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test1@example.com', u'test3@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Set mail to a new single value %r' % user1,
            command=(
                'user_mod', [user1], dict(mail=u'test4@example.com')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test4@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Set mail to three new values %r' % user1,
            command=(
                'user_mod', [user1], dict(mail=[u'test5@example.com', u'test6@example.com', u'test7@example.com'])
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test6@example.com', u'test7@example.com', u'test5@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Remove all mail values %r' % user1,
            command=(
                'user_mod', [user1], dict(mail=u'')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Ensure single-value mods work too, replace initials %r' % user1,
            command=(
                'user_mod', [user1], dict(initials=u'ABC')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    initials=[u'ABC'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Drop a single-value attribute %r' % user1,
            command=(
                'user_mod', [user1], dict(initials=u'')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),

    ]
