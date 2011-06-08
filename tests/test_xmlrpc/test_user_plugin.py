# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
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
Test the `ipalib/plugins/user.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid


user_memberof = (u'cn=ipausers,cn=groups,cn=accounts,%s' % api.env.basedn,)
user1=u'tuser1'
user2=u'tuser2'
renameduser1=u'tuser'
group1=u'group1'

invaliduser1=u'+tuser1'
invaliduser2=u'tuser1234567890123456789012345678901234567890'


class test_user(Declarative):

    cleanup_commands = [
        ('user_del', [user1, user2], {}),
        ('group_del', [group1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % user1,
            command=('user_show', [user1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % user1,
            command=('user_mod', [user1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % user1,
            command=('user_del', [user1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to rename non-existent %r' % user1,
            command=('user_mod', [user1], dict(setattr=u'uid=tuser')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
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
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % user1,
            command=(
                'user_show', [user1], {}
            ),
            expected=dict(
                result=dict(
                    dn=u'uid=tuser1,cn=users,cn=accounts,%s' % api.env.basedn,
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=[u'False'],
                ),
                value=user1,
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r with all=True' % user1,
            command=(
                'user_find', [user1], {'all': True}
            ),
            expected=dict(
                result=[
                    {
                        'dn': u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                        'cn': [u'Test User1'],
                        'gecos': [u'Test User1'],
                        'givenname': [u'Test'],
                        'homedirectory': [u'/home/tuser1'],
                        'krbprincipalname': [u'tuser1@' + api.env.realm],
                        'loginshell': [u'/bin/sh'],
                        'memberof_group': [u'ipausers'],
                        'objectclass': objectclasses.user + [u'mepOriginEntry'],
                        'sn': [u'User1'],
                        'uid': [user1],
                        'uidnumber': [fuzzy_digits],
                        'gidnumber': [fuzzy_digits],
                        'ipauniqueid': [fuzzy_uuid],
                        'mepmanagedentry': [u'cn=%s,cn=groups,cn=accounts,%s' % (user1, api.env.basedn)],
                        'krbpwdpolicyreference': [u'cn=global_policy,cn=%s,cn=kerberos,%s' % (api.env.realm, api.env.basedn)],
                        'nsaccountlock': [u'False'],
                        'displayname': [u'Test User1'],
                        'cn': [u'Test User1'],
                        'initials': [u'TU'],
                    },
                ],
                summary=u'1 user matched',
                count=1, truncated=False,
            ),
        ),


        dict(
            desc='Search for %r with minimal attributes' % user1,
            command=(
                'user_find', [user1], {}
            ),
            expected=dict(
                result=[
                    dict(
                        dn=u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                        givenname=[u'Test'],
                        homedirectory=[u'/home/tuser1'],
                        loginshell=[u'/bin/sh'],
                        sn=[u'User1'],
                        uid=[user1],
                        nsaccountlock=[u'False'],
                        uidnumber=[fuzzy_digits],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),


        dict(
            desc='Search for all users',
            command=(
                'user_find', [], {}
            ),
            expected=dict(
                result=[
                    dict(
                        dn=u'uid=admin,cn=users,cn=accounts,' + api.env.basedn,
                        homedirectory=[u'/home/admin'],
                        loginshell=[u'/bin/bash'],
                        sn=[u'Administrator'],
                        uid=[u'admin'],
                        nsaccountlock=[u'False'],
                        uidnumber=[fuzzy_digits],
                        gidnumber=[fuzzy_digits],
                    ),
                    dict(
                        dn=u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                        givenname=[u'Test'],
                        homedirectory=[u'/home/tuser1'],
                        loginshell=[u'/bin/sh'],
                        sn=[u'User1'],
                        uid=[user1],
                        nsaccountlock=[u'False'],
                        uidnumber=[fuzzy_digits],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'2 users matched',
                count=2,
                truncated=False,
            ),
        ),


        dict(
            desc='Search for all users with a limit of 1',
            command=(
                'user_find', [], dict(sizelimit=1,),
            ),
            expected=dict(
                result=[
                    dict(
                        dn=u'uid=admin,cn=users,cn=accounts,' + api.env.basedn,
                        homedirectory=[u'/home/admin'],
                        loginshell=[u'/bin/bash'],
                        sn=[u'Administrator'],
                        uid=[u'admin'],
                        nsaccountlock=[u'False'],
                        uidnumber=[fuzzy_digits],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'1 user matched',
                count=1,
                truncated=True,
            ),
        ),


        dict(
            desc='Disable %r' % user1,
            command=(
                'user_disable', [user1], {}
            ),
            expected=dict(
                result=True,
                value=user1,
                summary=u'Disabled user account "tuser1"',
            ),
        ),


        dict(
            desc='Enable %r'  % user1,
            command=(
                'user_enable', [user1], {}
            ),
            expected=dict(
                result=True,
                value=user1,
                summary=u'Enabled user account "tuser1"',
            ),
        ),


        dict(
            desc='Update %r' % user1,
            command=(
                'user_mod', [user1], dict(givenname=u'Finkle')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=[u'False'],
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Try updating the krb ticket policy of %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'krbmaxticketlife=88000')
            ),
            expected=errors.ObjectclassViolation(info='attribute "krbmaxticketlife" not allowed'),
        ),


        dict(
            desc='Retrieve %r to verify update' % user1,
            command=('user_show', [user1], {}),
            expected=dict(
                result=dict(
                    dn=u'uid=tuser1,cn=users,cn=accounts,%s' % api.env.basedn,
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=[u'False'],
                ),
                summary=None,
                value=user1,
            ),

        ),


        dict(
            desc='Rename %r' % user1,
            command=('user_mod', [user1], dict(setattr=u'uid=%s' % renameduser1)),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[renameduser1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=[u'False'],
                ),
                summary=u'Modified user "%s"' % user1,
                value=user1,
            ),
        ),


        dict(
            desc='Rename %r to same value' % renameduser1,
            command=('user_mod', [renameduser1], dict(setattr=u'uid=%s' % renameduser1)),
            expected=errors.EmptyModlist(),
        ),


        dict(
            desc='Rename back %r' % renameduser1,
            command=('user_mod', [renameduser1], dict(setattr=u'uid=%s' % user1)),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=[u'False'],
                ),
                summary=u'Modified user "%s"' % renameduser1,
                value=renameduser1,
            ),
        ),


        dict(
            desc='Delete %r' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Try to delete non-existent %r' % user1,
            command=('user_del', [user1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create user %r with krb ticket policy' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                setattr=u'krbmaxticketlife=88000')
            ),
            expected=errors.ObjectclassViolation(info='attribute "krbmaxticketlife" not allowed'),
        ),



        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
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
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Create %r' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "tuser2"',
                result=dict(
                    gecos=[u'Test User2'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser2'],
                    krbprincipalname=[u'tuser2@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User2'],
                    uid=[user2],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    displayname=[u'Test User2'],
                    cn=[u'Test User2'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=tuser2,cn=users,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Make non-existent %r the manager of %r' % (renameduser1, user2),
            command=('user_mod', [user2], dict(manager=renameduser1)),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Make %r the manager of %r' % (user1, user2),
            command=('user_mod', [user2], dict(manager=user1)),
            expected=dict(
                result=dict(
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser2'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User2'],
                    uid=[user2],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=[u'False'],
                    manager=[user1],
                ),
                summary=u'Modified user "%s"' % user2,
                value=user2,
            ),
        ),


        dict(
            desc='Delete %r and %r at the same time' % (user1, user2),
            command=('user_del', [user1, user2], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "tuser1,tuser2"',
                value=u','.join((user1, user2)),
            ),
        ),

        dict(
            desc='Try to retrieve non-existent %r' % user1,
            command=('user_show', [user1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % user1,
            command=('user_mod', [user1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Test an invalid login name %r' % invaliduser1,
            command=('user_add', [invaliduser1], dict(givenname=u'Test', sn=u'User1')),
            expected=errors.ValidationError(name='uid', error='may only include letters, numbers, _, -, . and $'),
        ),


        dict(
            desc='Test a login name that is too long %r' % invaliduser2,
            command=('user_add', [invaliduser2], dict(givenname=u'Test', sn=u'User1')),
            expected=errors.ValidationError(name='uid', error='can be at most 33 characters'),
        ),

        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'cn=%s,cn=groups,cn=accounts,%s' % (group1, api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Try to user %r where the managed group exists' % group1,
            command=(
                'user_add', [group1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=errors.ManagedGroupExistsError(group=group1)
        ),


        dict(
            desc='Create %r with a full address' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                street=u'123 Maple Rd', l=u'Anytown', st=u'MD',
                telephonenumber=u'410-555-1212', postalcode=u'01234-5678')
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
                    street=[u'123 Maple Rd'],
                    l=[u'Anytown'],
                    st=[u'MD'],
                    postalcode=[u'01234-5678'],
                    telephonenumber=[u'410-555-1212'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Delete %r' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "tuser1"',
                value=user1,
            ),
        ),


    ]
