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
from tests.util import assert_equal, assert_not_equal
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid, fuzzy_password, fuzzy_string, fuzzy_dergeneralizedtime
from ipalib.dn import *

user1=u'tuser1'
user2=u'tuser2'
renameduser1=u'tuser'
group1=u'group1'

invaliduser1=u'+tuser1'
invaliduser2=u'tuser1234567890123456789012345678901234567890'

def upg_check(response):
    """Check that the user was assigned to the corresponding private group."""
    assert_equal(response['result']['uidnumber'],
                 response['result']['gidnumber'])
    return True

def not_upg_check(response):
    """Check that the user was not assigned to the corresponding private group."""
    assert_not_equal(response['result']['uidnumber'],
                     response['result']['gidnumber'])
    return True

class test_user(Declarative):

    cleanup_commands = [
        ('user_del', [user1, user2], {}),
        ('group_del', [group1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % user1,
            command=('user_show', [user1], {}),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to update non-existent %r' % user1,
            command=('user_mod', [user1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to delete non-existent %r' % user1,
            command=('user_del', [user1], {}),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to rename non-existent %r' % user1,
            command=('user_mod', [user1], dict(setattr=u'uid=tuser')),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
            extra_check = upg_check,
        ),


        dict(
            desc='Try to create duplicate %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=errors.DuplicateEntry(
                message=u'user with name "%s" already exists' % user1),
        ),


        dict(
            desc='Retrieve %r' % user1,
            command=(
                'user_show', [user1], {}
            ),
            expected=dict(
                result=dict(
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
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
                        'dn': lambda x: DN(x) == \
                            DN(('uid','tuser1'),('cn','users'),
                               ('cn','accounts'),api.env.basedn),
                        'cn': [u'Test User1'],
                        'gecos': [u'Test User1'],
                        'givenname': [u'Test'],
                        'homedirectory': [u'/home/tuser1'],
                        'krbprincipalname': [u'tuser1@' + api.env.realm],
                        'loginshell': [u'/bin/sh'],
                        'memberof_group': [u'ipausers'],
                        'objectclass': objectclasses.user,
                        'sn': [u'User1'],
                        'uid': [user1],
                        'uidnumber': [fuzzy_digits],
                        'gidnumber': [fuzzy_digits],
                        'ipauniqueid': [fuzzy_uuid],
                        'mepmanagedentry': lambda x: [DN(i) for i in x] == \
                            [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                                api.env.basedn)],
                        'krbpwdpolicyreference': lambda x: [DN(i) for i in x] == \
                            [DN(('cn','global_policy'),('cn',api.env.realm),
                                ('cn','kerberos'),api.env.basedn)],
                        'nsaccountlock': False,
                        'has_keytab': False,
                        'has_password': False,
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
            desc='Search for %r with pkey-only=True' % user1,
            command=(
                'user_find', [user1], {'pkey_only': True}
            ),
            expected=dict(
                result=[
                    {
                        'dn':lambda x: DN(x) == \
                                DN(('uid',user1),('cn','users'),
                                   ('cn','accounts'),api.env.basedn),
                        'uid': [user1],
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
                        dn=lambda x: DN(x) == \
                            DN(('uid','tuser1'),('cn','users'),
                               ('cn','accounts'),api.env.basedn),
                        givenname=[u'Test'],
                        homedirectory=[u'/home/tuser1'],
                        loginshell=[u'/bin/sh'],
                        sn=[u'User1'],
                        uid=[user1],
                        nsaccountlock=False,
                        has_keytab=False,
                        has_password=False,
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
                        dn=lambda x: DN(x) == \
                            DN(('uid','admin'),('cn','users'),('cn','accounts'),
                               api.env.basedn),
                        homedirectory=[u'/home/admin'],
                        loginshell=[u'/bin/bash'],
                        sn=[u'Administrator'],
                        uid=[u'admin'],
                        nsaccountlock=False,
                        has_keytab=True,
                        has_password=True,
                        uidnumber=[fuzzy_digits],
                        gidnumber=[fuzzy_digits],
                    ),
                    dict(
                        dn=lambda x: DN(x) == \
                            DN(('uid','tuser1'),('cn','users'),
                               ('cn','accounts'),api.env.basedn),
                        givenname=[u'Test'],
                        homedirectory=[u'/home/tuser1'],
                        loginshell=[u'/bin/sh'],
                        sn=[u'User1'],
                        uid=[user1],
                        nsaccountlock=False,
                        has_keytab=False,
                        has_password=False,
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
                        dn=lambda x: DN(x) == \
                            DN(('uid','admin'),('cn','users'),('cn','accounts'),
                               api.env.basedn),
                        homedirectory=[u'/home/admin'],
                        loginshell=[u'/bin/bash'],
                        sn=[u'Administrator'],
                        uid=[u'admin'],
                        nsaccountlock=False,
                        has_keytab=True,
                        has_password=True,
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
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
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
            expected=errors.ObjectclassViolation(
                info=u'attribute "krbmaxticketlife" not allowed'),
        ),


        dict(
            desc='Retrieve %r to verify update' % user1,
            command=('user_show', [user1], {}),
            expected=dict(
                result=dict(
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                    givenname=[u'Finkle'],
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
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
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
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
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
            expected=errors.NotFound(reason=u'tuser1: user not found'),
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
            extra_check = upg_check,
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user2),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser2'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
            extra_check = upg_check,
        ),


        dict(
            desc='Make non-existent %r the manager of %r' % (renameduser1, user2),
            command=('user_mod', [user2], dict(manager=renameduser1)),
            expected=errors.NotFound(
                reason=u'manager %s not found' % renameduser1),
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
                    nsaccountlock=False,
                    has_keytab=False,
                    has_password=False,
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
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to update non-existent %r' % user1,
            command=('user_mod', [user1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Test an invalid login name %r' % invaliduser1,
            command=('user_add', [invaliduser1], dict(givenname=u'Test', sn=u'User1')),
            expected=errors.ValidationError(name='login',
                error=u'may only include letters, numbers, _, -, . and $'),
        ),


        dict(
            desc='Test a login name that is too long %r' % invaliduser2,
            command=('user_add', [invaliduser2],
                dict(givenname=u'Test', sn=u'User1')),
            expected=errors.ValidationError(name='login',
                error='can be at most 32 characters'),
        ),


        # The assumption on these next 4 tests is that if we don't get a
        # validation error then the request was processed normally.
        dict(
            desc='Test that validation is disabled on deletes',
            command=('user_del', [invaliduser1], {}),
            expected=errors.NotFound(
                reason=u'%s: user not found' % invaliduser1),
        ),


        dict(
            desc='Test that validation is disabled on show',
            command=('user_show', [invaliduser1], {}),
            expected=errors.NotFound(
                reason=u'%s: user not found' % invaliduser1),
        ),


        dict(
            desc='Test that validation is disabled on find',
            command=('user_find', [invaliduser1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 users matched',
                result=[],
            ),
        ),


        dict(
            desc='Try to rename to invalid username %r' % user1,
            command=('user_mod', [user1], dict(rename=invaliduser1)),
            expected=errors.ValidationError(name='rename',
                error=u'may only include letters, numbers, _, -, . and $'),
        ),


        dict(
            desc='Try to rename to a username that is too long %r' % user1,
            command=('user_mod', [user1], dict(rename=invaliduser2)),
            expected=errors.ValidationError(name='login',
                error='can be at most 32 characters'),
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
                    dn=lambda x: DN(x) == \
                        DN(('cn',group1),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
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

        dict(
            desc='Create %r with random password' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1', random=True)
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=True,
                    has_password=True,
                    randompassword=fuzzy_password,
                    krbextradata=[fuzzy_string],
                    krbpasswordexpiration=[fuzzy_dergeneralizedtime],
                    krblastpwdchange=[fuzzy_dergeneralizedtime],
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user2),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser2'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),

        dict(
            desc='Modify %r with random password' % user2,
            command=(
                'user_mod', [user2], dict(random=True)
            ),
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
                    nsaccountlock=False,
                    has_keytab=True,
                    has_password=True,
                    randompassword=fuzzy_password,
                ),
                summary=u'Modified user "tuser2"',
                value=user2,
            ),
        ),

        dict(
            desc='Delete %r' % user2,
            command=('user_del', [user2], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "tuser2"',
                value=user2,
            ),
        ),

        dict(
            desc='Create user %r with upper-case principal' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                krbprincipalname=user1.upper())
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create user %r with bad realm in principal' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                krbprincipalname='%s@NOTFOUND.ORG' % user1)
            ),
            expected=errors.RealmMismatch()
        ),


        dict(
            desc='Create user %r with malformed principal' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                krbprincipalname='%s@BAD@NOTFOUND.ORG' % user1)
            ),
            expected=errors.MalformedUserPrincipal(principal='%s@BAD@NOTFOUND.ORG' % user1),
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
            desc='Change default home directory',
            command=(
                'config_mod', [], dict(ipahomesrootdir=u'/other-home'),
            ),
            expected=lambda x: True,
        ),

        dict(
            desc='Create user %r with different default home directory' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "tuser1"',
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/other-home/tuser1'],
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
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Reset default home directory',
            command=(
                'config_mod', [], dict(ipahomesrootdir=u'/home'),
            ),
            expected=lambda x: True,
        ),

        dict(
            desc='Delete %r' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "%s"' % user1,
                value=user1,
            ),
        ),

        dict(
            desc='Change default login shell',
            command=(
                'config_mod', [], dict(ipadefaultloginshell=u'/usr/bin/ipython'),
            ),
            expected=lambda x: True,
        ),

        dict(
            desc='Create user %r with different default login shell' % user1,
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
                    loginshell=[u'/usr/bin/ipython'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=lambda x: [DN(i) for i in x] == \
                        [DN(('cn',user1),('cn','groups'),('cn','accounts'),
                            api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),

        dict(
            desc='Reset default login shell',
            command=(
                'config_mod', [], dict(ipadefaultloginshell=u'/bin/sh'),
            ),
            expected=lambda x: True,
        ),

        dict(
            desc='Delete %r' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "%s"' % user1,
                value=user1,
            ),
        ),

        dict(
            desc='Create %r without UPG' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1', noprivate=True)
            ),
            expected=errors.NotFound(reason='Default group for new users is not POSIX'),
        ),

        dict(
            desc='Create %r without UPG with GID explicitly set' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2', noprivate=True, gidnumber=1000)
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "tuser2"',
                result=dict(
                    gecos=[u'Test User2'],
                    givenname=[u'Test'],
                    description=[],
                    homedirectory=[u'/home/tuser2'],
                    krbprincipalname=[u'tuser2@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user_base,
                    sn=[u'User2'],
                    uid=[user2],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[u'1000'],
                    displayname=[u'Test User2'],
                    cn=[u'Test User2'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser2'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),

        dict(
            desc='Delete %r' % user2,
            command=('user_del', [user2], {}),
            expected=dict(
                result=dict(failed=u''),
                summary=u'Deleted user "%s"' % user2,
                value=user2,
            ),
        ),

        dict(
            desc='Change default user group',
            command=(
                'config_mod', [], dict(ipadefaultprimarygroup=group1),
            ),
            expected=lambda x: True,
        ),

        dict(
            desc='Create %r without UPG' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1', noprivate=True)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "tuser1"',
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    description=[],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user_base,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    memberof_group=[group1],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
            extra_check = not_upg_check,
        ),

        dict(
            desc='Create %r without UPG with GID explicitly set' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2', noprivate=True, gidnumber=1000)
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "tuser2"',
                result=dict(
                    gecos=[u'Test User2'],
                    givenname=[u'Test'],
                    description=[],
                    homedirectory=[u'/home/tuser2'],
                    krbprincipalname=[u'tuser2@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user_base,
                    sn=[u'User2'],
                    uid=[user2],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[u'1000'],
                    displayname=[u'Test User2'],
                    cn=[u'Test User2'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=lambda x: [DN(i) for i in x] == \
                        [DN(('cn','global_policy'),('cn',api.env.realm),
                            ('cn','kerberos'),api.env.basedn)],
                    memberof_group=[group1],
                    has_keytab=False,
                    has_password=False,
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser2'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),

        dict(
            desc='Reset default user group',
            command=(
                'config_mod', [], dict(ipadefaultprimarygroup=u'ipausers'),
            ),
            expected=lambda x: True,
        ),
    ]
