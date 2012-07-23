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
Test group nexting an indirect members
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipapython.dn import DN

group1 = u'testgroup1'
group2 = u'testgroup2'
group3 = u'testgroup3'
group4 = u'testgroup4'
user1 = u'tuser1'
user2 = u'tuser2'
user3 = u'tuser3'
user4 = u'tuser4'

hostgroup1 = u'testhostgroup1'
hgdn1 = DN(('cn',hostgroup1),('cn','hostgroups'),('cn','accounts'),
           api.env.basedn)
hostgroup2 = u'testhostgroup2'
hgdn2 = DN(('cn',hostgroup2),('cn','hostgroups'),('cn','accounts'),
           api.env.basedn)

fqdn1 = u'testhost1.%s' % api.env.domain
host_dn1 = DN(('fqdn',fqdn1),('cn','computers'),('cn','accounts'),
              api.env.basedn)


class test_nesting(Declarative):
    cleanup_commands = [
        ('group_del', [group1], {}),
        ('group_del', [group2], {}),
        ('group_del', [group3], {}),
        ('group_del', [group4], {}),
        ('user_del', [user1], {}),
        ('user_del', [user2], {}),
        ('user_del', [user3], {}),
        ('user_del', [user4], {}),
        ('host_del', [fqdn1], {}),
        ('hostgroup_del', [hostgroup1], {}),
        ('hostgroup_del', [hostgroup2], {}),
    ]

    tests = [

        ################
        # create group1:

        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc 1')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "testgroup1"',
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    gidnumber=[fuzzy_digits],
                    dn=DN(('cn','testgroup1'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        ################
        # create group2:
        dict(
            desc='Create %r' % group2,
            command=(
                'group_add', [group2], dict(description=u'Test desc 2')
            ),
            expected=dict(
                value=group2,
                summary=u'Added group "testgroup2"',
                result=dict(
                    cn=[group2],
                    description=[u'Test desc 2'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn','testgroup2'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % group3,
            command=(
                'group_add', [group3], dict(description=u'Test desc 3')
            ),
            expected=dict(
                value=group3,
                summary=u'Added group "testgroup3"',
                result=dict(
                    cn=[group3],
                    description=[u'Test desc 3'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn','testgroup3'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % group4,
            command=(
                'group_add', [group4], dict(description=u'Test desc 4')
            ),
            expected=dict(
                value=group4,
                summary=u'Added group "testgroup4"',
                result=dict(
                    cn=[group4],
                    description=[u'Test desc 4'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn','testgroup4'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
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
                    dn=DN(('uid',user1),('cn','users'),('cn','accounts'),
                          api.env.basedn)
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
                summary=u'Added user "%s"' % user2,
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
                    mail=[u'%s@%s' % (user2, api.env.domain)],
                    displayname=[u'Test User2'],
                    cn=[u'Test User2'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn','global_policy'),('cn',api.env.realm),
                                              ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=[DN(('cn',user2),('cn','groups'),('cn','accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=DN(('uid',user2),('cn','users'),('cn','accounts'),
                          api.env.basedn)
                ),
            ),
        ),


        dict(
            desc='Create %r' % user3,
            command=(
                'user_add', [user3], dict(givenname=u'Test', sn=u'User3')
            ),
            expected=dict(
                value=user3,
                summary=u'Added user "%s"' % user3,
                result=dict(
                    gecos=[u'Test User3'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser3'],
                    krbprincipalname=[u'tuser3@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User3'],
                    uid=[user3],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'%s@%s' % (user3, api.env.domain)],
                    displayname=[u'Test User3'],
                    cn=[u'Test User3'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn','global_policy'),('cn',api.env.realm),
                                              ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=[DN(('cn',user3),('cn','groups'),('cn','accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=DN(('uid',user3),('cn','users'),('cn','accounts'),
                          api.env.basedn)
                ),
            ),
        ),


        dict(
            desc='Create %r' % user4,
            command=(
                'user_add', [user4], dict(givenname=u'Test', sn=u'User4')
            ),
            expected=dict(
                value=user4,
                summary=u'Added user "%s"' % user4,
                result=dict(
                    gecos=[u'Test User4'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser4'],
                    krbprincipalname=[u'tuser4@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User4'],
                    uid=[user4],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'%s@%s' % (user4, api.env.domain)],
                    displayname=[u'Test User4'],
                    cn=[u'Test User4'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn','global_policy'),('cn',api.env.realm),
                                              ('cn','kerberos'),api.env.basedn)],
                    mepmanagedentry=[DN(('cn',user4),('cn','groups'),('cn','accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'ipausers'],
                    has_keytab=False,
                    has_password=False,
                    dn=DN(('uid',user4),('cn','users'),('cn','accounts'),
                          api.env.basedn)
                ),
            ),
        ),


        ###############
        # member stuff
        #
        # Create 4 groups and 4 users and set the following membership:
        #
        # g1:
        #    no direct memberships
        #
        # g2:
        #    memberof: g1
        #    member: user1, user2
        #
        # g3:
        #    memberof: g1
        #    member: user3, g4
        #
        # g4:
        #    memberof: g3
        #    member: user1, user4
        #
        # So when we do a show it looks like:
        #
        # g1:
        #    member groups: g2, g3
        #    indirect member group: g4
        #    indirect member users: user1, user2, tuser3, tuser4
        #
        # g2:
        #    member of group: g1
        #    member users: tuser1, tuser2
        #
        # g3:
        #  member users: tuser3
        #  member groups: g4
        #  member of groups: g1
        #  indirect member users: tuser4
        #
        # g4:
        #  member users: tuser1, tuser4
        #  member of groups: g3
        #  indirect member of groups: g1
        #
        # Note that tuser1 is an indirect member of g1 both through
        # g2 and g4. It should appear just once in the list.

        dict(
            desc='Add a group member %r to %r' % (group2, group1),
            command=(
                'group_add_member', [group1], dict(group=group2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group1),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_group': (group2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'Test desc 1'],
                },
            ),
        ),


        dict(
            desc='Add a group member %r to %r' % (group3, group1),
            command=(
                'group_add_member', [group1], dict(group=group3)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group1),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_group': [group2, group3,],
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'Test desc 1'],
                },
            ),
        ),


        dict(
            desc='Add a user member %r to %r' % (user1, group2),
            command=(
                'group_add_member', [group2], dict(user=user1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group2),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': (u'tuser1',),
                        'memberof_group': (u'testgroup1',),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group2],
                        'description': [u'Test desc 2'],
                },
            ),
        ),


        dict(
            desc='Add a user member %r to %r' % (user2, group2),
            command=(
                'group_add_member', [group2], dict(user=user2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group2),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': [user1, user2],
                        'memberof_group': [group1],
                        'gidnumber': [fuzzy_digits],
                        'cn': [group2],
                        'description': [u'Test desc 2'],
                },
            ),
        ),


        dict(
            desc='Add a user member %r to %r' % (user3, group3),
            command=(
                'group_add_member', [group3], dict(user=user3)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group3),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': [user3],
                        'memberof_group': [group1],
                        'gidnumber': [fuzzy_digits],
                        'cn': [group3],
                        'description': [u'Test desc 3'],
                },
            ),
        ),


        dict(
            desc='Add a group member %r to %r' % (group4, group3),
            command=(
                'group_add_member', [group3], dict(group=group4)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group3),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': [user3],
                        'memberof_group': [group1],
                        'member_group': [group4],
                        'gidnumber': [fuzzy_digits],
                        'cn': [group3],
                        'description': [u'Test desc 3'],
                },
            ),
        ),


        dict(
            desc='Add a user member %r to %r' % (user1, group4),
            command=(
                'group_add_member', [group4], dict(user=user1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group4),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': [user1],
                        'memberof_group': [group3],
                        'memberofindirect_group': [group1],
                        'gidnumber': [fuzzy_digits],
                        'cn': [group4],
                        'description': [u'Test desc 4'],
                },
            ),
        ),


        dict(
            desc='Add a user member %r to %r' % (user4, group4),
            command=(
                'group_add_member', [group4], dict(user=user4)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group4),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': [user1, user4],
                        'memberof_group': [group3],
                        'memberofindirect_group': [group1],
                        'gidnumber': [fuzzy_digits],
                        'cn': [group4],
                        'description': [u'Test desc 4'],
                },
            ),
        ),


        dict(
            desc='Retrieve group %r' % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                summary=None,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    gidnumber= [fuzzy_digits],
                    memberindirect_group = [group4],
                    member_group = [group2, group3],
                    memberindirect_user = [user1, user2, user3, user4],
                    dn=DN(('cn','testgroup1'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Retrieve group %r' % group2,
            command=('group_show', [group2], {}),
            expected=dict(
                value=group2,
                summary=None,
                result=dict(
                    cn=[group2],
                    description=[u'Test desc 2'],
                    gidnumber= [fuzzy_digits],
                    memberof_group = [group1],
                    member_user = [user1, user2],
                    dn=DN(('cn','testgroup2'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Retrieve group %r' % group3,
            command=('group_show', [group3], {}),
            expected=dict(
                value=group3,
                summary=None,
                result=dict(
                    cn=[group3],
                    description=[u'Test desc 3'],
                    gidnumber= [fuzzy_digits],
                    memberof_group = [group1],
                    member_user = [user3],
                    member_group = [group4],
                    memberindirect_user = [user1, user4],
                    dn=DN(('cn','testgroup3'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Retrieve group %r' % group4,
            command=('group_show', [group4], {}),
            expected=dict(
                value=group4,
                summary=None,
                result=dict(
                    cn=[group4],
                    description=[u'Test desc 4'],
                    gidnumber= [fuzzy_digits],
                    memberof_group = [group3],
                    member_user = [user1, user4],
                    memberofindirect_group = [group1],
                    dn=DN(('cn','testgroup4'),('cn','groups'),
                          ('cn','accounts'),api.env.basedn),
                ),
            ),
        ),


        # Now do something similar with hosts and hostgroups
        dict(
            desc='Create host %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Added host "%s"' % fqdn1,
                result=dict(
                    dn=host_dn1,
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup1],
                dict(description=u'Test hostgroup 1')
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added hostgroup "testhostgroup1"',
                result=dict(
                    dn=hgdn1,
                    cn=[hostgroup1],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn',hostgroup1),('cn','ng'),('cn','alt'),
                                        api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup2,
            command=('hostgroup_add', [hostgroup2],
                dict(description=u'Test hostgroup 2')
            ),
            expected=dict(
                value=hostgroup2,
                summary=u'Added hostgroup "testhostgroup2"',
                result=dict(
                    dn=hgdn2,
                    cn=[hostgroup2],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 2'],
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn',hostgroup2),('cn','ng'),('cn','alt'),
                                        api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc=u'Add host %r to %r' % (fqdn1, hostgroup2),
            command=(
                'hostgroup_add_member', [hostgroup2], dict(host=fqdn1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                result={
                    'dn': hgdn2,
                    'cn': [hostgroup2],
                    'description': [u'Test hostgroup 2'],
                    'member_host': [fqdn1],
                },
            ),
        ),


        dict(
            desc=u'Add hostgroup %r to %r' % (hostgroup2, hostgroup1),
            command=(
                'hostgroup_add_member', [hostgroup1], dict(hostgroup=hostgroup2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        host=tuple(),
                        hostgroup=tuple(),
                    ),
                ),
                result={
                    'dn': hgdn1,
                    'cn': [hostgroup1],
                    'description': [u'Test hostgroup 1'],
                    'member_hostgroup': [hostgroup2],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % hostgroup1,
            command=('hostgroup_show', [hostgroup1], {}),
            expected=dict(
                value=hostgroup1,
                summary=None,
                result={
                    'dn': hgdn1,
                    'memberindirect_host': [u'testhost1.%s' % api.env.domain],
                    'member_hostgroup': [hostgroup2],
                    'cn': [hostgroup1],
                    'description': [u'Test hostgroup 1'],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % fqdn1,
            command=('host_show', [fqdn1], {}),
            expected=dict(
                value=fqdn1,
                summary=None,
                result=dict(
                    dn=host_dn1,
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    managedby_host=[fqdn1],
                    memberof_hostgroup = [u'testhostgroup2'],
                    memberofindirect_hostgroup = [u'testhostgroup1'],
                    memberofindirect_netgroup = [u'testhostgroup2'],
                ),
            ),
        ),

    ]
