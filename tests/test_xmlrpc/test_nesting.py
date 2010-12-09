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

group1 = u'testgroup1'
group2 = u'testgroup2'
group3 = u'testgroup3'
user1 = u'tuser1'
user2 = u'tuser2'


class test_group(Declarative):
    cleanup_commands = [
        ('group_del', [group1], {}),
        ('group_del', [group2], {}),
        ('group_del', [group3], {}),
        ('user_del', [user1], {}),
        ('user_del', [user2], {}),
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
                    dn=u'cn=testgroup1,cn=groups,cn=accounts,' + api.env.basedn,
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
                    dn=u'cn=testgroup2,cn=groups,cn=accounts,' + api.env.basedn,
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
                    dn=u'cn=testgroup3,cn=groups,cn=accounts,' + api.env.basedn,
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
                    gecos=[user1],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=%s,cn=users,cn=accounts,%s' % (user1, api.env.basedn)
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
                    gecos=[user2],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser2'],
                    krbprincipalname=[u'tuser2@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User2'],
                    uid=[user2],
                    uidnumber=[fuzzy_digits],
                    displayname=[u'Test User2'],
                    cn=[u'Test User2'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=%s,cn=users,cn=accounts,%s' % (user2, api.env.basedn)
                ),
            ),
        ),


        ###############
        # member stuff
        #
        # Create 3 groups and 2 users and set the following membership:
        #
        # g1:
        #    member: g2
        #
        # g2:
        #    member: g3
        #    member: user1
        #
        # g3:
        #    member: user2
        #
        # So when we do a show it looks like:
        #
        # g1:
        #    member: g2
        #    indirect group: g3
        #    indirect users: user1, user2
        #
        # g2:
        #    member group: g3
        #    member user: tuser1
        #    indirect users: user2
        #    memberof: g1
        #
        # g3:
        #    member: user2
        #    memberof: g1, g2


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
                        'dn': u'cn=%s,cn=groups,cn=accounts,%s' % (group1, api.env.basedn),
                        'member_group': (group2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'Test desc 1'],
                },
            ),
        ),


        dict(
            desc='Add a group member %r to %r' % (group3, group2),
            command=(
                'group_add_member', [group2], dict(group=group3)
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
                        'dn': u'cn=%s,cn=groups,cn=accounts,%s' % (group2, api.env.basedn),
                        'member_group': (group3,),
                        'memberof_group': (u'testgroup1',),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group2],
                        'description': [u'Test desc 2'],
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
                        'dn': u'cn=%s,cn=groups,cn=accounts,%s' % (group2, api.env.basedn),
                        'member_user': (u'tuser1',),
                        'member_group': (group3,),
                        'memberof_group': (u'testgroup1',),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group2],
                        'description': [u'Test desc 2'],
                },
            ),
        ),


        dict(
            desc='Add a user member %r to %r' % (user2, group3),
            command=(
                'group_add_member', [group3], dict(user=user2)
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
                        'dn': u'cn=%s,cn=groups,cn=accounts,%s' % (group3, api.env.basedn),
                        'member_user': (u'tuser2',),
                        'memberof_group': (u'testgroup2', u'testgroup1'),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group3],
                        'description': [u'Test desc 3'],
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
                    memberindirect_group = (u'testgroup3',),
                    member_group = (u'testgroup2',),
                    memberindirect_user = (u'tuser1',u'tuser2',),
                    dn=u'cn=testgroup1,cn=groups,cn=accounts,' + api.env.basedn,
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
                    memberof_group = (u'testgroup1',),
                    member_group = (u'testgroup3',),
                    member_user = (u'tuser1',),
                    memberindirect_user = (u'tuser2',),
                    dn=u'cn=testgroup2,cn=groups,cn=accounts,' + api.env.basedn,
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
                    memberof_group = (u'testgroup2', u'testgroup1',),
                    member_user = (u'tuser2',),
                    dn=u'cn=testgroup3,cn=groups,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


    ]
