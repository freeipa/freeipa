# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipalib/plugins/group.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipalib.dn import *

group1 = u'testgroup1'
group2 = u'testgroup2'
renamedgroup1 = u'testgroup'
user1 = u'tuser1'

invalidgroup1=u'+tgroup1'


class test_group(Declarative):
    cleanup_commands = [
        ('group_del', [group1], {}),
        ('group_del', [group2], {}),
        ('user_del', [user1], {}),
    ]

    tests = [

        ################
        # create group1:
        dict(
            desc='Try to retrieve non-existent %r' % group1,
            command=('group_show', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group1,
            command=('group_mod', [group1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % group1,
            command=('group_del', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to rename non-existent %r' % group1,
            command=('group_mod', [group1], dict(setattr=u'cn=%s' % renamedgroup1)),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create non-POSIX %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc 1',nonposix=True)
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "testgroup1"',
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    objectclass=objectclasses.group,
                    ipauniqueid=[fuzzy_uuid],
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup1'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc 1')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve non-POSIX %r' % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                summary=None,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup1'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Updated non-POSIX %r' % group1,
            command=(
                'group_mod', [group1], dict(description=u'New desc 1')
            ),
            expected=dict(
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                ),
                summary=u'Modified group "testgroup1"',
                value=group1,
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup1'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
                summary=None,
            ),
        ),


        # FIXME: The return value is totally different here than from the above
        # group_mod() test.  I think that for all *_mod() commands we should
        # just return the entry exactly as *_show() does.
        dict(
            desc='Updated %r to promote it to a POSIX group' % group1,
            command=('group_mod', [group1], dict(posix=True)),
            expected=dict(
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                    gidnumber=[fuzzy_digits],
                ),
                value=group1,
                summary=u'Modified group "testgroup1"',
            ),
        ),


        dict(
            desc="Retrieve %r to verify it's a POSIX group" % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                result=dict(
                    cn=[group1],
                    description=(u'New desc 1',),
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup1'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                    gidnumber=[fuzzy_digits],
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r' % group1,
            command=('group_find', [], dict(cn=group1)),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        dn=lambda x: DN(x) == \
                            DN(('cn',group1),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        cn=[group1],
                        description=[u'New desc 1'],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'1 group matched',
            ),
        ),



        ################
        # create group2:
        dict(
            desc='Try to retrieve non-existent %r' % group2,
            command=('group_show', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group2,
            command=('group_mod', [group2], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % group2,
            command=('group_del', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


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
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup2'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % group2,
            command=(
                'group_add', [group2], dict(description=u'Test desc 2')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % group2,
            command=('group_show', [group2], {}),
            expected=dict(
                value=group2,
                summary=None,
                result=dict(
                    cn=[group2],
                    description=[u'Test desc 2'],
                    gidnumber=[fuzzy_digits],
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup2'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Updated %r' % group2,
            command=(
                'group_mod', [group2], dict(description=u'New desc 2')
            ),
            expected=dict(
                result=dict(
                    cn=[group2],
                    gidnumber=[fuzzy_digits],
                    description=[u'New desc 2'],
                ),
                summary=u'Modified group "testgroup2"',
                value=group2,
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % group2,
            command=('group_show', [group2], {}),
            expected=dict(
                value=group2,
                result=dict(
                    cn=[group2],
                    description=[u'New desc 2'],
                    gidnumber=[fuzzy_digits],
                    dn=lambda x: DN(x) == \
                        DN(('cn','testgroup2'),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r' % group2,
            command=('group_find', [], dict(cn=group2)),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        dn=lambda x: DN(x) == \
                            DN(('cn',group2),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        cn=[group2],
                        description=[u'New desc 2'],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'1 group matched',
            ),
        ),


        dict(
            desc='Search for all groups',
            command=('group_find', [], {}),
            expected=dict(
                summary=u'5 groups matched',
                count=5,
                truncated=False,
                result=[
                    {
                        'dn': lambda x: DN(x) == \
                            DN(('cn','admins'),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        'member_user': [u'admin'],
                        'gidnumber': [fuzzy_digits],
                        'cn': [u'admins'],
                        'description': [u'Account administrators group'],
                    },
                    {
                        'dn': lambda x: DN(x) == \
                            DN(('cn','editors'),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        'gidnumber': [fuzzy_digits],
                        'cn': [u'editors'],
                        'description': [u'Limited admins who can edit other users'],
                    },
                    {
                        'dn': lambda x: DN(x) == \
                            DN(('cn','ipausers'),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        'gidnumber': [fuzzy_digits],
                        'cn': [u'ipausers'],
                        'description': [u'Default group for all users'],
                    },
                    dict(
                        dn=lambda x: DN(x) == \
                            DN(('cn',group1),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        cn=[group1],
                        description=[u'New desc 1'],
                        gidnumber=[fuzzy_digits],
                    ),
                    dict(
                        dn=lambda x: DN(x) == \
                            DN(('cn',group2),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        cn=[group2],
                        description=[u'New desc 2'],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
            ),
        ),



        ###############
        # member stuff:
        dict(
            desc='Add member %r to %r' % (group2, group1),
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
                        'dn': lambda x: DN(x) == \
                            DN(('cn',group1),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        'member_group': (group2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'New desc 1'],
                },
            ),
        ),

        dict(
            # FIXME: Shouldn't this raise a NotFound instead?
            desc='Try to add non-existent member to %r' % group1,
            command=(
                'group_add_member', [group1], dict(group=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        group=[(u'notfound', u'no such entry')],
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': lambda x: DN(x) == \
                            DN(('cn',group1),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        'member_group': (group2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'New desc 1'],
                },
            ),
        ),

        dict(
            desc='Remove member %r from %r' % (group2, group1),
            command=('group_remove_member',
                [group1], dict(group=group2)
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
                    'dn': lambda x: DN(x) == \
                        DN(('cn',group1),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                    'cn': [group1],
                    'gidnumber': [fuzzy_digits],
                    'description': [u'New desc 1'],
                },
            ),
        ),

        dict(
            # FIXME: Shouldn't this raise a NotFound instead?
            desc='Try to remove non-existent member from %r' % group1,
            command=('group_remove_member',
                [group1], dict(group=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        group=[(u'notfound', u'This entry is not a member')],
                        user=tuple(),
                    ),
                ),
                result={
                    'dn': lambda x: DN(x) == \
                        DN(('cn',group1),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                    'cn': [group1],
                    'gidnumber': [fuzzy_digits],
                    'description': [u'New desc 1'],
                },
            ),
        ),


        dict(
            desc='Rename %r' % group1,
            command=('group_mod', [group1], dict(setattr=u'cn=%s' % renamedgroup1)),
            expected=dict(
                value=group1,
                result=dict(
                    cn=[renamedgroup1],
                    description=[u'New desc 1'],
                    gidnumber=[fuzzy_digits],
                ),
                summary=u'Modified group "%s"' % group1
            )
        ),


        dict(
            desc='Rename %r back' % renamedgroup1,
            command=('group_mod', [renamedgroup1], dict(setattr=u'cn=%s' % group1)),
            expected=dict(
                value=renamedgroup1,
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                    gidnumber=[fuzzy_digits],
                ),
                summary=u'Modified group "%s"' % renamedgroup1
            )
        ),



        ################
        # delete group1:
        dict(
            desc='Delete %r' % group1,
            command=('group_del', [group1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=group1,
                summary=u'Deleted group "testgroup1"',
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % group1,
            command=('group_del', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % group1,
            command=('group_show', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group1,
            command=('group_mod', [group1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),



        ################
        # delete group2:
        dict(
            desc='Delete %r' % group2,
            command=('group_del', [group2], {}),
            expected=dict(
                result=dict(failed=u''),
                value=group2,
                summary=u'Deleted group "testgroup2"',
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % group2,
            command=('group_del', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % group2,
            command=('group_show', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group2,
            command=('group_mod', [group2], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),

        dict(
            desc='Test an invalid group name %r' % invalidgroup1,
            command=('group_add', [invalidgroup1], dict(description=u'Test')),
            expected=errors.ValidationError(name='cn', error='may only include letters, numbers, _, -, . and $'),
        ),


        ##### managed entry tests
        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/%s' % user1],
                    krbprincipalname=[u'%s@%s' % (user1, api.env.realm)],
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
                    dn=lambda x: DN(x) == \
                        DN(('uid',user1),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Verify the managed group %r was created' % user1,
            command=('group_show', [user1], {}),
            expected=dict(
                value=user1,
                summary=None,
                result=dict(
                    cn=[user1],
                    description=[u'User private group for %s' % user1],
                    gidnumber=[fuzzy_digits],
                    dn=lambda x: DN(x) == \
                        DN(('cn',user1),('cn','groups'),('cn','accounts'),
                           api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Verify that managed group %r can be found' % user1,
            command=('group_find', [], {'cn': user1, 'private': True}),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        dn=lambda x: DN(x) == \
                            DN(('cn',user1),('cn','groups'),('cn','accounts'),
                               api.env.basedn),
                        cn=[user1],
                        description=[u'User private group for %s' % user1],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'1 group matched',
            ),
        ),


        dict(
            desc='Try to delete a managed group %r' % user1,
            command=('group_del', [user1], {}),
            expected=errors.ManagedGroupError(),
        ),


        dict(
            desc='Detach managed group %r' % user1,
            command=('group_detach', [user1], {}),
            expected=dict(
                result=True,
                value=user1,
                summary=u'Detached group "%s" from user "%s"' % (user1, user1),
            ),
        ),


        dict(
            desc='Now delete the unmanaged group %r' % user1,
            command=('group_del', [user1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=user1,
                summary=u'Deleted group "%s"' % user1,
            )
        ),


        dict(
            desc='Verify that %r is really gone' % user1,
            command=('group_show', [user1], {}),
            expected=errors.NotFound(reason='no such entry'),
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
            desc='Create %r without User Private Group' % user1,
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
                    dn=lambda x: DN(x) == \
                        DN(('uid','tuser1'),('cn','users'),('cn','accounts'),
                           api.env.basedn),
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Verify the managed group %r was not created' % user1,
            command=('group_show', [user1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),

    ]
