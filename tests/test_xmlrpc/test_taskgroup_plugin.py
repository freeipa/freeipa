# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Test the `ipalib/plugins/taskgroup.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

search = u'test-taskgroup'

taskgroup1 = u'test-taskgroup-1'
taskgroup1_dn = u'cn=%s,cn=taskgroups,cn=accounts,%s' % (
    taskgroup1, api.env.basedn
)

taskgroup2 = u'test-taskgroup-2'
taskgroup2_dn = u'cn=%s,cn=taskgroups,cn=accounts,%s' % (
    taskgroup2, api.env.basedn
)

group1 = u'testgroup1'
group1_dn = u'cn=%s,cn=groups,cn=accounts,%s' % (group1, api.env.basedn)

rolegroup1 = u'test-rolegroup-1'
rolegroup1_dn = u'cn=%s,cn=rolegroups,cn=accounts,%s' % (
    rolegroup1, api.env.basedn
)


class test_taskgroup(Declarative):

    cleanup_commands = [
        ('taskgroup_del', [taskgroup1], {}),
        ('taskgroup_del', [taskgroup2], {}),
        ('group_del', [group1], {}),
        ('rolegroup_del', [rolegroup1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % taskgroup1,
            command=('taskgroup_show', [taskgroup1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % taskgroup1,
            command=('taskgroup_mod', [taskgroup1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % taskgroup1,
            command=('taskgroup_del', [taskgroup1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Search for non-existent %r' % taskgroup1,
            command=('taskgroup_find', [taskgroup1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 taskgroups matched',
                result=[],
            ),
        ),


        dict(
            desc='Create %r' % taskgroup1,
            command=(
                'taskgroup_add', [taskgroup1], dict(description=u'Test desc 1')
            ),
            expected=dict(
                value=taskgroup1,
                summary=u'Added taskgroup "test-taskgroup-1"',
                result=dict(
                    dn=taskgroup1_dn,
                    cn=[taskgroup1],
                    description=[u'Test desc 1'],
                    objectclass=objectclasses.taskgroup,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % taskgroup1,
            command=(
                'taskgroup_add', [taskgroup1], dict(description=u'Test desc 1')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Create %r' % rolegroup1,
            command=('rolegroup_add', [rolegroup1],
                dict(description=u'rolegroup desc. 1')
            ),
            expected=dict(
                value=rolegroup1,
                summary=u'Added rolegroup "test-rolegroup-1"',
                result=dict(
                    dn=rolegroup1_dn,
                    cn=[rolegroup1],
                    description=[u'rolegroup desc. 1'],
                    objectclass=objectclasses.rolegroup,
                ),
            ),
        ),


        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test group desc 1')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "testgroup1"',
                result=dict(
                    dn=group1_dn,
                    cn=[group1],
                    description=[u'Test group desc 1'],
                    objectclass=objectclasses.group,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Add member to %r' % taskgroup1,
            command=('taskgroup_add_member', [taskgroup1],
                dict(rolegroup=rolegroup1, group=group1)
            ),
            expected=dict(
                completed=2,
                failed=dict(
                    member=dict(
                        rolegroup=[],
                        group=[],
                        user=[],
                    ),
                ),
                result={
                    'dn': taskgroup1_dn,
                    'cn': [taskgroup1],
                    'description': [u'Test desc 1'],
                    'member_rolegroup': [rolegroup1],
                    'member_group': [group1],
                }
            ),
        ),


        dict(
            desc='Retrieve %r' % taskgroup1,
            command=('taskgroup_show', [taskgroup1], {}),
            expected=dict(
                value=taskgroup1,
                summary=None,
                result={
                    'dn': taskgroup1_dn,
                    'cn': [taskgroup1],
                    'description': [u'Test desc 1'],
                    'member_rolegroup': [rolegroup1],
                    'member_group': [group1],
                },
            ),
        ),


        dict(
            desc='Search for %r' % taskgroup1,
            command=('taskgroup_find', [taskgroup1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 taskgroup matched',
                result=[
                    {
                        #'dn': taskgroup1_dn,
                        'cn': [taskgroup1],
                        'description': [u'Test desc 1'],
                        'member_rolegroup': [rolegroup1],
                        'member_group': [group1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % search,
            command=('taskgroup_find', [search], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 taskgroup matched',
                result=[
                    {
                        #'dn': taskgroup1_dn,
                        'cn': [taskgroup1],
                        'description': [u'Test desc 1'],
                        'member_rolegroup': [rolegroup1],
                        'member_group': [group1],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % taskgroup2,
            command=(
                'taskgroup_add', [taskgroup2], dict(description=u'Test desc 2')
            ),
            expected=dict(
                value=taskgroup2,
                summary=u'Added taskgroup "test-taskgroup-2"',
                result=dict(
                    dn=taskgroup2_dn,
                    cn=[taskgroup2],
                    description=[u'Test desc 2'],
                    objectclass=objectclasses.taskgroup,
                ),
            ),
        ),


        dict(
            desc='Search for %r' % taskgroup1,
            command=('taskgroup_find', [taskgroup1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 taskgroup matched',
                result=[
                    {
                        #'dn': taskgroup1_dn,
                        'cn': [taskgroup1],
                        'description': [u'Test desc 1'],
                        'member_rolegroup': [rolegroup1],
                        'member_group': [group1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % search,
            command=('taskgroup_find', [search], {}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 taskgroups matched',
                result=[
                    {
                        #'dn': taskgroup1_dn,
                        'cn': [taskgroup1],
                        'description': [u'Test desc 1'],
                        'member_rolegroup': [rolegroup1],
                        'member_group': [group1],
                    },
                    {
                        #'dn': taskgroup2_dn,
                        'cn': [taskgroup2],
                        'description': [u'Test desc 2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Updated %r' % taskgroup1,
            command=(
                'taskgroup_mod', [taskgroup1], dict(description=u'New desc 1')
            ),
            expected=dict(
                value=taskgroup1,
                summary=u'Modified taskgroup "test-taskgroup-1"',
                result=dict(
                    cn=[taskgroup1],
                    description=[u'New desc 1'],
                    member_rolegroup=[rolegroup1],
                    member_group=[group1],

                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % taskgroup1,
            command=('taskgroup_show', [taskgroup1], {}),
            expected=dict(
                value=taskgroup1,
                summary=None,
                result={
                    'dn': taskgroup1_dn,
                    'cn': [taskgroup1],
                    'description': [u'New desc 1'],
                    'member_rolegroup': [rolegroup1],
                    'member_group': [group1],
                },
            ),
        ),


        dict(
            desc='Remove member from %r' % taskgroup1,
            command=('taskgroup_remove_member', [taskgroup1],
                dict(group=group1),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        rolegroup=[],
                        group=[],
                        user=[],
                    ),
                ),
                result={
                    'dn': taskgroup1_dn,
                    'cn': [taskgroup1],
                    'description': [u'New desc 1'],
                    'member_rolegroup': [rolegroup1],
                }
            ),
        ),


        dict(
            desc='Delete %r' % taskgroup1,
            command=('taskgroup_del', [taskgroup1], {}),
            expected=dict(
                result=True,
                value=taskgroup1,
                summary=u'Deleted taskgroup "test-taskgroup-1"',
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % taskgroup1,
            command=('taskgroup_del', [taskgroup1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % taskgroup1,
            command=('taskgroup_show', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % taskgroup1,
            command=('taskgroup_mod', [taskgroup1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Search for %r' % search,
            command=('taskgroup_find', [search], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 taskgroup matched',
                result=[
                    {
                        #'dn': taskgroup2_dn,
                        'cn': [taskgroup2],
                        'description': [u'Test desc 2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Delete %r' % taskgroup2,
            command=('taskgroup_del', [taskgroup2], {}),
            expected=dict(
                result=True,
                value=taskgroup2,
                summary=u'Deleted taskgroup "test-taskgroup-2"',
            )
        ),


        dict(
            desc='Search for %r' % search,
            command=('taskgroup_find', [search], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 taskgroups matched',
                result=[],
            ),
        ),


        dict(
            desc='Delete %r' % group1,
            command=('group_del', [group1], {}),
            expected=dict(
                result=True,
                value=group1,
                summary=u'Deleted group "testgroup1"',
            )
        ),


        dict(
            desc='Delete %r' % rolegroup1,
            command=('rolegroup_del', [rolegroup1], {}),
            expected=dict(
                result=True,
                value=rolegroup1,
                summary=u'Deleted rolegroup "test-rolegroup-1"',
            )
        ),

    ]
