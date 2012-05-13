# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipalib/plugins/role.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipapython.dn import DN

search = u'test-role'

role1 = u'test-role-1'
role1_dn = DN(('cn',role1),api.env.container_rolegroup,
              api.env.basedn)
renamedrole1 = u'test-role'
invalidrole1 = u' whitespace '

role2 = u'test-role-2'
role2_dn = DN(('cn',role2),api.env.container_rolegroup,
              api.env.basedn)

group1 = u'testgroup1'
group1_dn = DN(('cn',group1),api.env.container_group,
               api.env.basedn)

privilege1 = u'r,w privilege 1'
privilege1_dn = DN(('cn', privilege1), DN(api.env.container_privilege),
                   api.env.basedn)

class test_role(Declarative):

    cleanup_commands = [
        ('role_del', [role1], {}),
        ('role_del', [role2], {}),
        ('group_del', [group1], {}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % role1,
            command=('role_show', [role1], {}),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Try to update non-existent %r' % role1,
            command=('role_mod', [role1], dict(description=u'Foo')),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Try to delete non-existent %r' % role1,
            command=('role_del', [role1], {}),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Try to rename non-existent %r' % role1,
            command=('role_mod', [role1], dict(setattr=u'cn=%s' % renamedrole1)),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Search for non-existent %r' % role1,
            command=('role_find', [role1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 roles matched',
                result=[],
            ),
        ),


        dict(
            desc='Create invalid %r' % invalidrole1,
            command=('role_add', [invalidrole1],
                dict(description=u'role desc 1')
            ),
            expected=errors.ValidationError(name='name',
                error=u'Leading and trailing spaces are not allowed'),
        ),


        dict(
            desc='Create %r' % role1,
            command=('role_add', [role1],
                dict(description=u'role desc 1')
            ),
            expected=dict(
                value=role1,
                summary=u'Added role "%s"' % role1,
                result=dict(
                    dn=role1_dn,
                    cn=[role1],
                    description=[u'role desc 1'],
                    objectclass=objectclasses.role,
                ),
            ),
        ),


        dict(
            desc='Retrieve %r' % role1,
            command=('role_show', [role1], {}),
            expected=dict(
                value=role1,
                summary=None,
                result=dict(
                    dn=role1_dn,
                    cn=[role1],
                    description=[u'role desc 1'],
                ),
            ),
        ),


        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'group desc 1',
                nonposix=True,)
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "testgroup1"',
                result=dict(
                    dn=group1_dn,
                    cn=[group1],
                    description=[u'group desc 1'],
                    objectclass=objectclasses.group,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Create %r' % privilege1,
            command=('privilege_add', [privilege1],
                dict(description=u'privilege desc. 1')
            ),
            expected=dict(
                value=privilege1,
                summary=u'Added privilege "%s"' % privilege1,
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                    objectclass=objectclasses.privilege,
                ),
            ),
        ),


        dict(
            desc='Add privilege %r to role %r' % (privilege1, role1),
            command=('role_add_privilege', [role1],
                dict(privilege=privilege1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        privilege=[],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'role desc 1'],
                    'memberof_privilege': [privilege1],
                }
            ),
        ),


        dict(
            desc='Add zero privileges to role %r' % role1,
            command=('role_add_privilege', [role1], dict(privilege=None)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        privilege=[],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'role desc 1'],
                    'memberof_privilege': [privilege1],
                }
            ),
        ),


        dict(
            desc='Remove zero privileges from role %r' % role1,
            command=('role_remove_privilege', [role1], dict(privilege=None)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        privilege=[],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'role desc 1'],
                    'memberof_privilege': [privilege1],
                }
            ),
        ),


        dict(
            desc='Add member %r to %r' % (group1, role1),
            command=('role_add_member', [role1], dict(group=group1)),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        user=[],
                        group=[],
                        host=[],
                        hostgroup=[],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'role desc 1'],
                    'member_group': [group1],
                    'memberof_privilege': [privilege1],
                }
            ),
        ),


        dict(
            desc='Retrieve %r to verify member-add' % role1,
            command=('role_show', [role1], {}),
            expected=dict(
                value=role1,
                summary=None,
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'role desc 1'],
                    'member_group': [group1],
                    'memberof_privilege': [privilege1],
                },
            ),
        ),


        dict(
            desc='Search for %r' % role1,
            command=('role_find', [role1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 role matched',
                result=[
                    {
                        'dn': role1_dn,
                        'cn': [role1],
                        'description': [u'role desc 1'],
                        'member_group': [group1],
                        'memberof_privilege': [privilege1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % search,
            command=('role_find', [search], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 role matched',
                result=[
                    {
                        'dn': role1_dn,
                        'cn': [role1],
                        'description': [u'role desc 1'],
                        'member_group': [group1],
                        'memberof_privilege': [privilege1],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % role2,
            command=('role_add', [role2],
                dict(description=u'role desc 2')
            ),
            expected=dict(
                value=role2,
                summary=u'Added role "%s"' % role2,
                result=dict(
                    dn=role2_dn,
                    cn=[role2],
                    description=[u'role desc 2'],
                    objectclass=objectclasses.role,
                ),
            ),
        ),


        dict(
            desc='Search for %r' % role1,
            command=('role_find', [role1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 role matched',
                result=[
                    {
                        'dn': role1_dn,
                        'cn': [role1],
                        'description': [u'role desc 1'],
                        'member_group': [group1],
                        'memberof_privilege': [privilege1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % search,
            command=('role_find', [search], {}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 roles matched',
                result=[
                    {
                        'dn': role1_dn,
                        'cn': [role1],
                        'description': [u'role desc 1'],
                        'member_group': [group1],
                        'memberof_privilege': [privilege1],
                    },
                    {
                        'dn': role2_dn,
                        'cn': [role2],
                        'description': [u'role desc 2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % role1,
            command=(
                'role_mod', [role1], dict(description=u'New desc 1')
            ),
            expected=dict(
                value=role1,
                summary=u'Modified role "%s"' % role1,
                result=dict(
                    cn=[role1],
                    description=[u'New desc 1'],
                    member_group=[group1],
                    memberof_privilege=[privilege1],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % role1,
            command=('role_show', [role1], {}),
            expected=dict(
                value=role1,
                summary=None,
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'New desc 1'],
                    'member_group': [group1],
                    'memberof_privilege': [privilege1],
                },
            ),
        ),


        dict(
            desc='Remove member %r from %r' % (group1, role1),
            command=('role_remove_member', [role1], dict(group=group1)),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        user=[],
                        group=[],
                        host=[],
                        hostgroup=[],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'New desc 1'],
                    'memberof_privilege': [privilege1],
                },
            ),
        ),


        dict(
            desc='Retrieve %r to verify member-del' % role1,
            command=('role_show', [role1], {}),
            expected=dict(
                value=role1,
                summary=None,
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'New desc 1'],
                    'memberof_privilege': [privilege1],
                },
            ),
        ),


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
            desc='Rename %r' % role1,
            command=('role_mod', [role1], dict(setattr=u'cn=%s' % renamedrole1)),
            expected=dict(
                value=role1,
                result=dict(
                    cn=[renamedrole1],
                    description=[u'New desc 1'],
                    memberof_privilege=[privilege1],
                ),
                summary=u'Modified role "%s"' % role1
            )
        ),


        dict(
            desc='Rename %r back' % renamedrole1,
            command=('role_mod', [renamedrole1], dict(setattr=u'cn=%s' % role1)),
            expected=dict(
                value=renamedrole1,
                result=dict(
                    cn=[role1],
                    description=[u'New desc 1'],
                    memberof_privilege=[privilege1],
                ),
                summary=u'Modified role "%s"' % renamedrole1
            )
        ),


        dict(
            desc='Remove privilege %r from role %r' % (privilege1, role1),
            command=('role_remove_privilege', [role1],
                dict(privilege=privilege1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        privilege=[],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'New desc 1'],
                }
            ),
        ),


        dict(
            desc='Remove privilege %r from role %r again' % (privilege1, role1),
            command=('role_remove_privilege', [role1],
                dict(privilege=privilege1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        privilege=[(u'%s' % privilege1, u'This entry is not a member'),],
                    ),
                ),
                result={
                    'dn': role1_dn,
                    'cn': [role1],
                    'description': [u'New desc 1'],
                }
            ),
        ),



        dict(
            desc='Delete %r' % role1,
            command=('role_del', [role1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=role1,
                summary=u'Deleted role "%s"' % role1,
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % role1,
            command=('role_del', [role1], {}),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Try to show non-existent %r' % role1,
            command=('role_show', [role1], {}),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Try to update non-existent %r' % role1,
            command=('role_mod', [role1], dict(description=u'Foo')),
            expected=errors.NotFound(reason=u'%s: role not found' % role1),
        ),


        dict(
            desc='Search for %r' % search,
            command=('role_find', [search], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 role matched',
                result=[
                    {
                        'dn': role2_dn,
                        'cn': [role2],
                        'description': [u'role desc 2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Delete %r' % role2,
            command=('role_del', [role2], {}),
            expected=dict(
                result=dict(failed=u''),
                value=role2,
                summary=u'Deleted role "%s"' % role2,
            )
        ),


        dict(
            desc='Search for %r' % search,
            command=('role_find', [search], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 roles matched',
                result=[],
            ),
        ),

    ]
