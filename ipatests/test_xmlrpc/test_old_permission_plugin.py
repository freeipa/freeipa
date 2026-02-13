# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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
Test the `ipaserver/plugins/permission.py` module with old API.

This ensures basic backwards compatibility for code before
http://www.freeipa.org/page/V3/Permissions_V2
"""

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
from ipapython.dn import DN
import pytest

permission1 = 'testperm'
permission1_dn = DN(('cn',permission1),
                    api.env.container_permission,api.env.basedn)


permission1_renamed = 'testperm1_rn'
permission1_renamed_dn = DN(('cn',permission1_renamed),
                            api.env.container_permission,api.env.basedn)

permission1_renamed_ucase = 'Testperm_RN'
permission1_renamed_ucase_dn = DN(('cn',permission1_renamed_ucase),
                            api.env.container_permission,api.env.basedn)


permission2 = 'testperm2'
permission2_dn = DN(('cn',permission2),
                    api.env.container_permission,api.env.basedn)

permission3 = 'testperm3'
permission3_dn = DN(('cn',permission3),
                    api.env.container_permission,api.env.basedn)
permission3_attributelevelrights = {
    'member': 'rscwo',
    'seealso': 'rscwo',
    'ipapermissiontype': 'rscwo',
    'cn': 'rscwo',
    'businesscategory': 'rscwo',
    'objectclass': 'rscwo',
    'memberof': 'rscwo',
    'aci': 'rscwo',
    'o': 'rscwo',
    'owner': 'rscwo',
    'ou': 'rscwo',
    'targetgroup': 'rscwo',
    'type': 'rscwo',
    'nsaccountlock': 'rscwo',
    'description': 'rscwo',
    'attrs': 'rscwo',
    'ipapermincludedattr': 'rscwo',
    'ipapermbindruletype': 'rscwo',
    'ipapermdefaultattr': 'rscwo',
    'ipapermexcludedattr': 'rscwo',
    'subtree': 'rscwo',  # old
    'permissions': 'rscwo',  # old
    'ipapermtarget': 'rscwo',
    'ipapermtargetfilter': 'rscwo',
    'ipapermtargetto': 'rscwo',
    'ipapermtargetfrom': 'rscwo',
}

privilege1 = 'testpriv1'
privilege1_dn = DN(('cn',privilege1),
                   api.env.container_privilege,api.env.basedn)

invalid_permission1 = 'bad;perm'

users_dn = DN(api.env.container_user, api.env.basedn)
groups_dn = DN(api.env.container_group, api.env.basedn)
hbac_dn = DN(api.env.container_hbac, api.env.basedn)


@pytest.mark.tier1
class test_old_permission(Declarative):
    default_version = '2.65'

    cleanup_commands = [
        ('permission_del', [permission1], {}),
        ('permission_del', [permission2], {}),
        ('permission_del', [permission3], {}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [
        dict(
            desc='Try to retrieve non-existent %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=errors.NotFound(
                reason='%s: permission not found' % permission1
            ),
        ),
        dict(
            desc='Try to update non-existent %r' % permission1,
            command=('permission_mod', [permission1], dict(permissions='all')),
            expected=errors.NotFound(
                reason='%s: permission not found' % permission1
            ),
        ),
        dict(
            desc='Try to delete non-existent %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.NotFound(
                reason='%s: permission not found' % permission1
            ),
        ),
        dict(
            desc='Search for non-existent %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 permissions matched',
                result=[],
            ),
        ),
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add',
                [permission1],
                dict(
                    type='user',
                    permissions='write',
                ),
            ),
            expected=dict(
                value=permission1,
                summary='Added permission "%s"' % permission1,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type='user',
                    permissions=['write'],
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Try to create duplicate %r' % permission1,
            command=(
                'permission_add',
                [permission1],
                dict(
                    type='user',
                    permissions='write',
                ),
            ),
            expected=errors.DuplicateEntry(
                message='permission with name "%s" already exists' % permission1
            ),
        ),
        dict(
            desc='Create %r' % privilege1,
            command=(
                'privilege_add',
                [privilege1],
                dict(description='privilege desc. 1'),
            ),
            expected=dict(
                value=privilege1,
                summary='Added privilege "%s"' % privilege1,
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=['privilege desc. 1'],
                    objectclass=objectclasses.privilege,
                ),
            ),
        ),
        dict(
            desc='Add permission %r to privilege %r'
            % (permission1, privilege1),
            command=(
                'privilege_add_permission',
                [privilege1],
                dict(permission=permission1),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': ['privilege desc. 1'],
                    'memberof_permission': [permission1],
                },
            ),
        ),
        dict(
            desc='Retrieve %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': 'user',
                    'permissions': ['write'],
                    'ipapermbindruletype': ['permission'],
                    'ipapermissiontype': ['V2', 'SYSTEM'],
                    'subtree': 'ldap:///%s' % users_dn,
                },
            ),
        ),
        dict(
            desc='Retrieve %r with --raw' % permission1,
            command=('permission_show', [permission1], {'raw': True}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member': [privilege1_dn],
                    'aci': [
                        '(targetfilter = "(objectclass=posixaccount)")'
                        + '(version 3.0;acl "permission:testperm";'
                        + 'allow (write) '
                        + 'groupdn = "ldap:///%s";)'
                        % DN(
                            ('cn', 'testperm'),
                            ('cn', 'permissions'),
                            ('cn', 'pbac'),
                            api.env.basedn,
                        )
                    ],
                    'ipapermright': ['write'],
                    'ipapermbindruletype': ['permission'],
                    'ipapermissiontype': ['V2', 'SYSTEM'],
                    'ipapermtargetfilter': ['(objectclass=posixaccount)'],
                    'ipapermlocation': [users_dn],
                },
            ),
        ),
        dict(
            desc='Search for %r with members' % permission1,
            command=('permission_find', [permission1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r using --name with members' % permission1,
            command=(
                'permission_find',
                [],
                {'cn': permission1, 'no_members': False},
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r using --name' % permission1,
            command=('permission_find', [], {'cn': permission1}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for non-existence permission using --name',
            command=('permission_find', [], {'cn': 'notfound'}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 permissions matched',
                result=[],
            ),
        ),
        dict(
            desc='Search for %r with members' % privilege1,
            command=('permission_find', [privilege1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r' % privilege1,
            command=('permission_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with --raw with members' % permission1,
            command=(
                'permission_find',
                [permission1],
                {'raw': True, 'no_members': False},
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member': [privilege1_dn],
                        'aci': [
                            '(targetfilter = "(objectclass=posixaccount)")(version 3.0;acl "permission:testperm";allow (write) groupdn = "ldap:///%s";)'
                            % DN(
                                ('cn', 'testperm'),
                                ('cn', 'permissions'),
                                ('cn', 'pbac'),
                                api.env.basedn,
                            )
                        ],
                        'ipapermright': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'ipapermtargetfilter': ['(objectclass=posixaccount)'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with --raw' % permission1,
            command=('permission_find', [permission1], {'raw': True}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'aci': [
                            '(targetfilter = "(objectclass=posixaccount)")'
                            '(version 3.0;acl "permission:testperm";'
                            'allow (write) groupdn = "ldap:///%s";)'
                            % DN(
                                ('cn', 'testperm'),
                                ('cn', 'permissions'),
                                ('cn', 'pbac'),
                                api.env.basedn,
                            )
                        ],
                        'ipapermright': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'ipapermtargetfilter': ['(objectclass=posixaccount)'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),
        dict(
            desc='Create %r' % permission2,
            command=(
                'permission_add',
                [permission2],
                dict(
                    type='user',
                    permissions='write',
                    setattr='owner=cn=test',
                    addattr='owner=cn=test2',
                ),
            ),
            expected=dict(
                value=permission2,
                summary='Added permission "%s"' % permission2,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result=dict(
                    dn=permission2_dn,
                    cn=[permission2],
                    objectclass=objectclasses.permission,
                    type='user',
                    permissions=['write'],
                    owner=['cn=test', 'cn=test2'],
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Search for %r with members' % permission1,
            command=('permission_find', [permission1], {'no_members': False}),
            expected=dict(
                count=2,
                truncated=False,
                summary='2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=2,
                truncated=False,
                summary='2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with --pkey-only' % permission1,
            command=('permission_find', [permission1], {'pkey_only': True}),
            expected=dict(
                count=2,
                truncated=False,
                summary='2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                    },
                ],
            ),
        ),
        dict(
            desc='Search by ACI attribute with --pkey-only',
            command=(
                'permission_find',
                [],
                {'pkey_only': True, 'attrs': ['krbminpwdlife']},
            ),
            expected=dict(
                count=2,
                truncated=False,
                summary='2 permissions matched',
                result=[
                    {
                        'dn': DN(
                            ('cn', 'System: Modify Group Password Policy'),
                            api.env.container_permission,
                            api.env.basedn,
                        ),
                        'cn': ['System: Modify Group Password Policy'],
                    },
                    {
                        'dn': DN(
                            ('cn', 'System: Read Group Password Policy'),
                            api.env.container_permission,
                            api.env.basedn,
                        ),
                        'cn': ['System: Read Group Password Policy'],
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r with members' % privilege1,
            command=('privilege_find', [privilege1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': ['privilege desc. 1'],
                        'memberof_permission': [permission1],
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r' % privilege1,
            command=('privilege_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': ['privilege desc. 1'],
                    },
                ],
            ),
        ),
        dict(
            desc=(
                'Search for %r with a limit of 1 (truncated) with members'
                % permission1
            ),
            command=(
                'permission_find',
                [permission1],
                dict(sizelimit=1, no_members=False),
            ),
            expected=dict(
                count=1,
                truncated=True,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
                messages=(
                    {
                        'message': (
                            'Search result has been truncated: '
                            'Configured size limit exceeded'
                        ),
                        'code': 13017,
                        'type': 'warning',
                        'name': 'SearchResultTruncated',
                        'data': {'reason': 'Configured size limit exceeded'},
                    },
                ),
            ),
        ),
        dict(
            desc='Search for %r with a limit of 1 (truncated)' % permission1,
            command=('permission_find', [permission1], dict(sizelimit=1)),
            expected=dict(
                count=1,
                truncated=True,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
                messages=(
                    {
                        'message': (
                            'Search result has been truncated: '
                            'Configured size limit exceeded'
                        ),
                        'code': 13017,
                        'type': 'warning',
                        'name': 'SearchResultTruncated',
                        'data': {'reason': 'Configured size limit exceeded'},
                    },
                ),
            ),
        ),
        dict(
            desc='Search for %r with a limit of 2' % permission1,
            command=('permission_find', [permission1], dict(sizelimit=2)),
            expected=dict(
                count=2,
                truncated=False,
                summary='2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': 'user',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                        'subtree': 'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),
        # This tests setting truncated to True in the post_callback of
        # permission_find(). The return order in LDAP is not guaranteed
        # so do not check the actual entry.
        dict(
            desc='Search for permissions by attr with a limit of 1 (truncated)',
            command=(
                'permission_find',
                ['Modify'],
                dict(attrs='ipaenabledflag', sizelimit=1),
            ),
            expected=dict(
                count=1,
                truncated=True,
                summary='1 permission matched',
                result=[
                    lambda res: (
                        DN(res['dn']).endswith(
                            DN(api.env.container_permission, api.env.basedn)
                        )
                        and 'ipapermission' in res['objectclass']
                    )
                ],
                messages=(
                    {
                        'message': (
                            'Search result has been truncated: '
                            'Configured size limit exceeded'
                        ),
                        'code': 13017,
                        'type': 'warning',
                        'name': 'SearchResultTruncated',
                        'data': {'reason': 'Configured size limit exceeded'},
                    },
                ),
            ),
        ),
        dict(
            desc='Update %r' % permission1,
            command=(
                'permission_mod',
                [permission1],
                dict(
                    permissions='read',
                    memberof='ipausers',
                    setattr='owner=cn=other-test',
                    addattr='owner=cn=other-test2',
                ),
            ),
            expected=dict(
                value=permission1,
                summary='Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': (
                            'The permission has read rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'read',
                        },
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    type='user',
                    permissions=['read'],
                    memberof='ipausers',
                    owner=['cn=other-test', 'cn=other-test2'],
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Retrieve %r to verify update' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': 'user',
                    'permissions': ['read'],
                    'memberof': 'ipausers',
                    'ipapermbindruletype': ['permission'],
                    'ipapermissiontype': ['V2', 'SYSTEM'],
                    'subtree': 'ldap:///%s' % users_dn,
                },
            ),
        ),
        dict(
            desc='Try to rename %r to existing permission %r'
            % (permission1, permission2),
            command=(
                'permission_mod',
                [permission1],
                dict(
                    rename=permission2,
                    permissions='all',
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),
        dict(
            desc='Try to rename %r to empty name' % (permission1),
            command=(
                'permission_mod',
                [permission1],
                dict(
                    rename='',
                    permissions='all',
                ),
            ),
            expected=errors.ValidationError(
                name='rename', error='New name can not be empty'
            ),
        ),
        dict(
            desc='Check integrity of original permission %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': 'user',
                    'permissions': ['read'],
                    'memberof': 'ipausers',
                    'ipapermbindruletype': ['permission'],
                    'ipapermissiontype': ['V2', 'SYSTEM'],
                    'subtree': 'ldap:///%s' % users_dn,
                },
            ),
        ),
        dict(
            desc='Rename %r to permission %r'
            % (permission1, permission1_renamed),
            command=(
                'permission_mod',
                [permission1],
                dict(
                    rename=permission1_renamed,
                    permissions='all',
                ),
            ),
            expected=dict(
                value=permission1,
                summary='Modified permission "%s"' % permission1,
                result={
                    'dn': permission1_renamed_dn,
                    'cn': [permission1_renamed],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': 'user',
                    'permissions': ['all'],
                    'memberof': 'ipausers',
                    'ipapermbindruletype': ['permission'],
                    'ipapermissiontype': ['V2', 'SYSTEM'],
                    'subtree': 'ldap:///%s' % users_dn,
                },
            ),
        ),
        dict(
            desc='Rename %r to permission %r'
            % (permission1_renamed, permission1_renamed_ucase),
            command=(
                'permission_mod',
                [permission1_renamed],
                dict(
                    rename=permission1_renamed_ucase,
                    permissions='write',
                ),
            ),
            expected=dict(
                value=permission1_renamed,
                summary='Modified permission "%s"' % permission1_renamed,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result={
                    'dn': permission1_renamed_ucase_dn,
                    'cn': [permission1_renamed_ucase],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': 'user',
                    'permissions': ['write'],
                    'memberof': 'ipausers',
                    'ipapermbindruletype': ['permission'],
                    'ipapermissiontype': ['V2', 'SYSTEM'],
                    'subtree': 'ldap:///%s' % users_dn,
                },
            ),
        ),
        dict(
            desc='Change %r to a subtree type' % permission1_renamed_ucase,
            command=(
                'permission_mod',
                [permission1_renamed_ucase],
                dict(
                    subtree='ldap:///%s'
                    % DN(('cn', 'accounts'), api.env.basedn),
                    type=None,
                ),
            ),
            expected=dict(
                value=permission1_renamed_ucase,
                summary='Modified permission "%s"' % permission1_renamed_ucase,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result=dict(
                    dn=permission1_renamed_ucase_dn,
                    cn=[permission1_renamed_ucase],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    subtree='ldap:///%s'
                    % DN(('cn', 'accounts'), api.env.basedn),
                    permissions=['write'],
                    memberof='ipausers',
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                ),
            ),
        ),
        dict(
            desc='Search for %r using --subtree with members' % permission1,
            command=(
                'permission_find',
                [],
                {
                    'subtree': 'ldap:///%s'
                    % DN(('cn', 'accounts'), api.env.basedn),
                    'no_members': False,
                },
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_renamed_ucase_dn,
                        'cn': [permission1_renamed_ucase],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'subtree': 'ldap:///%s'
                        % DN(('cn', 'accounts'), api.env.basedn),
                        'permissions': ['write'],
                        'memberof': 'ipausers',
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                    },
                ],
            ),
        ),
        dict(
            desc='Search for %r using --subtree' % permission1,
            command=(
                'permission_find',
                [],
                {
                    'subtree': 'ldap:///%s'
                    % DN(('cn', 'accounts'), api.env.basedn)
                },
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': permission1_renamed_ucase_dn,
                        'cn': [permission1_renamed_ucase],
                        'objectclass': objectclasses.permission,
                        'subtree': 'ldap:///%s'
                        % DN(('cn', 'accounts'), api.env.basedn),
                        'permissions': ['write'],
                        'memberof': 'ipausers',
                        'ipapermbindruletype': ['permission'],
                        'ipapermissiontype': ['V2', 'SYSTEM'],
                    },
                ],
            ),
        ),
        dict(
            desc='Search using nonexistent --subtree',
            command=('permission_find', [], {'subtree': 'ldap:///foo=bar'}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 permissions matched',
                result=[],
            ),
        ),
        dict(
            desc='Search using --targetgroup with members',
            command=(
                'permission_find',
                [],
                {'targetgroup': 'ipausers', 'no_members': False},
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': DN(
                            ('cn', 'System: Add User to default group'),
                            api.env.container_permission,
                            api.env.basedn,
                        ),
                        'cn': ['System: Add User to default group'],
                        'objectclass': objectclasses.permission,
                        'member_privilege': ['User Administrators'],
                        'attrs': ['member'],
                        'targetgroup': 'ipausers',
                        'memberindirect_role': ['User Administrator'],
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermtarget': [DN('cn=ipausers', groups_dn)],
                        'subtree': 'ldap:///%s' % groups_dn,
                        'ipapermdefaultattr': ['member'],
                        'ipapermissiontype': ['V2', 'MANAGED', 'SYSTEM'],
                    }
                ],
            ),
        ),
        dict(
            desc='Search using --targetgroup',
            command=('permission_find', [], {'targetgroup': 'ipausers'}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 permission matched',
                result=[
                    {
                        'dn': DN(
                            ('cn', 'System: Add User to default group'),
                            api.env.container_permission,
                            api.env.basedn,
                        ),
                        'cn': ['System: Add User to default group'],
                        'objectclass': objectclasses.permission,
                        'attrs': ['member'],
                        'targetgroup': 'ipausers',
                        'permissions': ['write'],
                        'ipapermbindruletype': ['permission'],
                        'ipapermtarget': [DN('cn=ipausers', groups_dn)],
                        'subtree': 'ldap:///%s' % groups_dn,
                        'ipapermdefaultattr': ['member'],
                        'ipapermissiontype': ['V2', 'MANAGED', 'SYSTEM'],
                    }
                ],
            ),
        ),
        dict(
            desc='Delete %r' % permission1_renamed_ucase,
            command=('permission_del', [permission1_renamed_ucase], {}),
            expected=dict(
                result=dict(failed=''),
                value=permission1_renamed_ucase,
                summary='Deleted permission "%s"' % permission1_renamed_ucase,
            ),
        ),
        dict(
            desc='Try to delete non-existent %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.NotFound(
                reason='%s: permission not found' % permission1
            ),
        ),
        dict(
            desc='Try to retrieve non-existent %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=errors.NotFound(
                reason='%s: permission not found' % permission1
            ),
        ),
        dict(
            desc='Try to update non-existent %r' % permission1,
            command=('permission_mod', [permission1], dict(rename='Foo')),
            expected=errors.NotFound(
                reason='%s: permission not found' % permission1
            ),
        ),
        dict(
            desc='Delete %r' % permission2,
            command=('permission_del', [permission2], {}),
            expected=dict(
                result=dict(failed=''),
                value=permission2,
                summary='Deleted permission "%s"' % permission2,
            ),
        ),
        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 permissions matched',
                result=[],
            ),
        ),
        dict(
            desc='Delete %r' % privilege1,
            command=('privilege_del', [privilege1], {}),
            expected=dict(
                result=dict(failed=''),
                value=privilege1,
                summary='Deleted privilege "%s"' % privilege1,
            ),
        ),
        dict(
            desc='Try to create permission %r with non-existing memberof'
            % permission1,
            command=(
                'permission_add',
                [permission1],
                dict(
                    memberof='nonexisting',
                    permissions='write',
                ),
            ),
            expected=errors.NotFound(reason='nonexisting: group not found'),
        ),
        dict(
            desc='Create memberof permission %r' % permission1,
            command=(
                'permission_add',
                [permission1],
                dict(
                    memberof='editors',
                    permissions='write',
                    type='user',
                ),
            ),
            expected=dict(
                value=permission1,
                summary='Added permission "%s"' % permission1,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof='editors',
                    permissions=['write'],
                    type='user',
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Try to update non-existent memberof of %r' % permission1,
            command=(
                'permission_mod',
                [permission1],
                dict(memberof='nonexisting'),
            ),
            expected=errors.NotFound(reason='nonexisting: group not found'),
        ),
        dict(
            desc='Update memberof permission %r' % permission1,
            command=(
                'permission_mod',
                [permission1],
                dict(
                    memberof='admins',
                ),
            ),
            expected=dict(
                value=permission1,
                summary='Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof='admins',
                    permissions=['write'],
                    type='user',
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Unset memberof of permission %r' % permission1,
            command=(
                'permission_mod',
                [permission1],
                dict(
                    memberof=None,
                ),
            ),
            expected=dict(
                summary='Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                value=permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    permissions=['write'],
                    type='user',
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=dict(
                result=dict(failed=''),
                value=permission1,
                summary='Deleted permission "%s"' % permission1,
            ),
        ),
        dict(
            desc='Create targetgroup permission %r' % permission1,
            command=(
                'permission_add',
                [permission1],
                dict(
                    targetgroup='editors',
                    permissions='write',
                ),
            ),
            expected=dict(
                value=permission1,
                summary='Added permission "%s"' % permission1,
                messages=(
                    {
                        'message': (
                            'The permission has write rights but no '
                            'attributes are set.'
                        ),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        },
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    targetgroup='editors',
                    permissions=['write'],
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    subtree='ldap:///%s' % api.env.basedn,
                ),
            ),
        ),
        dict(
            desc='Try to create invalid %r' % invalid_permission1,
            command=(
                'permission_add',
                [invalid_permission1],
                dict(
                    type='user',
                    permissions='write',
                ),
            ),
            expected=errors.ValidationError(
                name='name',
                error='May only contain letters, numbers, -, _, ., and space',
            ),
        ),
        dict(
            desc='Create %r' % permission3,
            command=(
                'permission_add',
                [permission3],
                dict(type='user', permissions='write', attrs=['cn']),
            ),
            expected=dict(
                value=permission3,
                summary='Added permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type='user',
                    permissions=['write'],
                    attrs=('cn',),
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Retrieve %r with --all --rights' % permission3,
            command=(
                'permission_show',
                [permission3],
                {'all': True, 'rights': True},
            ),
            expected=dict(
                value=permission3,
                summary=None,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type='user',
                    attrs=('cn',),
                    ipapermincludedattr=['cn'],
                    permissions=['write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    ipapermtargetfilter=['(objectclass=posixaccount)'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
        dict(
            desc='Modify %r with --all -rights' % permission3,
            command=(
                'permission_mod',
                [permission3],
                {'all': True, 'rights': True, 'attrs': ['cn', 'uid']},
            ),
            expected=dict(
                value=permission3,
                summary='Modified permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type='user',
                    attrs=('cn', 'uid'),
                    ipapermincludedattr=['cn', 'uid'],
                    permissions=['write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=['permission'],
                    ipapermissiontype=['V2', 'SYSTEM'],
                    ipapermtargetfilter=['(objectclass=posixaccount)'],
                    subtree='ldap:///%s' % users_dn,
                ),
            ),
        ),
    ]
