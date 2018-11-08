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

permission1 = u'testperm'
permission1_dn = DN(('cn',permission1),
                    api.env.container_permission,api.env.basedn)


permission1_renamed = u'testperm1_rn'
permission1_renamed_dn = DN(('cn',permission1_renamed),
                            api.env.container_permission,api.env.basedn)

permission1_renamed_ucase = u'Testperm_RN'
permission1_renamed_ucase_dn = DN(('cn',permission1_renamed_ucase),
                            api.env.container_permission,api.env.basedn)


permission2 = u'testperm2'
permission2_dn = DN(('cn',permission2),
                    api.env.container_permission,api.env.basedn)

permission3 = u'testperm3'
permission3_dn = DN(('cn',permission3),
                    api.env.container_permission,api.env.basedn)
permission3_attributelevelrights = {
                                     'member': u'rscwo',
                                     'seealso': u'rscwo',
                                     'ipapermissiontype': u'rscwo',
                                     'cn': u'rscwo',
                                     'businesscategory': u'rscwo',
                                     'objectclass': u'rscwo',
                                     'memberof': u'rscwo',
                                     'aci': u'rscwo',
                                     'o': u'rscwo',
                                     'owner': u'rscwo',
                                     'ou': u'rscwo',
                                     'targetgroup': u'rscwo',
                                     'type': u'rscwo',
                                     'nsaccountlock': u'rscwo',
                                     'description': u'rscwo',
                                     'attrs': u'rscwo',
                                     'ipapermincludedattr': u'rscwo',
                                     'ipapermbindruletype': u'rscwo',
                                     'ipapermdefaultattr': u'rscwo',
                                     'ipapermexcludedattr': u'rscwo',
                                     'subtree': u'rscwo',  # old
                                     'permissions': u'rscwo',  # old
                                     'ipapermtarget': u'rscwo',
                                     'ipapermtargetfilter': u'rscwo',
                                     'ipapermtargetto': u'rscwo',
                                     'ipapermtargetfrom': u'rscwo',
                                   }

privilege1 = u'testpriv1'
privilege1_dn = DN(('cn',privilege1),
                   api.env.container_privilege,api.env.basedn)

invalid_permission1 = u'bad;perm'

users_dn = DN(api.env.container_user, api.env.basedn)
groups_dn = DN(api.env.container_group, api.env.basedn)
hbac_dn = DN(api.env.container_hbac, api.env.basedn)


@pytest.mark.tier1
class test_old_permission(Declarative):
    default_version = u'2.65'

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
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to update non-existent %r' % permission1,
            command=('permission_mod', [permission1], dict(permissions=u'all')),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to delete non-existent %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Search for non-existent %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),


        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                     type=u'user',
                     permissions=u'write',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                     type=u'user',
                     permissions=u'write',
                ),
            ),
            expected=errors.DuplicateEntry(
                message='permission with name "%s" already exists' % permission1),
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
            desc='Add permission %r to privilege %r' % (permission1, privilege1),
            command=('privilege_add_permission', [privilege1],
                dict(permission=permission1)
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
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1],
                }
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
                    'type': u'user',
                    'permissions': [u'write'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'V2', u'SYSTEM'],
                    'subtree': u'ldap:///%s' % users_dn,
                },
            ),
        ),


        dict(
            desc='Retrieve %r with --raw' % permission1,
            command=('permission_show', [permission1], {'raw' : True}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member': [privilege1_dn],
                    'aci': [u'(targetfilter = "(objectclass=posixaccount)")'+
                            u'(version 3.0;acl "permission:testperm";' +
                            u'allow (write) ' +
                            u'groupdn = "ldap:///%s";)' % DN(
                               ('cn', 'testperm'), ('cn', 'permissions'),
                               ('cn', 'pbac'), api.env.basedn)],
                    'ipapermright': [u'write'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'V2', u'SYSTEM'],
                    'ipapermtargetfilter': [u'(objectclass=posixaccount)'],
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
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
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
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --name with members' % permission1,
            command=('permission_find', [], {
                'cn': permission1, 'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
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
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for non-existence permission using --name',
            command=('permission_find', [], {'cn': u'notfound'}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),


        dict(
            desc='Search for %r with members' % privilege1,
            command=('permission_find', [privilege1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
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
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw with members' % permission1,
            command=('permission_find', [permission1], {
                'raw': True, 'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member': [privilege1_dn],
                        'aci': [u'(targetfilter = "(objectclass=posixaccount)")(version 3.0;acl "permission:testperm";allow (write) groupdn = "ldap:///%s";)' % \
                             DN(('cn', 'testperm'), ('cn', 'permissions'), ('cn', 'pbac'), api.env.basedn)],
                        'ipapermright': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'ipapermtargetfilter': [u'(objectclass=posixaccount)'],
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
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'aci': [
                            u'(targetfilter = "(objectclass=posixaccount)")'
                            u'(version 3.0;acl "permission:testperm";'
                            u'allow (write) groupdn = "ldap:///%s";)' %
                            DN(
                                ('cn', 'testperm'), ('cn', 'permissions'),
                                ('cn', 'pbac'), api.env.basedn
                            )
                        ],
                        'ipapermright': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'ipapermtargetfilter': [u'(objectclass=posixaccount)'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % permission2,
            command=(
                'permission_add', [permission2], dict(
                     type=u'user',
                     permissions=u'write',
                     setattr=u'owner=cn=test',
                     addattr=u'owner=cn=test2',
                )
            ),
            expected=dict(
                value=permission2,
                summary=u'Added permission "%s"' % permission2,
                result=dict(
                    dn=permission2_dn,
                    cn=[permission2],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'write'],
                    owner=[u'cn=test', u'cn=test2'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),


        dict(
            desc='Search for %r with members' % permission1,
            command=('permission_find', [permission1], {'no_members': False}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
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
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --pkey-only' % permission1,
            command=('permission_find', [permission1], {'pkey_only' : True}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
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
            command=('permission_find', [], {'pkey_only': True,
                                             'attrs': [u'krbminpwdlife']}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': DN(('cn', 'System: Modify Group Password Policy'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Modify Group Password Policy'],
                    },
                    {
                        'dn': DN(('cn', 'System: Read Group Password Policy'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Read Group Password Policy'],
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
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
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
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                    },
                ],
            ),
        ),


        dict(
            desc=('Search for %r with a limit of 1 (truncated) with members' %
                  permission1),
            command=('permission_find', [permission1], dict(
                sizelimit=1, no_members=False)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
                messages=({
                    'message': (u'Search result has been truncated: '
                                u'Configured size limit exceeded'),
                    'code': 13017,
                    'type': u'warning',
                    'name': u'SearchResultTruncated',
                    'data': {
                        'reason': u"Configured size limit exceeded"
                    }
                },),
            ),
        ),


        dict(
            desc='Search for %r with a limit of 1 (truncated)' % permission1,
            command=('permission_find', [permission1], dict(sizelimit=1)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
                messages=({
                    'message': (u'Search result has been truncated: '
                                u'Configured size limit exceeded'),
                    'code': 13017,
                    'type': u'warning',
                    'name': u'SearchResultTruncated',
                    'data': {
                        'reason': u"Configured size limit exceeded"
                    }
                },),
            ),
        ),


        dict(
            desc='Search for %r with a limit of 2' % permission1,
            command=('permission_find', [permission1], dict(sizelimit=2)),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': u'user',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                        'subtree': u'ldap:///%s' % users_dn,
                    },
                ],
            ),
        ),


        # This tests setting truncated to True in the post_callback of
        # permission_find(). The return order in LDAP is not guaranteed
        # so do not check the actual entry.
        dict(
            desc='Search for permissions by attr with a limit of 1 (truncated)',
            command=('permission_find', [u'Modify'],
                     dict(attrs=u'ipaenabledflag', sizelimit=1)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[lambda res:
                    DN(res['dn']).endswith(DN(api.env.container_permission,
                                              api.env.basedn)) and
                    'ipapermission' in res['objectclass']],
                messages=({
                    'message': (u'Search result has been truncated: '
                                u'Configured size limit exceeded'),
                    'code': 13017,
                    'type': u'warning',
                    'name': u'SearchResultTruncated',
                    'data': {
                        'reason': u"Configured size limit exceeded"
                    }
                },),
            ),
        ),


        dict(
            desc='Update %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    permissions=u'read',
                    memberof=u'ipausers',
                    setattr=u'owner=cn=other-test',
                    addattr=u'owner=cn=other-test2',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    type=u'user',
                    permissions=[u'read'],
                    memberof=u'ipausers',
                    owner=[u'cn=other-test', u'cn=other-test2'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
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
                    'type': u'user',
                    'permissions': [u'read'],
                    'memberof': u'ipausers',
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'V2', u'SYSTEM'],
                    'subtree': u'ldap:///%s' % users_dn,
                },
            ),
        ),



        dict(
            desc='Try to rename %r to existing permission %r' % (permission1,
                                                                 permission2),
            command=(
                'permission_mod', [permission1], dict(rename=permission2,
                                                      permissions=u'all',)
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Try to rename %r to empty name' % (permission1),
            command=(
                'permission_mod', [permission1], dict(rename=u'',
                                                      permissions=u'all',)
            ),
            expected=errors.ValidationError(name='rename',
                                    error=u'New name can not be empty'),
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
                    'type': u'user',
                    'permissions': [u'read'],
                    'memberof': u'ipausers',
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'V2', u'SYSTEM'],
                    'subtree': u'ldap:///%s' % users_dn,
                },
            ),
        ),


        dict(
            desc='Rename %r to permission %r' % (permission1,
                                                 permission1_renamed),
            command=(
                'permission_mod', [permission1], dict(rename=permission1_renamed,
                                                      permissions= u'all',)
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result={
                    'dn': permission1_renamed_dn,
                    'cn': [permission1_renamed],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'all'],
                    'memberof': u'ipausers',
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'V2', u'SYSTEM'],
                    'subtree': u'ldap:///%s' % users_dn,
                },
            ),
        ),


        dict(
            desc='Rename %r to permission %r' % (permission1_renamed,
                                                 permission1_renamed_ucase),
            command=(
                'permission_mod', [permission1_renamed], dict(rename=permission1_renamed_ucase,
                                                      permissions= u'write',)
            ),
            expected=dict(
                value=permission1_renamed,
                summary=u'Modified permission "%s"' % permission1_renamed,
                result={
                    'dn': permission1_renamed_ucase_dn,
                    'cn': [permission1_renamed_ucase],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'write'],
                    'memberof': u'ipausers',
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'V2', u'SYSTEM'],
                    'subtree': u'ldap:///%s' % users_dn,
                },
            ),
        ),


        dict(
            desc='Change %r to a subtree type' % permission1_renamed_ucase,
            command=(
                'permission_mod', [permission1_renamed_ucase],
                dict(subtree=u'ldap:///%s' % DN(('cn', 'accounts'), api.env.basedn),
                     type=None)
            ),
            expected=dict(
                value=permission1_renamed_ucase,
                summary=u'Modified permission "%s"' % permission1_renamed_ucase,
                result=dict(
                    dn=permission1_renamed_ucase_dn,
                    cn=[permission1_renamed_ucase],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    subtree=u'ldap:///%s' % DN(('cn', 'accounts'), api.env.basedn),
                    permissions=[u'write'],
                    memberof=u'ipausers',
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                ),
            ),
        ),


        dict(
            desc='Search for %r using --subtree with members' % permission1,
            command=('permission_find', [], {
                'subtree': u'ldap:///%s' % DN(
                    ('cn', 'accounts'), api.env.basedn),
                'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn':permission1_renamed_ucase_dn,
                        'cn':[permission1_renamed_ucase],
                        'objectclass': objectclasses.permission,
                        'member_privilege':[privilege1],
                        'subtree':u'ldap:///%s' % DN(('cn', 'accounts'), api.env.basedn),
                        'permissions':[u'write'],
                        'memberof':u'ipausers',
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --subtree' % permission1,
            command=('permission_find', [], {
                'subtree': u'ldap:///%s' % DN(
                    ('cn', 'accounts'), api.env.basedn)}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn':permission1_renamed_ucase_dn,
                        'cn':[permission1_renamed_ucase],
                        'objectclass': objectclasses.permission,
                        'subtree':u'ldap:///%s' % DN(
                            ('cn', 'accounts'), api.env.basedn),
                        'permissions':[u'write'],
                        'memberof':u'ipausers',
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'V2', u'SYSTEM'],
                    },
                ],
            ),
        ),


        dict(
            desc='Search using nonexistent --subtree',
            command=('permission_find', [], {'subtree': u'ldap:///foo=bar'}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),


        dict(
            desc='Search using --targetgroup with members',
            command=('permission_find', [], {
                'targetgroup': u'ipausers', 'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': DN(('cn', 'System: Add User to default group'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Add User to default group'],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [u'User Administrators'],
                        'attrs': [u'member'],
                        'targetgroup': u'ipausers',
                        'memberindirect_role': [u'User Administrator'],
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermtarget': [DN('cn=ipausers', groups_dn)],
                        'subtree': u'ldap:///%s' % groups_dn,
                        'ipapermdefaultattr': [u'member'],
                        'ipapermissiontype': [u'V2', u'MANAGED', u'SYSTEM'],
                    }
                ],
            ),
        ),


        dict(
            desc='Search using --targetgroup',
            command=('permission_find', [], {'targetgroup': u'ipausers'}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': DN(('cn', 'System: Add User to default group'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Add User to default group'],
                        'objectclass': objectclasses.permission,
                        'attrs': [u'member'],
                        'targetgroup': u'ipausers',
                        'permissions': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermtarget': [DN('cn=ipausers', groups_dn)],
                        'subtree': u'ldap:///%s' % groups_dn,
                        'ipapermdefaultattr': [u'member'],
                        'ipapermissiontype': [u'V2', u'MANAGED', u'SYSTEM'],
                    }
                ],
            ),
        ),


        dict(
            desc='Delete %r' % permission1_renamed_ucase,
            command=('permission_del', [permission1_renamed_ucase], {}),
            expected=dict(
                result=dict(failed=u''),
                value=permission1_renamed_ucase,
                summary=u'Deleted permission "%s"' % permission1_renamed_ucase,
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to update non-existent %r' % permission1,
            command=('permission_mod', [permission1], dict(rename=u'Foo')),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Delete %r' % permission2,
            command=('permission_del', [permission2], {}),
            expected=dict(
                result=dict(failed=u''),
                value=permission2,
                summary=u'Deleted permission "%s"' % permission2,
            )
        ),


        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),


        dict(
            desc='Delete %r' % privilege1,
            command=('privilege_del', [privilege1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=privilege1,
                summary=u'Deleted privilege "%s"' % privilege1,
            )
        ),

        dict(
            desc='Try to create permission %r with non-existing memberof' % permission1,
            command=(
                'permission_add', [permission1], dict(
                     memberof=u'nonexisting',
                     permissions=u'write',
                )
            ),
            expected=errors.NotFound(reason=u'nonexisting: group not found'),
        ),

        dict(
            desc='Create memberof permission %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                     memberof=u'editors',
                     permissions=u'write',
                     type=u'user',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=u'editors',
                    permissions=[u'write'],
                    type=u'user',
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),

        dict(
            desc='Try to update non-existent memberof of %r' % permission1,
            command=('permission_mod', [permission1], dict(
                memberof=u'nonexisting')),
            expected=errors.NotFound(reason=u'nonexisting: group not found'),
        ),

        dict(
            desc='Update memberof permission %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                     memberof=u'admins',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=u'admins',
                    permissions=[u'write'],
                    type=u'user',
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),

        dict(
            desc='Unset memberof of permission %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                     memberof=None,
                )
            ),
            expected=dict(
                summary=u'Modified permission "%s"' % permission1,
                value=permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    permissions=[u'write'],
                    type=u'user',
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),


        dict(
            desc='Delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=permission1,
                summary=u'Deleted permission "%s"' % permission1,
            )
        ),


        dict(
            desc='Create targetgroup permission %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                     targetgroup=u'editors',
                     permissions=u'write',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    targetgroup=u'editors',
                    permissions=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    subtree=u'ldap:///%s' % api.env.basedn,
                ),
            ),
        ),

        dict(
            desc='Try to create invalid %r' % invalid_permission1,
            command=('permission_add', [invalid_permission1], dict(
                     type=u'user',
                     permissions=u'write',
                )),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, ., and space'),
        ),

        dict(
            desc='Create %r' % permission3,
            command=(
                'permission_add', [permission3], dict(
                     type=u'user',
                     permissions=u'write',
                     attrs=[u'cn']
                )
            ),
            expected=dict(
                value=permission3,
                summary=u'Added permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'write'],
                    attrs=(u'cn',),
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),

        dict(
            desc='Retrieve %r with --all --rights' % permission3,
            command=('permission_show', [permission3], {'all' : True, 'rights' : True}),
            expected=dict(
                value=permission3,
                summary=None,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    attrs=(u'cn',),
                    ipapermincludedattr=[u'cn'],
                    permissions=[u'write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),

        dict(
            desc='Modify %r with --all -rights' % permission3,
            command=('permission_mod', [permission3], {'all' : True, 'rights': True, 'attrs':[u'cn',u'uid']}),
            expected=dict(
                value=permission3,
                summary=u'Modified permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    attrs=(u'cn',u'uid'),
                    ipapermincludedattr=[u'cn', u'uid'],
                    permissions=[u'write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'V2', u'SYSTEM'],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    subtree=u'ldap:///%s' % users_dn,
                ),
            ),
        ),
    ]
