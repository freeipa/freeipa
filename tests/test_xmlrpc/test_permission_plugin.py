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
Test the `ipalib/plugins/permission.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipalib.dn import *

permission1 = u'testperm'
permission1_dn = DN(('cn',permission1),
                    api.env.container_permission,api.env.basedn)


permission1_renamed = u'testperm1_rn'
permission1_renamed_dn = DN(('cn',permission1_renamed),
                            api.env.container_permission,api.env.basedn)

permission1_renamed_ucase = u'Testperm_RN'
permission1_renamed_ucase_dn = DN(('cn',permission1_renamed_ucase.lower()),
                            api.env.container_permission,api.env.basedn)


permission2 = u'testperm2'
permission2_dn = DN(('cn',permission2),
                    api.env.container_permission,api.env.basedn)

privilege1 = u'testpriv1'
privilege1_dn = DN(('cn',privilege1),
                   api.env.container_privilege,api.env.basedn)

invalid_permission1 = u'bad;perm'


class test_permission(Declarative):

    cleanup_commands = [
        ('permission_del', [permission1], {}),
        ('permission_del', [permission2], {}),
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
                    dn=lambda x: DN(x) == permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'write'],
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
            expected=errors.DuplicateEntry(),
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
                    dn=lambda x: DN(x) == privilege1_dn,
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
                    'dn': lambda x: DN(x) == privilege1_dn,
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
                    'dn': lambda x: DN(x) == permission1_dn,
                    'cn': [permission1],
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'write'],
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
                    'dn': unicode(permission1_dn),
                    'cn': [permission1],
                    'member': [unicode(privilege1_dn)],
                    'aci': u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "permission:testperm";allow (write) groupdn = "ldap:///cn=testperm,cn=permissions,cn=pbac,%s";)' \
                            % (api.env.basedn, api.env.basedn),
                },
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
                        'dn': lambda x: DN(x) == permission1_dn,
                        'cn': [permission1],
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
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
                        'dn': lambda x: DN(x) == permission1_dn,
                        'cn': [permission1],
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw' % permission1,
            command=('permission_find', [permission1], {'raw' : True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': unicode(permission1_dn),
                        'cn': [permission1],
                        'member': [unicode(privilege1_dn)],
                        'aci': u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "permission:testperm";allow (write) groupdn = "ldap:///cn=testperm,cn=permissions,cn=pbac,%s";)' \
                                % (api.env.basedn, api.env.basedn),
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
                )
            ),
            expected=dict(
                value=permission2,
                summary=u'Added permission "%s"' % permission2,
                result=dict(
                    dn=lambda x: DN(x) == permission2_dn,
                    cn=[permission2],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'write'],
                ),
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
                        'dn': lambda x: DN(x) == permission1_dn,
                        'cn': [permission1],
                        'member_privilege': [privilege1],
                        'type': u'user',
                        'permissions': [u'write'],
                    },
                    {
                        'dn': lambda x: DN(x) == permission2_dn,
                        'cn': [permission2],
                        'type': u'user',
                        'permissions': [u'write'],
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
                        'dn': lambda x: DN(x) == permission1_dn,
                        'cn': [permission1],
                    },
                    {
                        'dn': lambda x: DN(x) == permission2_dn,
                        'cn': [permission2],
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
                        'dn': lambda x: DN(x) == privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                        'memberof_permission': [permission1],
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(permissions=u'read', memberof=u'ipausers')
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=lambda x: DN(x) == permission1_dn,
                    cn=[permission1],
                    member_privilege=[privilege1],
                    type=u'user',
                    permissions=[u'read'],
                    memberof=u'ipausers',
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
                    'dn': lambda x: DN(x) == permission1_dn,
                    'cn': [permission1],
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'read'],
                    'memberof': u'ipausers',
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
                    'dn': lambda x: DN(x) == permission1_dn,
                    'cn': [permission1],
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'read'],
                    'memberof': u'ipausers',
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
                    'dn': lambda x: DN(x) == permission1_renamed_dn,
                    'cn': [permission1_renamed],
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'all'],
                    'memberof': u'ipausers',
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
                    'dn': lambda x: DN(x) == permission1_renamed_ucase_dn,
                    'cn': [permission1_renamed_ucase.lower()],
                    'member_privilege': [privilege1],
                    'type': u'user',
                    'permissions': [u'write'],
                    'memberof': u'ipausers',
                },
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
                    dn=lambda x: DN(x) == permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=u'editors',
                    permissions=[u'write'],
                    type=u'user',
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
                    dn=lambda x: DN(x) == permission1_dn,
                    cn=[permission1],
                    memberof=u'admins',
                    permissions=[u'write'],
                    type=u'user',
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
                    dn=lambda x: DN(x) == permission1_dn,
                    cn=[permission1],
                    permissions=[u'write'],
                    type=u'user',
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
                    dn=lambda x: DN(x) == permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    targetgroup=u'editors',
                    permissions=[u'write'],
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
                error='May only contain letters, numbers, -, _, and space'),
        ),

    ]
