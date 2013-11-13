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
from ipatests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative
from ipapython.dn import DN

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
                                    'ipapermlocation': u'rscwo',
                                    'o': u'rscwo',
                                    'ipapermallowedattr': u'rscwo',
                                    'ipapermdefaultattr': u'rscwo',
                                    'ipapermexcludedattr': u'rscwo',
                                    'owner': u'rscwo',
                                    'ou': u'rscwo',
                                    'ipapermright': u'rscwo',
                                    'nsaccountlock': u'rscwo',
                                    'description': u'rscwo',
                                    'ipapermtargetfilter': u'rscwo',
                                    'ipapermbindruletype': u'rscwo',
                                    'ipapermlocation': u'rscwo',
                                    'ipapermtarget': u'rscwo',
                                    'type': u'rscwo',
                                    'targetgroup': u'rscwo',
                                   }

privilege1 = u'testpriv1'
privilege1_dn = DN(('cn',privilege1),
                   api.env.container_privilege,api.env.basedn)

invalid_permission1 = u'bad;perm'


users_dn = DN(api.env.container_user, api.env.basedn)
groups_dn = DN(api.env.container_group, api.env.basedn)


class test_permission_negative(Declarative):
    """Make sure invalid operations fail"""

    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
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
            command=('permission_mod', [permission1], dict(ipapermright=u'all')),
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
            desc='Try creating %r with no ipapermright' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermallowedattr=[u'sn'],
                )
            ),
            expected=errors.RequirementError(name='ipapermright'),
        ),

        dict(
            desc='Try creating %r with no target option' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermright=u'write',
                )
            ),
            expected=errors.ValidationError(
                name='target',
                error='there must be at least one target entry specifier '
                      '(e.g. target, targetfilter, attrs)'),
        ),

        dict(
            desc='Try to create invalid %r' % invalid_permission1,
            command=('permission_add', [invalid_permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                )),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, ., and space'),
        ),

        dict(
            desc='Create %r so we can try breaking it' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                ),
            ),
        ),

        dict(
            desc='Try remove ipapermright from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermright=None,
                )
            ),
            expected=errors.RequirementError(name='ipapermright'),
        ),

        dict(
            desc='Try to remove type from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermallowedattr=None,
                    type=None,
                )
            ),
            expected=errors.ValidationError(
                name='target',
                error='there must be at least one target entry specifier '
                      '(e.g. target, targetfilter, attrs)'),
        ),

        dict(
            desc='Try to remove target and memberof from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermallowedattr=None,
                    ipapermtarget=None,
                )
            ),
            expected=errors.ValidationError(
                name='target',
                error='there must be at least one target entry specifier '
                      '(e.g. target, targetfilter, attrs)'),
        ),

        dict(
            desc='Try to rename %r to invalid invalid %r' % (
                permission1, invalid_permission1),
            command=('permission_mod', [permission1], dict(
                    rename=invalid_permission1,
                )),
            expected=errors.ValidationError(name='rename',
                error='May only contain letters, numbers, -, _, ., and space'),
        ),

    ]


class test_permission(Declarative):
    """Misc. tests for the permission plugin"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
        ('permission_del', [permission2], {'force': True}),
        ('permission_del', [permission3], {'force': True}),
        ('permission_del', [permission1_renamed], {'force': True}),
        ('permission_del', [permission1_renamed_ucase], {'force': True}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [

        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
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
                    'objectclass': objectclasses.privilege,
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
                    'type': [u'user'],
                    'ipapermright': [u'write'],
                    'ipapermallowedattr': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
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
                    'ipapermallowedattr': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermright': [u'write'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
                    'aci': ['(targetattr = "sn")'
                            '(target = "ldap:///%(tdn)s")'
                            '(version 3.0;acl "permission:%(name)s";'
                            'allow (write) groupdn = "ldap:///%(pdn)s";)' %
                            {'tdn': DN(('uid', '*'), users_dn),
                             'name': permission1,
                             'pdn': permission1_dn}],
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
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
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
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for non-existent permission using --name',
            command=('permission_find', [], {'cn': u'notfound'}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
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
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
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
                        'member': [privilege1_dn],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermright': [u'write'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
                        'aci': ['(targetattr = "sn")'
                                '(target = "ldap:///%(tdn)s")'
                                '(version 3.0;acl "permission:%(name)s";'
                                'allow (write) groupdn = "ldap:///%(pdn)s";)' %
                                {'tdn': DN(('uid', '*'), users_dn),
                                 'name': permission1,
                                 'pdn': permission1_dn}],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % permission2,
            command=(
                'permission_add', [permission2], dict(
                    type=u'user',
                    ipapermright=u'write',
                    setattr=u'owner=cn=test',
                    addattr=u'owner=cn=test2',
                    ipapermallowedattr=[u'cn'],
                )
            ),
            expected=dict(
                value=permission2,
                summary=u'Added permission "%s"' % permission2,
                result=dict(
                    dn=permission2_dn,
                    cn=[permission2],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    owner=[u'cn=test', u'cn=test2'],
                    ipapermallowedattr=[u'cn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
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
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'cn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
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
                                             'ipapermallowedattr': [u'krbminpwdlife']}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': DN(('cn','Modify Group Password Policy'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'Modify Group Password Policy'],
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
                        'memberof_permission': [permission1],
                    },
                ],
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
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
                    },
                ],
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
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
                        'member_privilege': [privilege1],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'ipapermallowedattr': [u'cn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtarget': [DN(('uid', '*'), users_dn)],
                    },
                ],
            ),
        ),


        # This tests setting truncated to True in the post_callback of
        # permission_find(). The return order in LDAP is not guaranteed
        # but in practice this is the first entry it finds. This is subject
        # to change.
        dict(
            desc='Search for permissions by attr with a limit of 1 (truncated)',
            command=('permission_find', [], dict(ipapermallowedattr=u'ipaenabledflag',
                                                 sizelimit=1)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': DN(('cn', 'Modify HBAC rule'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'Modify HBAC rule'],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [u'HBAC Administrator'],
                        'memberindirect_role': [u'IT Security Specialist'],
                        'ipapermright' : [u'write'],
                        'ipapermallowedattr': [u'servicecategory', u'sourcehostcategory', u'cn', u'description', u'ipaenabledflag', u'accesstime', u'usercategory', u'hostcategory', u'accessruletype', u'sourcehost'],
                        'ipapermtarget': [DN(('ipauniqueid', '*'), ('cn', 'hbac'), api.env.basedn)],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermlocation': [api.env.basedn],
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermright=u'read',
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
                    type=[u'user'],
                    ipapermright=[u'read'],
                    memberof=[u'ipausers'],
                    owner=[u'cn=other-test', u'cn=other-test2'],
                    ipapermallowedattr=[u'sn'],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN('cn=ipausers',
                                                               groups_dn)],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
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
                    'type': [u'user'],
                    'ipapermright': [u'read'],
                    'memberof': [u'ipausers'],
                    'ipapermallowedattr': [u'sn'],
                    'ipapermtargetfilter': [u'(memberOf=%s)' % DN('cn=ipausers',
                                                                  groups_dn)],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
                },
            ),
        ),



        dict(
            desc='Try to rename %r to existing permission %r' % (permission1,
                                                                 permission2),
            command=(
                'permission_mod', [permission1], dict(rename=permission2,
                                                      ipapermright=u'all',)
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Try to rename %r to empty name' % (permission1),
            command=(
                'permission_mod', [permission1], dict(rename=u'',
                                                      ipapermright=u'all',)
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
                    'type': [u'user'],
                    'ipapermright': [u'read'],
                    'memberof': [u'ipausers'],
                    'ipapermallowedattr': [u'sn'],
                    'ipapermtargetfilter': [u'(memberOf=%s)' % DN('cn=ipausers',
                                                                  groups_dn)],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
                },
            ),
        ),


        dict(
            desc='Rename %r to permission %r' % (permission1,
                                                 permission1_renamed),
            command=(
                'permission_mod', [permission1], dict(rename=permission1_renamed,
                                                      ipapermright= u'all',)
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result={
                    'dn': permission1_renamed_dn,
                    'cn': [permission1_renamed],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'all'],
                    'memberof': [u'ipausers'],
                    'ipapermallowedattr': [u'sn'],
                    'ipapermtargetfilter': [u'(memberOf=%s)' % DN('cn=ipausers',
                                                                  groups_dn)],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
                },
            ),
        ),


        dict(
            desc='Rename %r to permission %r' % (permission1_renamed,
                                                 permission1_renamed_ucase),
            command=(
                'permission_mod', [permission1_renamed], dict(rename=permission1_renamed_ucase,
                                                      ipapermright= u'write',)
            ),
            expected=dict(
                value=permission1_renamed,
                summary=u'Modified permission "%s"' % permission1_renamed,
                result={
                    'dn': permission1_renamed_ucase_dn,
                    'cn': [permission1_renamed_ucase],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'write'],
                    'memberof': [u'ipausers'],
                    'ipapermallowedattr': [u'sn'],
                    'ipapermtargetfilter': [u'(memberOf=%s)' % DN('cn=ipausers',
                                                                  groups_dn)],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
                },
            ),
        ),


        dict(
            desc='Change %r to a subtree type' % permission1_renamed_ucase,
            command=(
                'permission_mod', [permission1_renamed_ucase],
                dict(ipapermlocation=users_dn, type=None)
            ),
            expected=dict(
                value=permission1_renamed_ucase,
                summary=u'Modified permission "%s"' % permission1_renamed_ucase,
                result=dict(
                    dn=permission1_renamed_ucase_dn,
                    cn=[permission1_renamed_ucase],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    ipapermlocation=[users_dn],
                    ipapermright=[u'write'],
                    memberof=[u'ipausers'],
                    ipapermallowedattr=[u'sn'],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN('cn=ipausers',
                                                               groups_dn)],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                ),
            ),
        ),

        dict(
            desc='Reset --subtree of %r' % permission2,
            command=(
                'permission_mod', [permission2],
                dict(ipapermlocation=api.env.basedn)
            ),
            expected=dict(
                value=permission2,
                summary=u'Modified permission "%s"' % permission2,
                result={
                    'dn': permission2_dn,
                    'cn': [permission2],
                    'objectclass': objectclasses.permission,
                    'ipapermright': [u'write'],
                    'ipapermallowedattr': [u'cn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermtarget': [DN(('uid', '*'), users_dn)],
                    'ipapermlocation': [api.env.basedn],
                },
            ),
        ),

        dict(
            desc='Search for %r using --subtree' % permission1,
            command=('permission_find', [],
                     {'ipapermlocation': u'ldap:///%s' % users_dn}),
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
                        'ipapermlocation': [users_dn],
                        'ipapermright':[u'write'],
                        'memberof':[u'ipausers'],
                        'ipapermallowedattr': [u'sn'],
                        'ipapermtargetfilter': [u'(memberOf=%s)' % DN(
                            'cn=ipausers', groups_dn)],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search using nonexistent --subtree',
            command=('permission_find', [], {'ipapermlocation': u'foo'}),
            expected=errors.ConversionError(
                name='subtree', error='malformed RDN string = "foo"'),
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
                        'dn': DN(('cn','Add user to default group'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'Add user to default group'],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [u'User Administrators'],
                        'ipapermallowedattr': [u'member'],
                        'targetgroup': [u'ipausers'],
                        'memberindirect_role': [u'User Administrator'],
                        'ipapermright': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermtarget': [DN(
                            'cn=ipausers', api.env.container_group,
                            api.env.basedn)],
                        'ipapermlocation': [api.env.basedn],
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
                    ipapermright=u'write',
                    ipapermallowedattr=[u'cn'],
                )
            ),
            expected=errors.NotFound(reason=u'nonexisting: group not found'),
        ),

        dict(
            desc='Create memberof permission %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    memberof=u'editors',
                    ipapermright=u'write',
                    type=u'user',
                    ipapermallowedattr=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=[u'editors'],
                    ipapermright=[u'write'],
                    type=[u'user'],
                    ipapermallowedattr=[u'sn'],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'editors'),
                                                               groups_dn)],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
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
                    memberof=[u'admins'],
                    ipapermright=[u'write'],
                    type=[u'user'],
                    ipapermallowedattr=[u'sn'],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                               groups_dn)],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
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
                    ipapermright=[u'write'],
                    type=[u'user'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
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
                    ipapermright=u'write',
                    ipapermallowedattr=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    targetgroup=[u'editors'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermtarget=[DN(('cn', 'editors'), groups_dn)],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        dict(
            desc='Create %r' % permission3,
            command=(
                'permission_add', [permission3], dict(
                    type=u'user',
                    ipapermright=u'write',
                    ipapermallowedattr=[u'cn']
                )
            ),
            expected=dict(
                value=permission3,
                summary=u'Added permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=(u'cn',),
                    ipapermbindruletype=[u'permission'],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
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
                    type=[u'user'],
                    ipapermallowedattr=(u'cn',),
                    ipapermright=[u'write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=[u'permission'],
                    ipapermtarget=[DN(('uid', '*'),users_dn)],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        dict(
            desc='Modify %r with --all --rights' % permission3,
            command=('permission_mod', [permission3], {
                'all': True, 'rights': True,
                'ipapermallowedattr': [u'cn', u'uid']}),
            expected=dict(
                value=permission3,
                summary=u'Modified permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermallowedattr=(u'cn',u'uid'),
                    ipapermright=[u'write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=[u'permission'],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        dict(
            desc='Try to modify %r with invalid targetfilter' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermtargetfilter': u"ceci n'est pas un filtre"}),
            expected=errors.ValidationError(
                name='ipapermtargetfilter',
                error='Bad search filter'),
        ),
    ]


class test_permission_sync_attributes(Declarative):
    """Test the effects of setting permission attributes"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermlocation=users_dn,
                    ipapermright=u'write',
                    ipapermallowedattr=u'sn',
                    ipapermtargetfilter=u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn),
                    ipapermtarget=DN(('uid', '*'), users_dn),
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn)],
                    memberof=[u'admins'],
                ),
            ),
        ),

        dict(
            desc='Unset location on %r, verify type is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermlocation=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn)],
                    memberof=[u'admins'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        dict(
            desc='Reset location on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermlocation=users_dn,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn)],
                    memberof=[u'admins'],
                ),
            ),
        ),

        dict(
            desc='Unset target on %r, verify type is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtarget=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn)],
                    memberof=[u'admins'],
                ),
            ),
        ),

        dict(
            desc='Unset targetfilter on %r, verify memberof is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtargetfilter=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        dict(
            desc='Set type of %r to group' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'group',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[groups_dn],
                    ipapermtarget=[DN(('cn', '*'), groups_dn)],
                ),
            ),
        ),

        dict(
            desc='Set target on %r, verify targetgroup is set' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtarget=DN('cn=editors', groups_dn),
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    ipapermlocation=[groups_dn],
                    targetgroup=[u'editors'],
                ),
            ),
        ),
    ]


class test_permission_sync_nice(Declarative):
    """Test the effects of setting convenience options on permissions"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    ipapermallowedattr=u'sn',
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', '*'), users_dn)],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn)],
                    memberof=[u'admins'],
                ),
            ),
        ),

        dict(
            desc='Unset type on %r, verify target & location are gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtargetfilter=[u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn)],
                    memberof=[u'admins'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        dict(
            desc='Unset memberof on %r, verify targetfilter is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    memberof=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        dict(
            desc='Set type of %r to group' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'group',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[groups_dn],
                    ipapermtarget=[DN(('cn', '*'), groups_dn)],
                ),
            ),
        ),

        dict(
            desc='Set targetgroup on %r, verify target is set' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    targetgroup=u'editors',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermallowedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    ipapermlocation=[groups_dn],
                    targetgroup=[u'editors'],
                ),
            ),
        ),
    ]


def _make_permission_flag_tests(flags, expected_message):
    return [

        dict(
            desc='Create %r with flags %s' % (permission1, flags),
            command=(
                'permission_add_noaci', [permission1], dict(
                    ipapermissiontype=flags,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.system_permission,
                    ipapermissiontype=flags,
                ),
            ),
        ),

        dict(
            desc='Try to modify %r' % permission1,
            command=('permission_mod', [permission1], {'type': u'user'}),
            expected=errors.ACIError(info=expected_message),
        ),

        dict(
            desc='Try to delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.ACIError(info=expected_message),
        ),

        dict(
            desc='Delete %r with --force' % permission1,
            command=('permission_del', [permission1], {'force': True}),
            expected=dict(
                result=dict(failed=u''),
                value=permission1,
                summary=u'Deleted permission "%s"' % permission1,
            ),
        ),
    ]


class test_permission_flags(Declarative):
    """Test that permission flags are handled correctly"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = (
        _make_permission_flag_tests(
            [u'SYSTEM'],
            'A SYSTEM permission may not be modified or removed') +
        _make_permission_flag_tests(
            [u'??'],
            'Permission with unknown flag ?? may not be modified or removed') +
        _make_permission_flag_tests(
            [u'SYSTEM', u'??'],
            'Permission with unknown flag ?? may not be modified or removed'))


class test_permission_legacy(Declarative):
    """Tests for non-upgraded permissions"""

    tests = [
        dict(
            desc='Search for all permissions in $SUFFIX',
            command=('permission_find', [],
                     {'ipapermlocation': api.env.basedn}),
            expected=dict(
                count=lambda n: n > 50,
                truncated=False,
                summary=lambda s: True,
                result=lambda s: True,
            ),
        ),
    ]
