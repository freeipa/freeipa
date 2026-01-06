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
Test the `ipaserver/plugins/delegation.py` module.
"""

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
from ipapython.dn import DN
import pytest

delegation1 = 'testdelegation'
member1 = 'admins'


@pytest.mark.tier1
class test_delegation(Declarative):

    cleanup_commands = [
        ('delegation_del', [delegation1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % delegation1,
            command=('delegation_show', [delegation1], {}),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % delegation1),
        ),


        dict(
            desc='Try to update non-existent %r' % delegation1,
            command=('delegation_mod', [delegation1], dict(group='admins')),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % delegation1),
        ),


        dict(
            desc='Try to delete non-existent %r' % delegation1,
            command=('delegation_del', [delegation1], {}),
            expected=errors.NotFound(
                reason='ACI with name "%s" not found' % delegation1),
        ),


        dict(
            desc='Search for non-existent %r' % delegation1,
            command=('delegation_find', [delegation1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 delegations matched',
                result=[],
            ),
        ),

        dict(
            desc='Try to create %r for non-existing member group' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs='street,c,l,st,postalCode',
                     permissions='write',
                     group='editors',
                     memberof='nonexisting',
                ),
            ),
            expected=errors.NotFound(reason='nonexisting: group not found'),
        ),

        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=['street', 'c', 'l', 'st', 'postalCode'],
                     permissions='write',
                     group='editors',
                     memberof='admins',
                )
            ),
            expected=dict(
                value=delegation1,
                summary='Added delegation "%s"' % delegation1,
                result=dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions=['write'],
                    aciname=delegation1,
                    group='editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=['street', 'c', 'l', 'st', 'postalCode'],
                     permissions='write',
                     group='editors',
                     memberof='admins',
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % delegation1,
            command=('delegation_show', [delegation1], {}),
            expected=dict(
                value=delegation1,
                summary=None,
                result={
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['write'],
                    'aciname': delegation1,
                    'group': 'editors',
                    'memberof': member1,
                },
            ),
        ),


        dict(
            desc='Retrieve %r with --raw' % delegation1,
            command=('delegation_show', [delegation1], {'raw' : True}),
            expected=dict(
                value=delegation1,
                summary=None,
                result={
                    'aci': '(targetattr = "street || c || l || st || postalcode")(targetfilter = "(memberOf=%s)")(version 3.0;acl "delegation:testdelegation";allow (write) groupdn = "ldap:///%s";)' % \
                        (DN(('cn', 'admins'), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn),
                         DN(('cn', 'editors'), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn))
                },
            ),
        ),


        dict(
            desc='Search for %r' % delegation1,
            command=('delegation_find', [delegation1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 delegation matched',
                result=[
                    {
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['write'],
                    'aciname': delegation1,
                    'group': 'editors',
                    'memberof': member1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --group filter' % delegation1,
            command=('delegation_find', [delegation1], {'group': 'editors'}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 delegation matched',
                result=[
                    {
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['write'],
                    'aciname': delegation1,
                    'group': 'editors',
                    'memberof': member1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --membergroup filter' % delegation1,
            command=('delegation_find', [delegation1], {'memberof': member1}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 delegation matched',
                result=[
                    {
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['write'],
                    'aciname': delegation1,
                    'group': 'editors',
                    'memberof': member1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --pkey-only' % delegation1,
            command=('delegation_find', [delegation1], {'pkey_only' : True}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 delegation matched',
                result=[
                    {
                    'aciname': delegation1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw' % delegation1,
            command=('delegation_find', [delegation1], {'raw' : True}),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 delegation matched',
                result=[
                    {
                    'aci': '(targetattr = "street || c || l || st || postalcode")(targetfilter = "(memberOf=%s)")(version 3.0;acl "delegation:testdelegation";allow (write) groupdn = "ldap:///%s";)' % \
                        (DN(('cn', 'admins'), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn),
                         DN(('cn', 'editors'), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)),
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % delegation1,
            command=(
                'delegation_mod', [delegation1], dict(permissions='read')
            ),
            expected=dict(
                value=delegation1,
                summary='Modified delegation "%s"' % delegation1,
                result=dict(
                    attrs=['street', 'c', 'l', 'st', 'postalcode'],
                    permissions=['read'],
                    aciname=delegation1,
                    group='editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % delegation1,
            command=('delegation_show', [delegation1], {}),
            expected=dict(
                value=delegation1,
                summary=None,
                result={
                    'attrs': ['street', 'c', 'l', 'st', 'postalcode'],
                    'permissions': ['read'],
                    'aciname': delegation1,
                    'group': 'editors',
                    'memberof': member1,
                },
            ),
        ),


        dict(
            desc='Delete %r' % delegation1,
            command=('delegation_del', [delegation1], {}),
            expected=dict(
                result=True,
                value=delegation1,
                summary='Deleted delegation "%s"' % delegation1,
            )
        ),


        dict(
            desc='Create %r with duplicate attrs & perms' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                    attrs=['street', 'street'],
                    permissions=['write', 'write'],
                    group='editors',
                    memberof='admins',
                )
            ),
            expected=dict(
                value=delegation1,
                summary='Added delegation "%s"' % delegation1,
                result=dict(
                    attrs=['street'],
                    permissions=['write'],
                    aciname=delegation1,
                    group='editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Delete %r' % delegation1,
            command=('delegation_del', [delegation1], {}),
            expected=dict(
                result=True,
                value=delegation1,
                summary='Deleted delegation "%s"' % delegation1,
            )
        ),


        dict(
            desc='Create delegation with mobile attr and write permission',
            command=(
                'delegation_add', [u'test_mobile_delegation'], dict(
                    attrs=[u'mobile'],
                    permissions=u'write',
                    group=u'editors',
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=u'test_mobile_delegation',
                summary=u'Added delegation "test_mobile_delegation"',
                result=dict(
                    attrs=[u'mobile'],
                    permissions=[u'write'],
                    aciname=u'test_mobile_delegation',
                    group=u'editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Create delegation with --all flag',
            command=(
                'delegation_add', [u'test_all_flag'], dict(
                    attrs=[u'mobile'],
                    permissions=u'write',
                    group=u'editors',
                    memberof=u'admins',
                    all=True,
                )
            ),
            expected=dict(
                value=u'test_all_flag',
                summary=u'Added delegation "test_all_flag"',
                result=dict(
                    attrs=[u'mobile'],
                    permissions=[u'write'],
                    aciname=u'test_all_flag',
                    group=u'editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Create delegation with --raw flag',
            command=(
                'delegation_add', [u'test_raw_flag'], dict(
                    attrs=[u'mobile'],
                    permissions=u'write',
                    group=u'editors',
                    memberof=u'admins',
                    raw=True,
                )
            ),
            expected=dict(
                value=u'test_raw_flag',
                summary=u'Added delegation "test_raw_flag"',
                result={
                    'aci': u'(targetattr = "mobile")(targetfilter = '
                           u'"(memberOf=%s)")(version 3.0;acl '
                           u'"delegation:test_raw_flag";allow (write) '
                           u'groupdn = "ldap:///%s";)' % (
                               DN(('cn', 'admins'), ('cn', 'groups'),
                                   ('cn', 'accounts'), api.env.basedn),
                               DN(('cn', 'editors'), ('cn', 'groups'),
                                   ('cn', 'accounts'), api.env.basedn))
                },
            ),
        ),


        dict(
            desc='Delete test_mobile_delegation',
            command=('delegation_del', [u'test_mobile_delegation'], {}),
            expected=dict(
                result=True,
                value=u'test_mobile_delegation',
                summary=u'Deleted delegation "test_mobile_delegation"',
            )
        ),


        dict(
            desc='Delete test_all_flag',
            command=('delegation_del', [u'test_all_flag'], {}),
            expected=dict(
                result=True,
                value=u'test_all_flag',
                summary=u'Deleted delegation "test_all_flag"',
            )
        ),


        dict(
            desc='Delete test_raw_flag',
            command=('delegation_del', [u'test_raw_flag'], {}),
            expected=dict(
                result=True,
                value=u'test_raw_flag',
                summary=u'Deleted delegation "test_raw_flag"',
            )
        ),


        dict(
            desc='Create delegation for ipausers group',
            command=(
                'delegation_add', [u'delegation_del_positive_1001'], dict(
                    attrs=[u'mobile'],
                    group=u'ipausers',
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=u'delegation_del_positive_1001',
                summary=u'Added delegation "delegation_del_positive_1001"',
                result=dict(
                    attrs=[u'mobile'],
                    permissions=[u'write'],
                    aciname=u'delegation_del_positive_1001',
                    group=u'ipausers',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Delete delegation_del_positive_1001',
            command=('delegation_del', [u'delegation_del_positive_1001'], {}),
            expected=dict(
                result=True,
                value=u'delegation_del_positive_1001',
                summary=u'Deleted delegation "delegation_del_positive_1001"',
            )
        ),


        dict(
            desc='Create delegation for find, show, and mod tests',
            command=(
                'delegation_add', [u'delegation_find_show_mod_test'], dict(
                    attrs=[u'mobile'],
                    permissions=u'write',
                    group=u'editors',
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=u'delegation_find_show_mod_test',
                summary=u'Added delegation "delegation_find_show_mod_test"',
                result=dict(
                    attrs=[u'mobile'],
                    permissions=[u'write'],
                    aciname=u'delegation_find_show_mod_test',
                    group=u'editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Find delegation by name',
            command=('delegation_find', [u'delegation_find_show_mod_test'], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 delegation matched',
                result=[
                    {
                        'attrs': [u'mobile'],
                        'permissions': [u'write'],
                        'aciname': u'delegation_find_show_mod_test',
                        'group': u'editors',
                        'memberof': member1,
                    },
                ],
            ),
        ),


        dict(
            desc='Find delegation by membergroup',
            command=('delegation_find', [], {'memberof': member1}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 delegation matched',
                result=[
                    {
                        'attrs': [u'mobile'],
                        'permissions': [u'write'],
                        'aciname': u'delegation_find_show_mod_test',
                        'group': u'editors',
                        'memberof': member1,
                    },
                ],
            ),
        ),


        dict(
            desc='Show delegation by name',
            command=('delegation_show', [u'delegation_find_show_mod_test'], {}),
            expected=dict(
                value=u'delegation_find_show_mod_test',
                summary=None,
                result={
                    'attrs': [u'mobile'],
                    'permissions': [u'write'],
                    'aciname': u'delegation_find_show_mod_test',
                    'group': u'editors',
                    'memberof': member1,
                },
            ),
        ),


        dict(
            desc='Modify delegation attrs',
            command=(
                'delegation_mod', [u'delegation_find_show_mod_test'],
                dict(attrs=[u'l'])
            ),
            expected=dict(
                value=u'delegation_find_show_mod_test',
                summary=u'Modified delegation "delegation_find_show_mod_test"',
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'write'],
                    aciname=u'delegation_find_show_mod_test',
                    group=u'editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Modify delegation permissions',
            command=(
                'delegation_mod', [u'delegation_find_show_mod_test'],
                dict(permissions=u'read')
            ),
            expected=dict(
                value=u'delegation_find_show_mod_test',
                summary=u'Modified delegation "delegation_find_show_mod_test"',
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'read'],
                    aciname=u'delegation_find_show_mod_test',
                    group=u'editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Delete delegation_find_show_mod_test',
            command=('delegation_del', [u'delegation_find_show_mod_test'], {}),
            expected=dict(
                result=True,
                value=u'delegation_find_show_mod_test',
                summary=u'Deleted delegation "delegation_find_show_mod_test"',
            )
        ),


        dict(
            desc='Create delegation for BZ tests',
            command=(
                'delegation_add', [u'delegation_bz_test'], dict(
                    attrs=[u'mobile'],
                    permissions=u'write',
                    group=u'ipausers',
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=u'delegation_bz_test',
                summary=u'Added delegation "delegation_bz_test"',
                result=dict(
                    attrs=[u'mobile'],
                    permissions=[u'write'],
                    aciname=u'delegation_bz_test',
                    group=u'ipausers',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Try to modify with non-existent membergroup (BZ 783548)',
            command=(
                'delegation_mod', [u'delegation_bz_test'],
                dict(memberof=u'badmembergroup')
            ),
            expected=errors.NotFound(
                reason=u'badmembergroup: group not found'),
        ),


        dict(
            desc='Try to modify attrs with empty value (BZ 783554)',
            command=(
                'delegation_mod', [u'delegation_bz_test'], dict(attrs=u'')
            ),
            expected=errors.RequirementError(name='attrs'),
        ),


        dict(
            desc='Modify attrs to prepare for next BZ test',
            command=(
                'delegation_mod', [u'delegation_bz_test'], dict(attrs=[u'l'])
            ),
            expected=dict(
                value=u'delegation_bz_test',
                summary=u'Modified delegation "delegation_bz_test"',
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'write'],
                    aciname=u'delegation_bz_test',
                    group=u'ipausers',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Find delegation by group filter (BZ 888524)',
            command=('delegation_find', [], {'group': u'ipausers'}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 delegation matched',
                result=[
                    {
                        'attrs': [u'l'],
                        'permissions': [u'write'],
                        'aciname': u'delegation_bz_test',
                        'group': u'ipausers',
                        'memberof': member1,
                    },
                ],
            ),
        ),


        dict(
            desc='Delete delegation_bz_test',
            command=('delegation_del', [u'delegation_bz_test'], {}),
            expected=dict(
                result=True,
                value=u'delegation_bz_test',
                summary=u'Deleted delegation "delegation_bz_test"',
            )
        ),

    ]
