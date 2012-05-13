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
Test the `ipalib/plugins/delegation.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipapython.dn import DN

delegation1 = u'testdelegation'
member1 = u'admins'

class test_delegation(Declarative):

    cleanup_commands = [
        ('delegation_del', [delegation1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % delegation1,
            command=('delegation_show', [delegation1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % delegation1),
        ),


        dict(
            desc='Try to update non-existent %r' % delegation1,
            command=('delegation_mod', [delegation1], dict(group=u'admins')),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % delegation1),
        ),


        dict(
            desc='Try to delete non-existent %r' % delegation1,
            command=('delegation_del', [delegation1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % delegation1),
        ),


        dict(
            desc='Search for non-existent %r' % delegation1,
            command=('delegation_find', [delegation1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 delegations matched',
                result=[],
            ),
        ),

        dict(
            desc='Try to create %r for non-existing member group' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=u'street,c,l,st,postalCode',
                     permissions=u'write',
                     group=u'editors',
                     memberof=u'nonexisting',
                ),
            ),
            expected=errors.NotFound(reason=u'nonexisting: group not found'),
        ),

        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=[u'street', u'c', u'l', u'st', u'postalCode'],
                     permissions=u'write',
                     group=u'editors',
                     memberof=u'admins',
                )
            ),
            expected=dict(
                value=delegation1,
                summary=u'Added delegation "%s"' % delegation1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'write'],
                    aciname=delegation1,
                    group=u'editors',
                    memberof=member1,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=[u'street', u'c', u'l', u'st', u'postalCode'],
                     permissions=u'write',
                     group=u'editors',
                     memberof=u'admins',
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
                    'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                    'permissions': [u'write'],
                    'aciname': delegation1,
                    'group': u'editors',
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
                    'aci': u'(targetattr = "street || c || l || st || postalcode")(targetfilter = "(memberOf=%s)")(version 3.0;acl "delegation:testdelegation";allow (write) groupdn = "ldap:///%s";)' % \
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
                summary=u'1 delegation matched',
                result=[
                    {
                    'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                    'permissions': [u'write'],
                    'aciname': delegation1,
                    'group': u'editors',
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
                summary=u'1 delegation matched',
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
                summary=u'1 delegation matched',
                result=[
                    {
                    'aci': u'(targetattr = "street || c || l || st || postalcode")(targetfilter = "(memberOf=%s)")(version 3.0;acl "delegation:testdelegation";allow (write) groupdn = "ldap:///%s";)' % \
                        (DN(('cn', 'admins'), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn),
                         DN(('cn', 'editors'), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)),
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % delegation1,
            command=(
                'delegation_mod', [delegation1], dict(permissions=u'read')
            ),
            expected=dict(
                value=delegation1,
                summary=u'Modified delegation "%s"' % delegation1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'read'],
                    aciname=delegation1,
                    group=u'editors',
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
                    'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                    'permissions': [u'read'],
                    'aciname': delegation1,
                    'group': u'editors',
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
                summary=u'Deleted delegation "%s"' % delegation1,
            )
        ),

    ]
