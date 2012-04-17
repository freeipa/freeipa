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
Test the `ipalib/plugins/selfservice.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

selfservice1 = u'testself'
invalid_selfservice1 = u'bad+name'

class test_selfservice(Declarative):

    cleanup_commands = [
        ('selfservice_del', [selfservice1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Try to update non-existent %r' % selfservice1,
            command=('selfservice_mod', [selfservice1],
                dict(permissions=u'write')),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Try to delete non-existent %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Search for non-existent %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 selfservices matched',
                result=[],
            ),
        ),


        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % selfservice1,
            command=(
                'selfservice_add', [selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                )
            ),
            expected=dict(
                value=selfservice1,
                summary=u'Added selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % selfservice1,
            command=(
                'selfservice_add', [selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                    'permissions': [u'write'],
                    'selfaci': True,
                    'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Retrieve %r with --raw' % selfservice1,
            command=('selfservice_show', [selfservice1], {'raw':True}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'aci': u'(targetattr = "street || c || l || st || postalcode")(version 3.0;acl "selfservice:testself";allow (write) userdn = "ldap:///self";)',
                },
            ),
        ),


        dict(
            desc='Search for %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),

        dict(
            desc='Search for %r with --pkey-only' % selfservice1,
            command=('selfservice_find', [selfservice1], {'pkey_only' : True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with empty attrs and permissions' % selfservice1,
            command=('selfservice_find', [selfservice1], {'attrs' : None, 'permissions' : None}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw' % selfservice1,
            command=('selfservice_find', [selfservice1], {'raw':True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aci': u'(targetattr = "street || c || l || st || postalcode")(version 3.0;acl "selfservice:testself";allow (write) userdn = "ldap:///self";)'
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % selfservice1,
            command=(
                'selfservice_mod', [selfservice1], dict(permissions=u'read')
            ),
            expected=dict(
                value=selfservice1,
                summary=u'Modified selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'read'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'read'],
                        'selfaci': True,
                        'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Try to update %r with empty permissions' % selfservice1,
            command=(
                'selfservice_mod', [selfservice1], dict(permissions=None)
            ),
            expected=errors.RequirementError(name='permissions'),
        ),


        dict(
            desc='Retrieve %r to verify invalid update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'read'],
                        'selfaci': True,
                        'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Delete %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=dict(
                result=True,
                value=selfservice1,
                summary=u'Deleted selfservice "%s"' % selfservice1,
            )
        ),

        dict(
            desc='Create invalid %r' % invalid_selfservice1,
            command=(
                'selfservice_add', [invalid_selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                )
            ),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, and space'),
        ),

    ]
