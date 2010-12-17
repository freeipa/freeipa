# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test the `ipalib/plugins/delegation.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

delegation1 = u'testdelegation'
memberdn1 = u'cn=admins,cn=groups,cn=accounts,%s' % api.env.basedn

class test_delegation(Declarative):

    cleanup_commands = [
        ('delegation_del', [delegation1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % delegation1,
            command=('delegation_show', [delegation1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % delegation1,
            command=('delegation_mod', [delegation1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % delegation1,
            command=('delegation_del', [delegation1], {}),
            expected=errors.NotFound(reason='no such entry'),
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


        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=u'street,c,l,st,postalCode',
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
                    membergroup=u'%s' % memberdn1,
                    filter = u'(memberOf=%s)' % memberdn1
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % delegation1,
            command=(
                'delegation_add', [delegation1], dict(
                     attrs=u'street,c,l,st,postalCode',
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
                    'filter': u'(memberOf=%s)' % memberdn1,
                    'membergroup': u'%s' % memberdn1
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
                    'membergroup': u'%s' % memberdn1,
                    'filter': u'(memberOf=%s)' % memberdn1
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
                    membergroup=u'%s' % memberdn1,
                    filter=u'(memberOf=%s)' % memberdn1
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
                    'membergroup': u'%s' % memberdn1,
                    'filter': u'(memberOf=%s)' % memberdn1
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
