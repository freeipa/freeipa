# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010 Red Hat
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
Test the `ipalib/plugins/aci.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid


aci1=u'test1'
taskgroup = u'testtaskgroup'


class test_aci(Declarative):

    cleanup_commands = [
        ('aci_del', [aci1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % aci1,
            command=('aci_show', [aci1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % aci1,
            command=('aci_mod', [aci1], dict(permissions=u'write')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % aci1,
            command=('aci_del', [aci1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create %r' % aci1,
            command=(
                'aci_add', [aci1], dict(permissions=u'add', type=u'user', taskgroup=taskgroup)
            ),
            expected=dict(
                value=aci1,
                summary=u'Created ACI "test1"',
                result=u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn),
                ),
        ),


        dict(
            desc='Try to create duplicate %r' % aci1,
            command=(
                'aci_add', [aci1], dict(permissions=u'add', type=u'user', taskgroup=taskgroup)
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % aci1,
            command=(
                'aci_show', [aci1], {}
            ),
            expected=dict(
                value=aci1,
                summary=None,
                result=u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn),
                ),
        ),


        dict(
            desc='Search for %r with all=True' % aci1,
            command=(
                'aci_find', [aci1], {'all': True}
            ),
            expected=dict(
                result=[
                    u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn)
                ],
                summary=u'1 ACI matched',
                count=1,
            ),
        ),


        dict(
            desc='Search for %r with minimal attributes' % aci1,
            command=(
                'aci_find', [aci1], {}
            ),
            expected=dict(
                result=[
                    u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn)
                ],
                summary=u'1 ACI matched',
                count=1,
            ),
        ),


        dict(
            desc='Update permissions in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(permissions=u'add,write')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "test1"',
                result=u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add,write) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % aci1,
            command=('aci_show', [aci1], {}),
            expected=dict(
                value=aci1,
                summary=None,
                result=u'(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add,write) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn),
            ),

        ),

        dict(
            desc='Update attributes in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(attrs=u'cn, sn,givenName')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "test1"',
                result=u'(targetattr = "cn || sn || givenName")(target = "ldap:///uid=*,cn=users,cn=accounts,%s")(version 3.0;acl "test1";allow (add,write) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn),
            ),
        ),


        dict(
            desc='Update type in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(type=u'group')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "test1"',
                result=u'(targetattr = "cn || sn || givenName")(target = "ldap:///cn=*,cn=groups,cn=accounts,%s")(version 3.0;acl "test1";allow (add,write) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn),
            ),
        ),


        dict(
            desc='Update memberOf in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(memberof=u'ipausers')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "test1"',
                result=u'(targetattr = "cn || sn || givenName")(targetfilter = "(memberOf=cn=testtaskgroup,cn=taskgroups,cn=accounts,%s)")(target = "ldap:///cn=*,cn=groups,cn=accounts,%s")(version 3.0;acl "test1";allow (add,write) groupdn = "ldap:///cn=testtaskgroup,cn=taskgroups,cn=accounts,%s";)' % (api.env.basedn, api.env.basedn, api.env.basedn),
            ),
        ),


        dict(
            desc='Delete %r' % aci1,
            command=('aci_del', [aci1], {}),
            expected=dict(
                result=True,
                summary=u'Deleted ACI "test1"',
                value=aci1,
            ),
        ),


        dict(
            desc='Try to delete non-existent %r' % aci1,
            command=('aci_del', [aci1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % aci1,
            command=('aci_show', [aci1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % aci1,
            command=('aci_mod', [aci1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


    ]
