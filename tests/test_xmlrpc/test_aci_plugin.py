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

aci2=u'selftest1'


class test_aci(Declarative):

    cleanup_commands = [
        ('aci_del', [aci1], {}),
        ('aci_del', [aci2], {}),
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
                summary=u'Created ACI "%s"' % aci1,
                result=dict(
                    aciname=u'%s' % aci1,
                    type=u'user',
                    taskgroup=u'%s' % taskgroup,
                    permissions=[u'add'],
                ),
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
                result=dict(
                    aciname=u'%s' % aci1,
                    type=u'user',
                    taskgroup=u'%s' % taskgroup,
                    permissions=[u'add'],
                ),
            ),
        ),


        dict(
            desc='Search for %r with all=True' % aci1,
            command=(
                'aci_find', [aci1], {'all': True}
            ),
            expected=dict(
                result=[
                    dict(
                        aciname=u'%s' % aci1,
                        type=u'user',
                        taskgroup=u'%s' % taskgroup,
                        permissions=[u'add'],
                    ),
                ],
                summary=u'1 ACI matched',
                count=1,
                truncated=False,
            ),
        ),


        dict(
            desc='Search for %r with minimal attributes' % aci1,
            command=(
                'aci_find', [aci1], {}
            ),
            expected=dict(
                result=[
                    dict(
                        aciname=u'%s' % aci1,
                        type=u'user',
                        taskgroup=u'%s' % taskgroup,
                        permissions=[u'add'],
                    ),
                ],
                summary=u'1 ACI matched',
                count=1,
                truncated=False,
            ),
        ),


        dict(
            desc='Update permissions in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(permissions=u'add,write')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "%s"' % aci1,
                result=dict(
                    aciname=u'%s' % aci1,
                    type=u'user',
                    taskgroup=u'%s' % taskgroup,
                    permissions=[u'add', u'write'],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % aci1,
            command=('aci_show', [aci1], {}),
            expected=dict(
                value=aci1,
                summary=None,
                result=dict(
                    aciname=u'%s' % aci1,
                    type=u'user',
                    taskgroup=u'%s' % taskgroup,
                    permissions=[u'add', u'write'],
                ),
            ),

        ),

        dict(
            desc='Update attributes in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(attrs=u'cn, sn,givenName')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "%s"' % aci1,
                result=dict(
                    aciname=u'%s' % aci1,
                    attrs=[u'cn', u'sn', u'givenName'],
                    type=u'user',
                    taskgroup=u'%s' % taskgroup,
                    permissions=[u'add', u'write'],
                ),
            ),
        ),


        dict(
            desc='Update type in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(type=u'group')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "%s"' % aci1,
                result=dict(
                    aciname=u'%s' % aci1,
                    attrs=[u'cn', u'sn', u'givenName'],
                    type=u'group',
                    taskgroup=u'%s' % taskgroup,
                    permissions=[u'add', u'write'],
                ),
            ),
        ),


        dict(
            desc='Update memberOf in %r' % aci1,
            command=(
                'aci_mod', [aci1], dict(memberof=u'ipausers')
            ),
            expected=dict(
                value=aci1,
                summary=u'Modified ACI "%s"' % aci1,
                result=dict(
                    aciname=u'%s' % aci1,
                    taskgroup=u'%s' % taskgroup,
                    filter=u'(memberOf=cn=%s,cn=taskgroups,cn=accounts,%s)' % (taskgroup, api.env.basedn),
                    attrs=[u'cn', u'sn', u'givenName'],
                    type=u'group',
                    permissions=[u'add', u'write'],
                ),
            ),
        ),


        dict(
            desc='Delete %r' % aci1,
            command=('aci_del', [aci1], {}),
            expected=dict(
                result=True,
                summary=u'Deleted ACI "%s"' % aci1,
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


        dict(
            desc='Create %r' % aci2,
            command=(
                'aci_add', [aci2], dict(permissions=u'write', attrs=(u'givenName',u'sn',u'cn'), selfaci=True)
            ),
            expected=dict(
                value=aci2,
                summary=u'Created ACI "%s"' % aci2,
                result=dict(
                    selfaci=True,
                    aciname=u'%s' % aci2,
                    attrs=[u'givenName', u'sn', u'cn'],
                    permissions=[u'write'],
                ),
            ),
        ),


        dict(
            desc='Update attributes in %r' % aci2,
            command=(
                'aci_mod', [aci2], dict(attrs=(u'givenName',u'sn',u'cn',u'uidNumber'))
            ),
            expected=dict(
                value=aci2,
                summary=u'Modified ACI "%s"' % aci2,
                result=dict(
                    selfaci=True,
                    aciname=u'%s' % aci2,
                    attrs=[u'givenName', u'sn', u'cn', u'uidNumber'],
                    permissions=[u'write'],
                ),
            ),
        ),


        dict(
            desc='Update self ACI with a taskgroup %r' % aci2,
            command=(
                'aci_mod', [aci2], dict(attrs=(u'givenName',u'sn',u'cn',u'uidNumber'), taskgroup=taskgroup)
            ),
            expected=errors.ValidationError(name='target', error='group, taskgroup and self are mutually exclusive'),
        ),


    ]
