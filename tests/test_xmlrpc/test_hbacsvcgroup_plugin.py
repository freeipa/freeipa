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
Test the `ipalib.plugins.hbacsvcgroup` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid
from tests.test_xmlrpc import objectclasses
from ipapython.dn import DN

hbacsvcgroup1 = u'testhbacsvcgroup1'
dn1 = DN(('cn',hbacsvcgroup1),('cn','hbacservicegroups'),('cn','hbac'),
         api.env.basedn)

hbacsvc1 = u'sshd'
hbacsvc_dn1 = DN(('cn',hbacsvc1),('cn','hbacservices'),('cn','hbac'),
                 api.env.basedn)


class test_hbacsvcgroup(Declarative):

    cleanup_commands = [
        ('hbacsvcgroup_del', [hbacsvcgroup1], {}),
        ('hbacsvc_del', [hbacsvc1], {}),
    ]

    tests=[

        dict(
            desc='Try to retrieve non-existent %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_show', [hbacsvcgroup1], {}),
            expected=errors.NotFound(
                reason=u'%s: HBAC service group not found' % hbacsvcgroup1),
        ),


        dict(
            desc='Try to update non-existent %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_mod', [hbacsvcgroup1],
                dict(description=u'Updated hbacsvcgroup 1')
            ),
            expected=errors.NotFound(
                reason=u'%s: HBAC service group not found' % hbacsvcgroup1),
        ),


        dict(
            desc='Try to delete non-existent %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_del', [hbacsvcgroup1], {}),
            expected=errors.NotFound(
                reason=u'%s: HBAC service group not found' % hbacsvcgroup1),
        ),


        dict(
            desc='Create %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_add', [hbacsvcgroup1],
                dict(description=u'Test hbacsvcgroup 1')
            ),
            expected=dict(
                value=hbacsvcgroup1,
                summary=u'Added HBAC service group "testhbacsvcgroup1"',
                result=dict(
                    dn=dn1,
                    cn=[hbacsvcgroup1],
                    objectclass=objectclasses.hbacsvcgroup,
                    description=[u'Test hbacsvcgroup 1'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_add', [hbacsvcgroup1],
                dict(description=u'Test hbacsvcgroup 1')
            ),
            expected=errors.DuplicateEntry(
                message=u'HBAC service group with name "%s" already exists' %
                    hbacsvcgroup1),
        ),


        dict(
            desc='Create service %r' % hbacsvc1,
            command=('hbacsvc_add', [hbacsvc1],
                dict(
                    description=u'Test service 1',
                ),
            ),
            expected=dict(
                value=hbacsvc1,
                summary=u'Added HBAC service "%s"' % hbacsvc1,
                result=dict(
                    dn=hbacsvc_dn1,
                    cn=[hbacsvc1],
                    description=[u'Test service 1'],
                    objectclass=objectclasses.hbacsvc,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc=u'Add service %r to %r' % (hbacsvc1, hbacsvcgroup1),
            command=(
                'hbacsvcgroup_add_member', [hbacsvcgroup1], dict(hbacsvc=hbacsvc1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        hbacsvc=tuple(),
                    ),
                ),
                result={
                    'dn': dn1,
                    'cn': [hbacsvcgroup1],
                    'description': [u'Test hbacsvcgroup 1'],
                    'member_hbacsvc': [hbacsvc1],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_show', [hbacsvcgroup1], {}),
            expected=dict(
                value=hbacsvcgroup1,
                summary=None,
                result={
                    'dn': dn1,
                    'member_hbacsvc': [hbacsvc1],
                    'cn': [hbacsvcgroup1],
                    'description': [u'Test hbacsvcgroup 1'],
                },
            ),
        ),


        dict(
            desc='Search for %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_find', [], dict(cn=hbacsvcgroup1)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 HBAC service group matched',
                result=[
                    {
                        'dn': dn1,
                        'member_hbacsvc': [hbacsvc1],
                        'cn': [hbacsvcgroup1],
                        'description': [u'Test hbacsvcgroup 1'],
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_mod', [hbacsvcgroup1],
                dict(description=u'Updated hbacsvcgroup 1')
            ),
            expected=dict(
                value=hbacsvcgroup1,
                summary=u'Modified HBAC service group "testhbacsvcgroup1"',
                result=dict(
                    cn=[hbacsvcgroup1],
                    description=[u'Updated hbacsvcgroup 1'],
                    member_hbacsvc=[hbacsvc1],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % hbacsvcgroup1,
            command=('hbacsvcgroup_show', [hbacsvcgroup1], {}),
            expected=dict(
                value=hbacsvcgroup1,
                summary=None,
                result={
                    'dn': dn1,
                    'member_hbacsvc': [hbacsvc1],
                    'cn': [hbacsvcgroup1],
                    'description': [u'Updated hbacsvcgroup 1'],
                },
            ),
        ),


        dict(
            desc='Remove service %r from %r' % (hbacsvc1, hbacsvcgroup1),
            command=('hbacsvcgroup_remove_member', [hbacsvcgroup1],
                dict(hbacsvc=hbacsvc1)
            ),
            expected=dict(
                failed=dict(
                    member=dict(
                        hbacsvc=tuple(),
                    ),
                ),
                completed=1,
                result={
                    'dn': dn1,
                    'cn': [hbacsvcgroup1],
                    'description': [u'Updated hbacsvcgroup 1'],
                },
            ),
        ),


        dict(
            desc='Delete %r' % hbacsvcgroup1,
            command=('hbacsvcgroup_del', [hbacsvcgroup1], {}),
            expected=dict(
                value=hbacsvcgroup1,
                summary=u'Deleted HBAC service group "testhbacsvcgroup1"',
                result=dict(failed=u''),
            ),
        ),


        dict(
            desc='Delete service %r' % hbacsvc1,
            command=('hbacsvc_del', [hbacsvc1], {}),
            expected=dict(
                value=hbacsvc1,
                summary=u'Deleted HBAC service "%s"' % hbacsvc1,
                result=dict(failed=u''),
            ),
        )

    ]
