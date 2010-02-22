# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipalib/plugins/rolegroup.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

search = u'test-rolegroup'

rolegroup1 = u'test-rolegroup-1'
rolegroup1_dn = u'cn=%s,cn=rolegroups,cn=accounts,%s' % (
    rolegroup1, api.env.basedn
)

rolegroup2 = u'test-rolegroup-2'
rolegroup2_dn = u'cn=%s,cn=rolegroups,cn=accounts,%s' % (
    rolegroup2, api.env.basedn
)

group1 = u'testgroup1'
group1_dn = u'cn=%s,cn=groups,cn=accounts,%s' % (group1, api.env.basedn)


class test_rolegroup(Declarative):

    cleanup_commands = [
        ('rolegroup_del', [rolegroup1], {}),
        ('rolegroup_del', [rolegroup2], {}),
        ('group_del', [group1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % rolegroup1,
            command=('rolegroup_show', [rolegroup1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % rolegroup1,
            command=('rolegroup_mod', [rolegroup1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % rolegroup1,
            command=('rolegroup_del', [rolegroup1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Search for non-existent %r' % rolegroup1,
            command=('rolegroup_find', [rolegroup1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 rolegroups matched',
                result=[],
            ),
        ),


        dict(
            desc='Create %r' % rolegroup1,
            command=('rolegroup_add', [rolegroup1],
                dict(description=u'rolegroup desc 1')
            ),
            expected=dict(
                value=rolegroup1,
                summary=u'Added rolegroup "test-rolegroup-1"',
                result=dict(
                    dn=rolegroup1_dn,
                    cn=[rolegroup1],
                    description=[u'rolegroup desc 1'],
                    objectclass=objectclasses.rolegroup,
                ),
            ),
        ),


        dict(
            desc='Retrieve %r' % rolegroup1,
            command=('rolegroup_show', [rolegroup1], {}),
            expected=dict(
                value=rolegroup1,
                summary=None,
                result=dict(
                    dn=rolegroup1_dn,
                    cn=[rolegroup1],
                    description=[u'rolegroup desc 1'],
                ),
            ),
        ),


        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'group desc 1')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "testgroup1"',
                result=dict(
                    dn=group1_dn,
                    cn=[group1],
                    description=[u'group desc 1'],
                    objectclass=objectclasses.group,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Add member %r to %r' % (group1, rolegroup1),
            command=('rolegroup_add_member', [rolegroup1], dict(group=group1)),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        user=[],
                        group=[],
                        host=[],
                        hostgroup=[],
                    ),
                ),
                result={
                    'dn': rolegroup1_dn,
                    'cn': [rolegroup1],
                    'description': [u'rolegroup desc 1'],
                    'member_group': [group1],
                }
            ),
        ),


        dict(
            desc='Retrieve %r to verify member-add' % rolegroup1,
            command=('rolegroup_show', [rolegroup1], {}),
            expected=dict(
                value=rolegroup1,
                summary=None,
                result={
                    'dn': rolegroup1_dn,
                    'cn': [rolegroup1],
                    'description': [u'rolegroup desc 1'],
                    'member_group': [group1],
                },
            ),
        ),


        dict(
            desc='Search for %r' % rolegroup1,
            command=('rolegroup_find', [rolegroup1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 rolegroup matched',
                result=[
                    {
                        'dn': rolegroup1_dn,
                        'cn': [rolegroup1],
                        'description': [u'rolegroup desc 1'],
                        'member_group': [group1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % search,
            command=('rolegroup_find', [search], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 rolegroup matched',
                result=[
                    {
                        'dn': rolegroup1_dn,
                        'cn': [rolegroup1],
                        'description': [u'rolegroup desc 1'],
                        'member_group': [group1],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % rolegroup2,
            command=('rolegroup_add', [rolegroup2],
                dict(description=u'rolegroup desc 2')
            ),
            expected=dict(
                value=rolegroup2,
                summary=u'Added rolegroup "test-rolegroup-2"',
                result=dict(
                    dn=rolegroup2_dn,
                    cn=[rolegroup2],
                    description=[u'rolegroup desc 2'],
                    objectclass=objectclasses.rolegroup,
                ),
            ),
        ),


        dict(
            desc='Search for %r' % rolegroup1,
            command=('rolegroup_find', [rolegroup1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 rolegroup matched',
                result=[
                    {
                        'dn': rolegroup1_dn,
                        'cn': [rolegroup1],
                        'description': [u'rolegroup desc 1'],
                        'member_group': [group1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % search,
            command=('rolegroup_find', [search], {}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 rolegroups matched',
                result=[
                    {
                        'dn': rolegroup1_dn,
                        'cn': [rolegroup1],
                        'description': [u'rolegroup desc 1'],
                        'member_group': [group1],
                    },
                    {
                        'dn': rolegroup2_dn,
                        'cn': [rolegroup2],
                        'description': [u'rolegroup desc 2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Updated %r' % rolegroup1,
            command=(
                'rolegroup_mod', [rolegroup1], dict(description=u'New desc 1')
            ),
            expected=dict(
                value=rolegroup1,
                summary=u'Modified rolegroup "test-rolegroup-1"',
                result=dict(
                    cn=[rolegroup1],
                    description=[u'New desc 1'],
                    member_group=[group1],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % rolegroup1,
            command=('rolegroup_show', [rolegroup1], {}),
            expected=dict(
                value=rolegroup1,
                summary=None,
                result={
                    'dn': rolegroup1_dn,
                    'cn': [rolegroup1],
                    'description': [u'New desc 1'],
                    'member_group': [group1],
                },
            ),
        ),


        dict(
            desc='Remove member %r from %r' % (group1, rolegroup1),
            command=('rolegroup_remove_member', [rolegroup1], dict(group=group1)),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        user=[],
                        group=[],
                        host=[],
                        hostgroup=[],
                    ),
                ),
                result={
                    'dn': rolegroup1_dn,
                    'cn': [rolegroup1],
                    'description': [u'New desc 1'],
                },
            ),
        ),


        dict(
            desc='Retrieve %r to verify member-del' % rolegroup1,
            command=('rolegroup_show', [rolegroup1], {}),
            expected=dict(
                value=rolegroup1,
                summary=None,
                result={
                    'dn': rolegroup1_dn,
                    'cn': [rolegroup1],
                    'description': [u'New desc 1'],
                },
            ),
        ),


        dict(
            desc='Delete %r' % group1,
            command=('group_del', [group1], {}),
            expected=dict(
                result=True,
                value=group1,
                summary=u'Deleted group "testgroup1"',
            )
        ),


        dict(
            desc='Delete %r' % rolegroup1,
            command=('rolegroup_del', [rolegroup1], {}),
            expected=dict(
                result=True,
                value=rolegroup1,
                summary=u'Deleted rolegroup "test-rolegroup-1"',
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % rolegroup1,
            command=('rolegroup_del', [rolegroup1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % rolegroup1,
            command=('rolegroup_show', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % rolegroup1,
            command=('rolegroup_mod', [rolegroup1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Search for %r' % search,
            command=('rolegroup_find', [search], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 rolegroup matched',
                result=[
                    {
                        'dn': rolegroup2_dn,
                        'cn': [rolegroup2],
                        'description': [u'rolegroup desc 2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Delete %r' % rolegroup2,
            command=('rolegroup_del', [rolegroup2], {}),
            expected=dict(
                result=True,
                value=rolegroup2,
                summary=u'Deleted rolegroup "test-rolegroup-2"',
            )
        ),


        dict(
            desc='Search for %r' % search,
            command=('rolegroup_find', [search], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 rolegroups matched',
                result=[],
            ),
        ),

    ]
