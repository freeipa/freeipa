# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipalib/plugins/group.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid

group1 = u'testgroup1'
group2 = u'testgroup2'


class test_group(Declarative):
    cleanup_commands = [
        ('group_del', [group1], {}),
        ('group_del', [group2], {}),
    ]

    tests = [

        ################
        # create group1:
        dict(
            desc='Try to retrieve non-existent %r' % group1,
            command=('group_show', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group1,
            command=('group_mod', [group1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % group1,
            command=('group_del', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc 1')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "testgroup1"',
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    objectclass=objectclasses.group,
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'cn=testgroup1,cn=groups,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc 1')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                summary=None,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    dn=u'cn=testgroup1,cn=groups,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Updated %r' % group1,
            command=(
                'group_mod', [group1], dict(description=u'New desc 1')
            ),
            expected=dict(
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                ),
                summary=u'Modified group "testgroup1"',
                value=group1,
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                    dn=u'cn=testgroup1,cn=groups,cn=accounts,' + api.env.basedn,
                ),
                summary=None,
            ),
        ),


        # FIXME: The return value is totally different here than from the above
        # group_mod() test.  I think that for all *_mod() commands we should
        # just return the entry exactly as *_show() does.
        dict(
            desc='Updated %r to promote it to a posix group' % group1,
            command=('group_mod', [group1], dict(posix=True)),
            expected=dict(
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                    gidnumber=[fuzzy_digits],
                ),
                value=group1,
                summary=u'Modified group "testgroup1"',
            ),
        ),


        dict(
            desc="Retrieve %r to verify it's a posix group" % group1,
            command=('group_show', [group1], {}),
            expected=dict(
                value=group1,
                result=dict(
                    cn=[group1],
                    description=(u'New desc 1',),
                    dn=u'cn=testgroup1,cn=groups,cn=accounts,' + api.env.basedn,
                    gidnumber=[fuzzy_digits],
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r' % group1,
            command=('group_find', [], dict(cn=group1)),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        #dn=u'cn=%s,cn=groups,cn=accounts,%s' % (group1, api.env.basedn),
                        cn=[group1],
                        description=[u'New desc 1'],
                        gidnumber=[fuzzy_digits],
                    ),
                ],
                summary=u'1 group matched',
            ),
        ),



        ################
        # create group2:
        dict(
            desc='Try to retrieve non-existent %r' % group2,
            command=('group_show', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group2,
            command=('group_mod', [group2], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % group2,
            command=('group_del', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create %r' % group2,
            command=(
                'group_add', [group2], dict(description=u'Test desc 2')
            ),
            expected=dict(
                value=group2,
                summary=u'Added group "testgroup2"',
                result=dict(
                    cn=[group2],
                    description=[u'Test desc 2'],
                    objectclass=objectclasses.group,
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'cn=testgroup2,cn=groups,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % group2,
            command=(
                'group_add', [group2], dict(description=u'Test desc 2')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % group2,
            command=('group_show', [group2], {}),
            expected=dict(
                value=group2,
                summary=None,
                result=dict(
                    cn=[group2],
                    description=[u'Test desc 2'],
                    dn=u'cn=testgroup2,cn=groups,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Updated %r' % group2,
            command=(
                'group_mod', [group2], dict(description=u'New desc 2')
            ),
            expected=dict(
                result=dict(
                    cn=[group2],
                    description=[u'New desc 2'],
                ),
                summary=u'Modified group "testgroup2"',
                value=group2,
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % group2,
            command=('group_show', [group2], {}),
            expected=dict(
                value=group2,
                result=dict(
                    cn=[group2],
                    description=[u'New desc 2'],
                    dn=u'cn=testgroup2,cn=groups,cn=accounts,' + api.env.basedn,
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r' % group2,
            command=('group_find', [], dict(cn=group2)),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        #dn=u'cn=%s,cn=groups,cn=accounts,%s' % (group2, api.env.basedn),
                        cn=[group2],
                        description=[u'New desc 2'],
                    ),
                ],
                summary=u'1 group matched',
            ),
        ),


        dict(
            desc='Search for all groups',
            command=('group_find', [], {}),
            expected=dict(
                summary=u'5 groups matched',
                count=5,
                truncated=False,
                result=[
                    {
                        #'dn': u'cn=admins,cn=groups,cn=accounts,%s' % api.env.basedn,
                        'member_user': [u'admin'],
                        'gidnumber': [fuzzy_digits],
                        'cn': [u'admins'],
                        'description': [u'Account administrators group'],
                    },
                    {
                        #'dn': u'cn=ipausers,cn=groups,cn=accounts,%s' % api.env.basedn,
                        'gidnumber': [fuzzy_digits],
                        'cn': [u'ipausers'],
                        'description': [u'Default group for all users'],
                    },
                    {
                        #'dn': u'cn=editors,cn=groups,cn=accounts,%s' % api.env.basedn,
                        'gidnumber': [fuzzy_digits],
                        'cn': [u'editors'],
                        'description': [u'Limited admins who can edit other users'],
                    },
                    dict(
                        #dn=u'cn=%s,cn=groups,cn=accounts,%s' % (group1, api.env.basedn),
                        cn=[group1],
                        description=[u'New desc 1'],
                        gidnumber=[fuzzy_digits],
                    ),
                    dict(
                        #dn=u'cn=%s,cn=groups,cn=accounts,%s' % (group2, api.env.basedn),
                        cn=[group2],
                        description=[u'New desc 2'],
                    ),
                ],
            ),
        ),



        ###############
        # member stuff:
        dict(
            desc='Add member %r to %r' % (group2, group1),
            command=(
                'group_add_member', [group1], dict(group=group2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={'member_group': (group2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'New desc 1'],
                },
            ),
        ),

        dict(
            # FIXME: Shouldn't this raise a NotFound instead?
            desc='Try to add non-existent member to %r' % group1,
            command=(
                'group_add_member', [group1], dict(group=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        group=(u'notfound',),
                        user=tuple(),
                    ),
                ),
                result={'member_group': (group2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'New desc 1'],
                },
            ),
        ),

        dict(
            desc='Remove member %r from %r' % (group2, group1),
            command=('group_remove_member',
                [group1], dict(group=group2)
            ),
            expected=dict(
                completed=1,
                result=dict(),
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
            ),
        ),

        dict(
            # FIXME: Shouldn't this raise a NotFound instead?
            desc='Try to remove non-existent member from %r' % group1,
            command=('group_remove_member',
                [group1], dict(group=u'notfound')
            ),
            expected=dict(
                completed=0,
                result=dict(),
                failed=dict(
                    member=dict(
                        group=(u'notfound',),
                        user=tuple(),
                    ),
                ),
            ),
        ),



        ################
        # delete group1:
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
            desc='Try to delete non-existent %r' % group1,
            command=('group_del', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % group1,
            command=('group_show', [group1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group1,
            command=('group_mod', [group1], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),



        ################
        # delete group2:
        dict(
            desc='Delete %r' % group2,
            command=('group_del', [group2], {}),
            expected=dict(
                result=True,
                value=group2,
                summary=u'Deleted group "testgroup2"',
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % group2,
            command=('group_del', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % group2,
            command=('group_show', [group2], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % group2,
            command=('group_mod', [group2], dict(description=u'Foo')),
            expected=errors.NotFound(reason='no such entry'),
        ),

    ]
