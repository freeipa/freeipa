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

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api, errors
from xmlrpc_test import Declarative


group_objectclass = (
    u'top',
    u'groupofnames',
    u'nestedgroup',
    u'ipausergroup',
    u'ipaobject',
)


class test_group(Declarative):
    cleanup_commands = [
        ('group_del', [u'testgroup1'], {}),
        ('group_del', [u'testgroup2'], {}),
    ]

    tests = [
        # testgroup1:
        dict(
            desc='Try to retrieve a non-existant testgroup1',
            command=('group_show', [u'testgroup2'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),

        dict(
            desc='Create testgroup1',
            command=(
                'group_add', [u'testgroup1'], dict(description=u'Test desc 1')
            ),
            expected=dict(
                value=u'testgroup1',
                result=dict(
                    cn=(u'testgroup1',),
                    description=(u'Test desc 1',),
                    objectclass=group_objectclass,
                ),
                summary=u'Added group "testgroup1"',
            ),
            ignore_values=['ipauniqueid', 'dn'],
        ),

        dict(
            desc='Try to create testgroup1 again',
            command=(
                'group_add', [u'testgroup1'], dict(description=u'Test desc 1')
            ),
            expected=errors.DuplicateEntry(),
        ),

        dict(
            desc='Retrieve testgroup1',
            command=('group_show', [u'testgroup1'], {}),
            expected=dict(
                value=u'testgroup1',
                result=dict(
                    cn=(u'testgroup1',),
                    description=(u'Test desc 1',),
                ),
                summary=None,
            ),
            ignore_values=['dn'],
        ),

        dict(
            desc='Updated testgroup1',
            command=(
                'group_mod', [u'testgroup1'], dict(description=u'New desc 1')
            ),
            expected=dict(
                result=dict(
                    description=(u'New desc 1',),
                ),
                summary=u'Modified group "testgroup1"',
                value=u'testgroup1',
            ),
        ),

        dict(
            desc='Retrieve testgroup1 to check update',
            command=('group_show', [u'testgroup1'], {}),
            expected=dict(
                value=u'testgroup1',
                result=dict(
                    cn=(u'testgroup1',),
                    description=(u'New desc 1',),
                ),
                summary=None,
            ),
            ignore_values=['dn'],
        ),

        # FIXME: The return value is totally different here than from the above
        # group_mod() test.  I think that for all *_mod() commands we should
        # just return the entry exactly as *_show() does.
        dict(
            desc='Updated testgroup1 to promote it to posix group',
            command=('group_mod', [u'testgroup1'], dict(posix=True)),
            expected=dict(
                result=dict(
                    cn=(u'testgroup1',),
                    description=(u'New desc 1',),
                    objectclass=group_objectclass + (u'posixgroup',),
                ),
                value=u'testgroup1',
                summary=u'Modified group "testgroup1"',
            ),
            ignore_values=['gidnumber', 'ipauniqueid'],
        ),

        dict(
            desc="Retrieve testgroup1 to check it's a posix group",
            command=('group_show', [u'testgroup1'], {}),
            expected=dict(
                value=u'testgroup1',
                result=dict(
                    cn=(u'testgroup1',),
                    description=(u'New desc 1',),
                ),
                summary=None,
            ),
            ignore_values=['dn', 'gidnumber'],
        ),

        dict(
            desc='Search for testgroup1',
            command=('group_find', [], dict(cn=u'testgroup1')),
            expected=dict(
                count=1,
                truncated=False,
                result=(
                    dict(
                        cn=(u'testgroup1',),
                        description=(u'New desc 1',),
                    ),
                ),
                summary=u'1 group matched',
            ),
            ignore_values=['gidnumber'],
        ),


        # testgroup2:
        dict(
            desc='Try to retrieve a non-existant testgroup2',
            command=('group_show', [u'testgroup2'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),

        dict(
            desc='Create testgroup2',
            command=(
                'group_add', [u'testgroup2'], dict(description=u'Test desc 2')
            ),
            expected=dict(
                value=u'testgroup2',
                result=dict(
                    cn=(u'testgroup2',),
                    description=(u'Test desc 2',),
                    objectclass=group_objectclass,
                ),
                summary=u'Added group "testgroup2"',
            ),
            ignore_values=['ipauniqueid', 'dn'],
        ),

        dict(
            desc='Try to create testgroup2 again',
            command=(
                'group_add', [u'testgroup2'], dict(description=u'Test desc 2')
            ),
            expected=errors.DuplicateEntry(),
        ),

        dict(
            desc='Retrieve testgroup2',
            command=('group_show', [u'testgroup2'], {}),
            expected=dict(
                value=u'testgroup2',
                result=dict(
                    cn=(u'testgroup2',),
                    description=(u'Test desc 2',),
                ),
                summary=None,
            ),
            ignore_values=['dn'],
        ),

        dict(
            desc='Search for testgroup2',
            command=('group_find', [], dict(cn=u'testgroup2')),
            expected=dict(
                count=1,
                truncated=False,
                result=(
                    dict(
                        cn=(u'testgroup2',),
                        description=(u'Test desc 2',),
                    ),
                ),
                summary=u'1 group matched',
            ),
        ),

        dict(
            desc='Updated testgroup2',
            command=(
                'group_mod', [u'testgroup2'], dict(description=u'New desc 2')
            ),
            expected=dict(
                result=dict(
                    description=(u'New desc 2',),
                ),
                value=u'testgroup2',
                summary=u'Modified group "testgroup2"',
            ),
        ),

        dict(
            desc='Retrieve testgroup2 to check update',
            command=('group_show', [u'testgroup2'], {}),
            expected=dict(
                value=u'testgroup2',
                result=dict(
                    cn=(u'testgroup2',),
                    description=(u'New desc 2',),
                ),
                summary=None,
            ),
            ignore_values=['dn'],
        ),


        # member stuff:
        dict(
            desc='Make testgroup2 member of testgroup1',
            command=(
                'group_add_member', [u'testgroup1'], dict(group=u'testgroup2')
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={'member group': (u'testgroup2',)},
            ),
        ),

        dict(
            # FIXME: Shouldn't this raise a NotFound instead?
            desc='Try to add a non-existent member to testgroup1',
            command=(
                'group_add_member', [u'testgroup1'], dict(group=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        group=(u'notfound',),
                        user=tuple(),
                    ),
                ),
                result={'member group': (u'testgroup2',)},
            ),
        ),

        dict(
            desc='Remove member testgroup2 from testgroup1',
            command=('group_remove_member',
                [u'testgroup1'], dict(group=u'testgroup2')
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
            desc='Try to remove a non-existent member from testgroup1',
            command=('group_remove_member',
                [u'testgroup1'], dict(group=u'notfound')
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


        # Delete:
        dict(
            desc='Delete testgroup1',
            command=('group_del', [u'testgroup1'], {}),
            expected=dict(
                result=True,
                value=u'testgroup1',
                summary=u'Deleted group "testgroup1"',
            ),
        ),

        dict(
            desc='Delete testgroup2',
            command=('group_del', [u'testgroup2'], {}),
            expected=dict(
                result=True,
                value=u'testgroup2',
                summary=u'Deleted group "testgroup2"',
            ),
        ),


        ##############
        # Non-existent
        ##############

        # testgroup1:
        dict(
            desc='Try to retrieve non-existent testgroup1',
            command=('group_show', [u'testgroup1'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),
        dict(
            desc='Try to update non-existent testgroup1',
            command=(
                'group_mod', [u'testgroup1'], dict(description=u'New desc 1')
            ),
            expected=errors.NotFound(reason='no such entry'),
        ),
        dict(
            desc='Try to delete non-existent testgroup1',
            command=('group_del', [u'testgroup1'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),

        # testgroup2:
        dict(
            desc='Try to retrieve non-existent testgroup2',
            command=('group_show', [u'testgroup2'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),
        dict(
            desc='Try to update non-existent testgroup2',
            command=(
                'group_mod', [u'testgroup2'], dict(description=u'New desc 2')
            ),
            expected=errors.NotFound(reason='no such entry'),
        ),
        dict(
            desc='Try to delete non-existent testgroup2',
            command=('group_del', [u'testgroup2'], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


    ]
