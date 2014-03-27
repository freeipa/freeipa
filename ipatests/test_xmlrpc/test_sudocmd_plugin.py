# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
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
Test the `ipalib/plugins/sudocmd.py` module.
"""

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, fuzzy_sudocmddn,
    fuzzy_uuid)
from ipatests.test_xmlrpc import objectclasses

sudocmd1 = u'/usr/bin/sudotestcmd1'
sudocmd1_camelcase = u'/usr/bin/sudoTestCmd1'

sudorule1 = u'test_sudorule1'


class test_sudocmd(Declarative):

    cleanup_commands = [
        ('sudocmd_del', [sudocmd1], {}),
        ('sudocmd_del', [sudocmd1_camelcase], {}),
        ('sudorule_del', [sudorule1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1),
        ),


        dict(
            desc='Try to update non-existent %r' % sudocmd1,
            command=('sudocmd_mod', [sudocmd1], dict(description=u'Nope')),
            expected=errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1),
        ),


        dict(
            desc='Try to delete non-existent %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1),
        ),


        dict(
            desc='Create %r' % sudocmd1,
            command=('sudocmd_add', [sudocmd1],
                dict(
                    description=u'Test sudo command 1',
                ),
            ),
            expected=dict(
                value=sudocmd1,
                summary=u'Added Sudo Command "%s"' % sudocmd1,
                result=dict(
                    dn=fuzzy_sudocmddn,
                    sudocmd=[sudocmd1],
                    description=[u'Test sudo command 1'],
                    objectclass=objectclasses.sudocmd,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Create %r' % sudocmd1_camelcase,
            command=('sudocmd_add', [sudocmd1_camelcase],
                dict(
                    description=u'Test sudo command 2',
                ),
            ),
            expected=dict(
                value=sudocmd1_camelcase,
                summary=u'Added Sudo Command "%s"' % sudocmd1_camelcase,
                result=dict(
                    dn=fuzzy_sudocmddn,
                    sudocmd=[sudocmd1_camelcase],
                    description=[u'Test sudo command 2'],
                    objectclass=objectclasses.sudocmd,
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % sudocmd1,
            command=('sudocmd_add', [sudocmd1],
                dict(
                    description=u'Test sudo command 1',
                ),
            ),
            expected=errors.DuplicateEntry(message=u'sudo command with ' +
                u'name "%s" already exists' % sudocmd1),
        ),

        dict(
            desc='Try to create duplicate %r' % sudocmd1_camelcase,
            command=('sudocmd_add', [sudocmd1_camelcase],
                dict(
                    description=u'Test sudo command 2',
                ),
            ),
            expected=errors.DuplicateEntry(message=u'sudo command with ' +
                u'name "%s" already exists' % sudocmd1_camelcase),
        ),


        dict(
            desc='Retrieve %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=dict(
                value=sudocmd1,
                summary=None,
                result=dict(
                    dn=fuzzy_sudocmddn,
                    sudocmd=[sudocmd1],
                    description=[u'Test sudo command 1'],
                ),
            ),
        ),


        dict(
            desc='Search for %r' % sudocmd1,
            command=('sudocmd_find', [sudocmd1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 Sudo Command matched',
                result=[
                    dict(
                        dn=fuzzy_sudocmddn,
                        sudocmd=[sudocmd1],
                        description=[u'Test sudo command 1'],
                    ),
                ],
            ),
        ),

        dict(
            desc='Search for %r' % sudocmd1_camelcase,
            command=('sudocmd_find', [sudocmd1_camelcase], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 Sudo Command matched',
                result=[
                    dict(
                        dn=fuzzy_sudocmddn,
                        sudocmd=[sudocmd1_camelcase],
                        description=[u'Test sudo command 2'],
                    ),
                ],
            ),
        ),


        dict(
            desc='Update %r' % sudocmd1,
            command=('sudocmd_mod', [sudocmd1], dict(
                description=u'Updated sudo command 1')),
            expected=dict(
                value=sudocmd1,
                summary=u'Modified Sudo Command "%s"' % sudocmd1,
                result=dict(
                    sudocmd=[sudocmd1],
                    description=[u'Updated sudo command 1'],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=dict(
                value=sudocmd1,
                summary=None,
                result=dict(
                    dn=fuzzy_sudocmddn,
                    sudocmd=[sudocmd1],
                    description=[u'Updated sudo command 1'],
                ),
            ),
        ),

        dict(
            desc='Create %r' % sudorule1,
            command=('sudorule_add', [sudorule1], {}),
            expected=lambda e, result: True,
        ),

        dict(
            desc='Add %r to %r allow list' % (sudocmd1, sudorule1),
            command=('sudorule_add_allow_command', [sudorule1],
                dict(sudocmd=sudocmd1)),
            expected=dict(
                    completed=1,
                    failed=dict(
                        memberallowcmd=dict(sudocmdgroup=(), sudocmd=())),
                    result=lambda result: True,
                ),
        ),

        dict(
            desc="Test %r can't be deleted when in %r" % (sudocmd1, sudorule1),
            command=('sudocmd_del', [sudocmd1], {}),
            expected=errors.DependentEntry(key=sudocmd1, label='sudorule',
                dependent=sudorule1),
        ),

        dict(
            desc='Remove %r from %r' % (sudocmd1, sudorule1),
            command=('sudorule_remove_allow_command', [sudorule1],
                dict(sudocmd=sudocmd1)),
            expected=dict(
                    completed=1,
                    failed=dict(
                        memberallowcmd=dict(sudocmdgroup=(), sudocmd=())),
                    result=lambda result: True,
                ),
        ),

        dict(
            desc='Add %r to %r deny list' % (sudocmd1, sudorule1),
            command=('sudorule_add_deny_command', [sudorule1],
                dict(sudocmd=sudocmd1)),
            expected=dict(
                    completed=1,
                    failed=dict(
                        memberdenycmd=dict(sudocmdgroup=(), sudocmd=())),
                    result=lambda result: True,
                ),
        ),

        dict(
            desc="Test %r can't be deleted when in %r" % (sudocmd1, sudorule1),
            command=('sudocmd_del', [sudocmd1], {}),
            expected=errors.DependentEntry(key=sudocmd1, label='sudorule',
                dependent=sudorule1),
        ),

        dict(
            desc='Remove %r from %r' % (sudocmd1, sudorule1),
            command=('sudorule_remove_deny_command', [sudorule1],
                dict(sudocmd=sudocmd1)),
            expected=dict(
                    completed=1,
                    failed=dict(
                        memberdenycmd=dict(sudocmdgroup=(), sudocmd=())),
                    result=lambda result: True,
                ),
        ),

        dict(
            desc='Delete %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=dict(
                value=[sudocmd1],
                summary=u'Deleted Sudo Command "%s"' % sudocmd1,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1),
        ),


        dict(
            desc='Try to update non-existent %r' % sudocmd1,
            command=('sudocmd_mod', [sudocmd1], dict(description=u'Nope')),
            expected=errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1),
        ),


        dict(
            desc='Try to delete non-existent %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=errors.NotFound(
                reason=u'%s: sudo command not found' % sudocmd1),
        ),

        dict(
            desc='Retrieve %r' % sudocmd1_camelcase,
            command=('sudocmd_show', [sudocmd1_camelcase], {}),
            expected=dict(
                value=sudocmd1_camelcase,
                summary=None,
                result=dict(
                    dn=fuzzy_sudocmddn,
                    sudocmd=[sudocmd1_camelcase],
                    description=[u'Test sudo command 2'],
                ),
            ),
        ),
    ]
