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

from ipalib import api, errors
from tests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid
from tests.test_xmlrpc import objectclasses
from ipapython.dn import DN

sudocmd1 = u'/usr/bin/sudotestcmd1'


class test_sudocmd(Declarative):

    cleanup_commands = [
        ('sudocmd_del', [sudocmd1], {}),
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
                    dn=DN(('sudocmd',sudocmd1),('cn','sudocmds'),('cn','sudo'),
                          api.env.basedn),
                    sudocmd=[sudocmd1],
                    description=[u'Test sudo command 1'],
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
            desc='Retrieve %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=dict(
                value=sudocmd1,
                summary=None,
                result=dict(
                    dn=DN(('sudocmd',sudocmd1),('cn','sudocmds'),('cn','sudo'),
                          api.env.basedn),
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
                        dn=DN(('sudocmd',sudocmd1),('cn','sudocmds'),
                              ('cn','sudo'),api.env.basedn),
                        sudocmd=[sudocmd1],
                        description=[u'Test sudo command 1'],
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
                    dn=DN(('sudocmd',sudocmd1),('cn','sudocmds'),('cn','sudo'),
                          api.env.basedn),
                    sudocmd=[sudocmd1],
                    description=[u'Updated sudo command 1'],
                ),
            ),
        ),


        dict(
            desc='Delete %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=dict(
                value=sudocmd1,
                summary=u'Deleted Sudo Command "%s"' % sudocmd1,
                result=dict(failed=u''),
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
    ]
