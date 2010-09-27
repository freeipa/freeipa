# Authors:
#   Jr Aquino <jr.aquino@citrixonline.com>
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
Test the `ipalib/plugins/sudocmd.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_uuid
from tests.test_xmlrpc import objectclasses


sudocmd1 = u'/usr/bin/sudotestcmd1'


class test_sudocmd(Declarative):

    cleanup_commands = [
        ('sudocmd_del', [sudocmd1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % sudocmd1,
            command=('sudocmd_mod', [sudocmd1], dict(description=u'Nope')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=errors.NotFound(reason='no such entry'),
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
                summary=u'Added sudo command "%s"' % sudocmd1,
                result=dict(
                    dn=u'cn=%s,cn=sudocmds,cn=accounts,%s' % (sudocmd1,
                        api.env.basedn),
                    cn=[sudocmd1],
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
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=dict(
                value=sudocmd1,
                summary=None,
                result=dict(
                    dn=u'cn=%s,cn=sudocmds,cn=accounts,%s' % (sudocmd1,
                        api.env.basedn),
                    cn=[sudocmd1],
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
                summary=u'1 sudo command matched',
                result=[
                    dict(
                        dn=u'cn=%s,cn=sudocmds,cn=accounts,%s' % (sudocmd1,
                            api.env.basedn),
                        cn=[sudocmd1],
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
                summary=u'Modified sudo command "%s"' % sudocmd1,
                result=dict(
                    cn=[sudocmd1],
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
                    dn=u'cn=%s,cn=sudocmds,cn=accounts,%s' % (sudocmd1,
                        api.env.basedn),
                    cn=[sudocmd1],
                    description=[u'Updated sudo command 1'],
                ),
            ),
        ),


        dict(
            desc='Delete %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=dict(
                value=sudocmd1,
                summary=u'Deleted sudo command "%s"' % sudocmd1,
                result=True,
            ),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % sudocmd1,
            command=('sudocmd_show', [sudocmd1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to update non-existent %r' % sudocmd1,
            command=('sudocmd_mod', [sudocmd1], dict(description=u'Nope')),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Try to delete non-existent %r' % sudocmd1,
            command=('sudocmd_del', [sudocmd1], {}),
            expected=errors.NotFound(reason='no such entry'),
        ),
    ]
