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
Test the `ipalib/plugins/privilege.py` module.
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid
from ipapython.dn import DN

permission1 = u'testperm'
permission1_dn = DN(('cn',permission1),
                    api.env.container_permission,api.env.basedn)

permission2 = u'testperm2'
permission2_dn = DN(('cn',permission2),
                    api.env.container_permission,api.env.basedn)

privilege1 = u'testpriv1'
privilege1_dn = DN(('cn',privilege1),
                   api.env.container_privilege,api.env.basedn)


class test_privilege(Declarative):

    cleanup_commands = [
        ('permission_del', [permission1], {}),
        ('permission_del', [permission2], {}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % privilege1,
            command=('privilege_show', [privilege1], {}),
            expected=errors.NotFound(
                reason=u'%s: privilege not found' % privilege1),
        ),


        dict(
            desc='Try to update non-existent %r' % privilege1,
            command=('privilege_mod', [privilege1], dict(description=u'Foo')),
            expected=errors.NotFound(
                reason=u'%s: privilege not found' % privilege1),
        ),


        dict(
            desc='Try to delete non-existent %r' % privilege1,
            command=('privilege_del', [privilege1], {}),
            expected=errors.NotFound(
                reason=u'%s: privilege not found' % privilege1),
        ),


        dict(
            desc='Search for non-existent %r' % privilege1,
            command=('privilege_find', [privilege1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 privileges matched',
                result=[],
            ),
        ),


        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                     type=u'user',
                     permissions=[u'add', u'delete'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'add', u'delete'],
                ),
            ),
        ),


        dict(
            desc='Create %r' % privilege1,
            command=('privilege_add', [privilege1],
                dict(description=u'privilege desc. 1')
            ),
            expected=dict(
                value=privilege1,
                summary=u'Added privilege "%s"' % privilege1,
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                    objectclass=objectclasses.privilege,
                ),
            ),
        ),


        dict(
            desc='Add permission %r to privilege %r' % (permission1, privilege1),
            command=('privilege_add_permission', [privilege1],
                dict(permission=permission1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1],
                }
            ),
        ),


        dict(
            desc='Retrieve %r' % privilege1,
            command=('privilege_show', [privilege1], {}),
            expected=dict(
                value=privilege1,
                summary=None,
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1],
                },
            ),
        ),


        dict(
            desc='Search for %r' % privilege1,
            command=('privilege_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                        'memberof_permission': [permission1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % privilege1,
            command=('privilege_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                        'memberof_permission': [permission1],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % permission2,
            command=(
                'permission_add', [permission2], dict(
                     type=u'user',
                     permissions=u'write',
                )
            ),
            expected=dict(
                value=permission2,
                summary=u'Added permission "%s"' % permission2,
                result=dict(
                    dn=permission2_dn,
                    cn=[permission2],
                    objectclass=objectclasses.permission,
                    type=u'user',
                    permissions=[u'write'],
                ),
            ),
        ),


        dict(
            desc='Add permission %r to privilege %r' % (permission2, privilege1),
            command=('privilege_add_permission', [privilege1],
                dict(permission=permission2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1, permission2],
                }
            ),
        ),


        dict(
            desc='Add permission %r to privilege %r again' % (permission2, privilege1),
            command=('privilege_add_permission', [privilege1],
                dict(permission=permission2)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        permission=[(u'testperm2', u'This entry is already a member'),],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1, permission2],
                }
            ),
        ),


        dict(
            desc='Search for %r' % privilege1,
            command=('privilege_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                        'memberof_permission': [permission1, permission2],
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % privilege1,
            command=(
                'privilege_mod', [privilege1], dict(description=u'New desc 1')
            ),
            expected=dict(
                value=privilege1,
                summary=u'Modified privilege "%s"' % privilege1,
                result=dict(
                    cn=[privilege1],
                    description=[u'New desc 1'],
                    memberof_permission=[permission1, permission2],
                ),
            ),
        ),


        dict(
            desc='Remove permission from %r' % privilege1,
            command=('privilege_remove_permission', [privilege1],
                dict(permission=permission1),
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'New desc 1'],
                    'memberof_permission': [permission2],
                }
            ),
        ),


        dict(
            desc='Remove permission from %r again' % privilege1,
            command=('privilege_remove_permission', [privilege1],
                dict(permission=permission1),
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        permission=[(u'testperm', u'This entry is not a member'),],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'New desc 1'],
                    'memberof_permission': [permission2],
                }
            ),
        ),


        dict(
            desc='Add zero permissions to %r' % privilege1,
            command=('privilege_add_permission', [privilege1],
                dict(permission=None),
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'New desc 1'],
                    'memberof_permission': [permission2],
                }
            ),
        ),


        dict(
            desc='Remove zero permissions from %r' % privilege1,
            command=('privilege_remove_permission', [privilege1],
                dict(permission=None),
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'New desc 1'],
                    'memberof_permission': [permission2],
                }
            ),
        ),


        dict(
            desc='Delete %r' % privilege1,
            command=('privilege_del', [privilege1], {}),
            expected=dict(
                result=dict(failed=u''),
                value=privilege1,
                summary=u'Deleted privilege "%s"' % privilege1,
            )
        ),


    ]
