# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
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
Test the `ipalib/plugins/user.py` module.
"""

from ipalib import api, errors
from xmlrpc_test import Declarative

user_objectclass = (
    u'top',
    u'person',
    u'organizationalperson',
    u'inetorgperson',
    u'inetuser',
    u'posixaccount',
    u'krbprincipalaux',
    u'radiusprofile',
    u'ipaobject',
)

user_memberof = (u'cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com',)


class test_user(Declarative):

    cleanup_commands = [
        ('user_del', [u'tuser1'], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existant user',
            command=(
                'user_show', [u'tuser1'], {}
            ),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Create a user',
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=u'tuser1',
                result=dict(
                    cn=(u'Test User1',),
                    gecos=(u'tuser1',),
                    givenname=(u'Test',),
                    homedirectory=(u'/home/tuser1',),
                    krbprincipalname=(u'tuser1@' + api.env.realm,),
                    loginshell=(u'/bin/sh',),
                    objectclass=user_objectclass,
                    sn=(u'User1',),
                    uid=(u'tuser1',),
                ),
                summary=u'Added user "tuser1"',
            ),
            ignore_values=(
                'ipauniqueid', 'gidnumber'
            ),
        ),


        dict(
            desc='Try to create another user with same login',
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve the user',
            command=(
                'user_show', [u'tuser1'], {}
            ),
            expected=dict(
                result=dict(
                    dn=u'uid=tuser1,cn=users,cn=accounts,dc=example,dc=com',
                    givenname=(u'Test',),
                    homedirectory=(u'/home/tuser1',),
                    loginshell=(u'/bin/sh',),
                    sn=(u'User1',),
                    uid=(u'tuser1',),
                ),
                value=u'tuser1',
                summary=None,
            ),
        ),


        dict(
            desc='Search for this user with all=True',
            command=(
                'user_find', [u'tuser1'], {'all': True}
            ),
            expected=dict(
                result=(
                    {
                        'cn': (u'Test User1',),
                        'gecos': (u'tuser1',),
                        'givenname': (u'Test',),
                        'homedirectory': (u'/home/tuser1',),
                        'krbprincipalname': (u'tuser1@' + api.env.realm,),
                        'loginshell': (u'/bin/sh',),
                        'memberof group': (u'ipausers',),
                        'objectclass': user_objectclass,
                        'sn': (u'User1',),
                        'uid': (u'tuser1',),
                    },
                ),
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
            ignore_values=['uidnumber', 'gidnumber', 'ipauniqueid'],
        ),


        dict(
            desc='Search for this user with minimal attributes',
            command=(
                'user_find', [u'tuser1'], {}
            ),
            expected=dict(
                result=(
                    dict(
                        givenname=(u'Test',),
                        homedirectory=(u'/home/tuser1',),
                        loginshell=(u'/bin/sh',),
                        sn=(u'User1',),
                        uid=(u'tuser1',),
                    ),
                ),
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),


        dict(
            desc='Search for all users',
            command=(
                'user_find', [], {}
            ),
            expected=dict(
                result=(
                    dict(
                        homedirectory=(u'/home/admin',),
                        loginshell=(u'/bin/bash',),
                        sn=(u'Administrator',),
                        uid=(u'admin',),
                    ),
                    dict(
                        givenname=(u'Test',),
                        homedirectory=(u'/home/tuser1',),
                        loginshell=(u'/bin/sh',),
                        sn=(u'User1',),
                        uid=(u'tuser1',),
                    ),
                ),
                summary=u'2 users matched',
                count=2,
                truncated=False,
            ),
        ),


        dict(
            desc='Lock user',
            command=(
                'user_lock', [u'tuser1'], {}
            ),
            expected=dict(
                result=True,
                value=u'tuser1',
                summary=u'Locked user "tuser1"',
            ),
        ),


        dict(
            desc='Unlock user',
            command=(
                'user_unlock', [u'tuser1'], {}
            ),
            expected=dict(
                result=True,
                value=u'tuser1',
                summary=u'Unlocked user "tuser1"',
            ),
        ),


        dict(
            desc='Update user',
            command=(
                'user_mod', [u'tuser1'], dict(givenname=u'Finkle')
            ),
            expected=dict(
                result=dict(
                    givenname=(u'Finkle',),
                ),
                summary=u'Modified user "tuser1"',
                value=u'tuser1',
            ),
        ),


        dict(
            desc='Retrieve user to verify update',
            command=(
                'user_show', [u'tuser1'], {}
            ),
            expected=dict(
                result=dict(
                    dn=u'uid=tuser1,cn=users,cn=accounts,dc=example,dc=com',
                    givenname=(u'Finkle',),
                    homedirectory=(u'/home/tuser1',),
                    loginshell=(u'/bin/sh',),
                    sn=(u'User1',),
                    uid=(u'tuser1',),
                ),
                summary=None,
                value=u'tuser1',
            ),

        ),


        dict(
            desc='Delete user',
            command=(
                'user_del', [u'tuser1'], {}
            ),
            expected=dict(
                result=True,
                summary=u'Deleted user "tuser1"',
                value=u'tuser1',
            ),
        ),


        dict(
            desc='Do double delete',
            command=(
                'user_del', [u'tuser1'], {}
            ),
            expected=errors.NotFound(reason='no such entry'),
        ),


        dict(
            desc='Verify user is gone',
            command=(
                'user_show', [u'tuser1'], {}
            ),
            expected=errors.NotFound(reason='no such entry'),
        ),

    ]
