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
Test --setattr and --addattr and other attribute-specific issues
"""

from ipalib import api, errors
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid


user_memberof = (u'cn=ipausers,cn=groups,cn=accounts,%s' % api.env.basedn,)
user1=u'tuser1'


class test_attr(Declarative):

    cleanup_commands = [
        ('user_del', [user1], {}),
    ]

    tests = [

        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "tuser1"',
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=u'uid=tuser1,cn=users,cn=accounts,' + api.env.basedn,
                ),
            ),
        ),


        dict(
            desc='Change givenname, add mail %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=(u'givenname=Finkle', u'mail=test@example.com'))
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add another mail %r' % user1,
            command=(
                'user_mod', [user1], dict(addattr=u'mail=test2@example.com')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add two phone numbers at once %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'telephoneNumber=410-555-1212', addattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'410-555-1212', u'301-555-1212'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Go from two phone numbers to one %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'telephoneNumber=301-555-1212')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Add two more phone numbers %r' % user1,
            command=(
                'user_mod', [user1], dict(addattr=(u'telephoneNumber=703-555-1212', u'telephoneNumber=202-888-9833'))
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212', u'202-888-9833', u'703-555-1212'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Try setting givenname to None with setattr in %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=(u'givenname='))
            ),
            expected=errors.RequirementError(name='givenname'),
        ),


        dict(
            desc='Try setting givenname to None with option in %r' % user1,
            command=(
                'user_mod', [user1], dict(givenname=None)
            ),
            expected=errors.RequirementError(name='givenname'),
        ),


        dict(
            desc='Make sure setting givenname works with option in %r' % user1,
            command=(
                'user_mod', [user1], dict(givenname=u'Fred')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Fred'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212', u'202-888-9833', u'703-555-1212'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),


        dict(
            desc='Make sure setting givenname works with setattr in %r' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'givenname=Finkle')
            ),
            expected=dict(
                result=dict(
                    givenname=[u'Finkle'],
                    homedirectory=[u'/home/tuser1'],
                    loginshell=[u'/bin/sh'],
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'test@example.com', u'test2@example.com'],
                    memberof_group=[u'ipausers'],
                    telephonenumber=[u'301-555-1212', u'202-888-9833', u'703-555-1212'],
                    nsaccountlock=False,
                ),
                summary=u'Modified user "tuser1"',
                value=user1,
            ),
        ),

    ]
