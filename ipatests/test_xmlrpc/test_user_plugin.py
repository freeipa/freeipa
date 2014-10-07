# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
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
Test the `ipalib/plugins/user.py` module.
"""

import datetime
import ldap
import re

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import assert_equal, assert_not_equal, raises
from xmlrpc_test import (XMLRPC_test, Declarative, fuzzy_digits, fuzzy_uuid,
                         fuzzy_password, fuzzy_string, fuzzy_dergeneralizedtime,
                         add_sid, add_oc)
from ipapython.dn import DN

user1 = u'tuser1'
user2 = u'tuser2'
admin1 = u'admin'
admin2 = u'admin2'
renameduser1 = u'tuser'
group1 = u'group1'
admins_group = u'admins'

invaliduser1 = u'+tuser1'
invaliduser2 = u'tuser1234567890123456789012345678901234567890'

sshpubkey = (u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
              'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
              'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
              'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
              'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
              '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
              '0L public key test')
sshpubkeyfp = (u'13:67:6B:BF:4E:A2:05:8E:AE:25:8B:A1:31:DE:6F:1B '
                'public key test (ssh-rsa)')

validlanguage1 = u'en-US;q=0.987 , en, abcdfgh-abcdefgh;q=1        , a;q=1.000'
validlanguage2 = u'*'

invalidlanguage1 = u'abcdfghji-abcdfghji'
invalidlanguage2 = u'en-us;q=0,123'
invalidlanguage3 = u'en-us;q=0.1234'
invalidlanguage4 = u'en-us;q=1.1'
invalidlanguage5 = u'en-us;q=1.0000'

principal_expiration_string = "2020-12-07T19:54:13Z"
principal_expiration_date = datetime.datetime(2020, 12, 7, 19, 54, 13)

invalid_expiration_string = "2020-12-07 19:54:13"
expired_expiration_string = "1991-12-07T19:54:13Z"

# Date in ISO format (2013-12-10T12:00:00)
isodate_re = re.compile('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')


def get_user_result(uid, givenname, sn, operation='show', omit=[],
                    **overrides):
    """Get a user result for a user-{add,mod,find,show} command

    This gives the result as from a user_add(uid, givenname=givenname, sn=sn);
    modifications to that can be specified in ``omit`` and ``overrides``.

    The ``operation`` can be one of:
    - add
    - show
    - show-all ((show with the --all flag)
    - find
    - mod

    Attributes named in ``omit`` are removed from the result; any additional
    or non-default values can be specified in ``overrides``.
    """
    # sn can be None; this should only be used from `get_admin_result`
    cn = overrides.get('cn', ['%s %s' % (givenname, sn or '')])
    cn[0] = cn[0].strip()
    result = add_sid(dict(
        homedirectory=[u'/home/%s' % uid],
        loginshell=[u'/bin/sh'],
        uid=[uid],
        uidnumber=[fuzzy_digits],
        gidnumber=[fuzzy_digits],
        mail=[u'%s@%s' % (uid, api.env.domain)],
        has_keytab=False,
        has_password=False,
    ))
    if sn:
        result['sn'] = [sn]
    if givenname:
        result['givenname'] = [givenname]
    if operation in ('add', 'show', 'show-all', 'find'):
        result.update(
            dn=get_user_dn(uid),
        )
    if operation in ('add', 'show-all'):
        result.update(
            cn=cn,
            displayname=cn,
            gecos=cn,
            initials=[givenname[0] + (sn or '')[:1]],
            ipauniqueid=[fuzzy_uuid],
            mepmanagedentry=[get_group_dn(uid)],
            objectclass=add_oc(objectclasses.user, u'ipantuserattrs'),
            krbprincipalname=[u'%s@%s' % (uid, api.env.realm)],
        )
    if operation in ('show', 'show-all', 'find', 'mod'):
        result.update(
            nsaccountlock=False,
        )
    if operation in ('add', 'show', 'show-all', 'mod'):
        result.update(
            memberof_group=[u'ipausers'],
        )
    for key in omit:
        del result[key]
    result.update(overrides)
    return result


def get_admin_result(operation='show', **overrides):
    """Give the result for the default admin user

    Any additional or non-default values can be given in ``overrides``.
    """
    result = get_user_result(u'admin', None, u'Administrator', operation,
                             omit=['mail'],
                             has_keytab=True,
                             has_password=True,
                             loginshell=[u'/bin/bash'],
                             **overrides)
    return result


def get_user_dn(uid):
    return DN(('uid', uid), api.env.container_user, api.env.basedn)


def get_group_dn(cn):
    return DN(('cn', cn), api.env.container_group, api.env.basedn)


def upg_check(response):
    """Check that the user was assigned to the corresponding private group."""
    assert_equal(response['result']['uidnumber'],
                 response['result']['gidnumber'])
    return True


def not_upg_check(response):
    """
    Check that the user was not assigned to the corresponding
    private group.
    """

    assert_not_equal(response['result']['uidnumber'],
                     response['result']['gidnumber'])
    return True


class test_user(Declarative):

    cleanup_commands = [
        ('user_del', [user1, user2, renameduser1, admin2], {'continue': True}),
        ('group_del', [group1], {}),
        ('automember_default_group_remove', [], {'type': u'group'}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent "%s"' % user1,
            command=('user_show', [user1], {}),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to update non-existent "%s"' % user1,
            command=('user_mod', [user1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to delete non-existent "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to rename non-existent "%s"' % user1,
            command=('user_mod', [user1],
                     dict(setattr=u'uid=%s' % renameduser1)),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Create "%s"' % user1,
            command=(
                'user_add',
                [user1],
                dict(
                    givenname=u'Test',
                    sn=u'User1',
                    userclass=u'testusers'
                )
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1,
                    u'Test',
                    u'User1',
                    'add',
                    userclass=[u'testusers'],
                    objectclass=add_oc(
                        objectclasses.user,
                        u'ipantuserattrs'
                    ) + [u'ipauser']
                ),
            ),
            extra_check = upg_check,
        ),


        dict(
            desc='Try to create duplicate "%s"' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=errors.DuplicateEntry(
                message=u'user with name "%s" already exists' % user1),
        ),


        dict(
            desc='Retrieve "%s"' % user1,
            command=(
                'user_show', [user1], {}
            ),
            expected=dict(
                result=get_user_result(
                    user1,
                    u'Test',
                    u'User1',
                    'show',
                    userclass=[u'testusers']
                ),
                value=user1,
                summary=None,
            ),
        ),

        dict(
            desc='Remove userclass for user "%s"' % user1,
            command=('user_mod', [user1], dict(userclass=u'')),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod'),
                value=user1,
                summary=u'Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Search for "%s" with all=True' % user1,
            command=(
                'user_find', [user1], {'all': True}
            ),
            expected=dict(
                result=[
                    get_user_result(
                        user1,
                        u'Test',
                        u'User1',
                        'show-all',
                        objectclass=add_oc(
                            objectclasses.user,
                            u'ipantuserattrs'
                        ) + [u'ipauser']
                    ),
                ],
                summary=u'1 user matched',
                count=1, truncated=False,
            ),
        ),


        dict(
            desc='Search for "%s" with pkey-only=True' % user1,
            command=(
                'user_find', [user1], {'pkey_only': True}
            ),
            expected=dict(
                result=[
                    {
                        'dn': get_user_dn(user1),
                        'uid': [user1],
                    },
                ],
                summary=u'1 user matched',
                count=1, truncated=False,
            ),
        ),


        dict(
            desc='Search for "%s" with minimal attributes' % user1,
            command=(
                'user_find', [user1], {}
            ),
            expected=dict(
                result=[
                    get_user_result(user1, u'Test', u'User1', 'find'),
                ],
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
                result=[
                    get_admin_result('find'),
                    get_user_result(user1, u'Test', u'User1', 'find'),
                ],
                summary=u'2 users matched',
                count=2,
                truncated=False,
            ),
        ),


        dict(
            desc='Search for all users with a limit of 1',
            command=(
                'user_find', [], dict(sizelimit=1,),
            ),
            expected=dict(
                result=[get_admin_result('find')],
                summary=u'1 user matched',
                count=1,
                truncated=True,
            ),
        ),


        dict(
            desc='Disable "%s"' % user1,
            command=(
                'user_disable', [user1], {}
            ),
            expected=dict(
                result=True,
                value=user1,
                summary=u'Disabled user account "%s"' % user1,
            ),
        ),

        dict(
            desc='Assert user is disabled',
            command=('user_find', [user1], {}),
            expected=dict(
                result=[get_user_result(user1, u'Test', u'User1', 'find',
                                        nsaccountlock=True)],
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),

        dict(
            desc='Enable "%s"' % user1,
            command=(
                'user_enable', [user1], {}
            ),
            expected=dict(
                result=True,
                value=user1,
                summary=u'Enabled user account "%s"' % user1,
            ),
        ),

        dict(
            desc='Assert user "%s" is enabled' % user1,
            command=('user_find', [user1], {}),
            expected=dict(
                result=[get_user_result(user1, u'Test', u'User1', 'find')],
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),

        dict(
            desc='Disable "%s" using setattr' % user1,
            command=('user_mod', [user1], dict(setattr=u'nsaccountlock=True')),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                                       nsaccountlock=True),
                value=user1,
                summary=u'Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Enable "%s" using setattr' % user1,
            command=('user_mod', [user1], dict(setattr=u'nsaccountlock=False')),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod'),
                value=user1,
                summary=u'Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Disable "%s" using user_mod' % user1,
            command=('user_mod', [user1], dict(nsaccountlock=True)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                                       nsaccountlock=True),
                value=user1,
                summary=u'Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Enable "%s" using user_mod' % user1,
            command=('user_mod', [user1], dict(nsaccountlock=False)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod'),
                value=user1,
                summary=u'Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Try setting virtual attribute on "%s" using setattr' % user1,
            command=('user_mod', [user1], dict(setattr=u'random=xyz123')),
            expected=errors.ObjectclassViolation(
                info='attribute "random" not allowed'),
        ),

        dict(
            desc='Update "%s"' % user1,
            command=(
                'user_mod', [user1], dict(givenname=u'Finkle')
            ),
            expected=dict(
                result=get_user_result(user1, u'Finkle', u'User1', 'mod'),
                summary=u'Modified user "%s"' % user1,
                value=user1,
            ),
        ),


        dict(
            desc='Try updating the krb ticket policy of "%s"' % user1,
            command=(
                'user_mod', [user1], dict(setattr=u'krbmaxticketlife=88000')
            ),
            expected=errors.ObjectclassViolation(
                info=u'attribute "krbmaxticketlife" not allowed'),
        ),


        dict(
            desc='Retrieve "%s" to verify update' % user1,
            command=('user_show', [user1], {}),
            expected=dict(
                result=get_user_result(user1, u'Finkle', u'User1', 'show'),
                summary=None,
                value=user1,
            ),

        ),


        dict(
            desc='Rename "%s"' % user1,
            command=('user_mod', [user1],
                     dict(setattr=u'uid=%s' % renameduser1)),
            expected=dict(
                result=get_user_result(
                    renameduser1, u'Finkle', u'User1', 'mod',
                    mail=[u'%s@%s' % (user1, api.env.domain)],
                    homedirectory=[u'/home/%s' % user1]),
                summary=u'Modified user "%s"' % user1,
                value=user1,
            ),
        ),


        dict(
            desc='Rename "%s" to same value' % renameduser1,
            command=('user_mod', [renameduser1],
                     dict(setattr=u'uid=%s' % renameduser1)),
            expected=errors.EmptyModlist(),
        ),

        dict(
            desc='Rename "%s" to same value, check that other modifications '
                 'are performed' % renameduser1,
            command=('user_mod', [renameduser1],
                     dict(setattr=u'uid=%s' % renameduser1,
                          loginshell=u'/bin/bash')),
            expected=dict(
                result=get_user_result(
                    renameduser1, u'Finkle', u'User1', 'mod',
                    mail=[u'%s@%s' % (user1, api.env.domain)],
                    homedirectory=[u'/home/%s' % user1],
                    loginshell=[u'/bin/bash']),
                summary=u'Modified user "%s"' % renameduser1,
                value=renameduser1,
            ),
        ),


        dict(
            desc='Rename back "%s"' % renameduser1,
            command=('user_mod', [renameduser1],
                     dict(setattr=u'uid=%s' % user1, loginshell=u'/bin/sh')),
            expected=dict(
                result=get_user_result(user1, u'Finkle', u'User1', 'mod'),
                summary=u'Modified user "%s"' % renameduser1,
                value=renameduser1,
            ),
        ),


        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),


        dict(
            desc='Try to delete non-existent "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=errors.NotFound(reason=u'tuser1: user not found'),
        ),


        dict(
            desc='Create user "%s" with krb ticket policy' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                setattr=u'krbmaxticketlife=88000')
            ),
            expected=errors.ObjectclassViolation(
                info='attribute "krbmaxticketlife" not allowed'),
        ),


        dict(
            desc='Create "%s" with SSH public key' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                                          ipasshpubkey=[sshpubkey])
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1, u'Test', u'User1', 'add',
                    objectclass=add_oc(objectclasses.user, u'ipantuserattrs'),
                    ipasshpubkey=[sshpubkey],
                    sshpubkeyfp=[sshpubkeyfp],
                ),
            ),
            extra_check = upg_check,
        ),


        dict(
            desc='Add an illegal SSH public key to "%r"' % user1,
            command=('user_mod', [user1],
                     dict(ipasshpubkey=[u"anal nathrach orth' bhais's bethad "
                                         "do che'l de'nmha"])),
            expected=errors.ValidationError(name='sshpubkey',
                error=u'invalid SSH public key'),
        ),


        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),


        dict(
            desc='Create "%s"' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
            extra_check = upg_check,
        ),


        dict(
            desc='Create "%s"' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(user2, u'Test', u'User2', 'add'),
            ),
            extra_check = upg_check,
        ),


        dict(
            desc='Make non-existent "%s" the manager of "%s"' % (renameduser1,
                                                                 user2),
            command=('user_mod', [user2], dict(manager=renameduser1)),
            expected=errors.NotFound(
                reason=u'manager %s not found' % renameduser1),
        ),


        dict(
            desc='Make "%s" the manager of "%s"' % (user1, user2),
            command=('user_mod', [user2], dict(manager=user1)),
            expected=dict(
                result=get_user_result(user2, u'Test', u'User2', 'mod',
                                       manager=[user1]),
                summary=u'Modified user "%s"' % user2,
                value=user2,
            ),
        ),

        dict(
            desc='Search for "%s" with manager "%s"' % (user2, user1),
            command=(
                'user_find', [user2], {'manager': user1}
            ),
            expected=dict(
                result=[get_user_result(user2, u'Test', u'User2', 'find',
                                        manager=[user1])],
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),

        dict(
            desc='Delete "%s" and "%s" at the same time' % (user1, user2),
            command=('user_del', [user1, user2], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "tuser1,tuser2"',
                value=[user1, user2],
            ),
        ),

        dict(
            desc='Try to retrieve non-existent "%s"' % user1,
            command=('user_show', [user1], {}),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Try to update non-existent "%s"' % user1,
            command=('user_mod', [user1], dict(givenname=u'Foo')),
            expected=errors.NotFound(reason=u'%s: user not found' % user1),
        ),


        dict(
            desc='Test an invalid login name "%s"' % invaliduser1,
            command=('user_add', [invaliduser1], dict(givenname=u'Test',
                                                      sn=u'User1')),
            expected=errors.ValidationError(name='login',
                error=u'may only include letters, numbers, _, -, . and $'),
        ),


        dict(
            desc='Test a login name that is too long "%s"' % invaliduser2,
            command=('user_add', [invaliduser2],
                dict(givenname=u'Test', sn=u'User1')),
            expected=errors.ValidationError(name='login',
                error='can be at most 32 characters'),
        ),


        # The assumption on these next 4 tests is that if we don't get a
        # validation error then the request was processed normally.
        dict(
            desc='Test that validation is disabled on deletes',
            command=('user_del', [invaliduser1], {}),
            expected=errors.NotFound(
                reason=u'%s: user not found' % invaliduser1),
        ),


        dict(
            desc='Test that validation is disabled on show',
            command=('user_show', [invaliduser1], {}),
            expected=errors.NotFound(
                reason=u'%s: user not found' % invaliduser1),
        ),


        dict(
            desc='Test that validation is disabled on find',
            command=('user_find', [invaliduser1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 users matched',
                result=[],
            ),
        ),


        dict(
            desc='Try to rename to invalid username "%s"' % user1,
            command=('user_mod', [user1], dict(rename=invaliduser1)),
            expected=errors.ValidationError(name='rename',
                error=u'may only include letters, numbers, _, -, . and $'),
        ),


        dict(
            desc='Try to rename to a username that is too long "%s"' % user1,
            command=('user_mod', [user1], dict(rename=invaliduser2)),
            expected=errors.ValidationError(name='login',
                error='can be at most 32 characters'),
        ),


        dict(
            desc='Create "%s"' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=get_group_dn(group1),
                ),
            ),
        ),


        dict(
            desc='Try to user "%s" where the managed group exists' % group1,
            command=(
                'user_add', [group1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=errors.ManagedGroupExistsError(group=group1)
        ),


        dict(
            desc='Create "%s" with a full address' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                street=u'123 Maple Rd', l=u'Anytown', st=u'MD',
                telephonenumber=u'410-555-1212', postalcode=u'01234-5678')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1, u'Test', u'User1', 'add',
                    street=[u'123 Maple Rd'], l=[u'Anytown'], st=[u'MD'],
                    telephonenumber=[u'410-555-1212'],
                    postalcode=[u'01234-5678'],
                ),
            ),
        ),


        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),

        dict(
            desc='Create "%s" with random password' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                                          random=True)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1, u'Test', u'User1', 'add',
                    randompassword=fuzzy_password,
                    has_keytab=True, has_password=True,
                    krbextradata=[fuzzy_string],
                    krbpasswordexpiration=[fuzzy_dergeneralizedtime],
                    krblastpwdchange=[fuzzy_dergeneralizedtime]
                ),
            ),
        ),

        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),

        dict(
            desc='Create "%s"' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(user2, u'Test', u'User2', 'add'),
            ),
        ),

        dict(
            desc='Modify "%s" with random password' % user2,
            command=(
                'user_mod', [user2], dict(random=True)
            ),
            expected=dict(
                result=get_user_result(
                    user2, u'Test', u'User2', 'mod',
                    randompassword=fuzzy_password,
                    has_keytab=True, has_password=True,
                ),
                summary=u'Modified user "%s"' % user2,
                value=user2,
            ),
        ),

        dict(
            desc='Delete "%s"' % user2,
            command=('user_del', [user2], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user2,
                value=[user2],
            ),
        ),

        dict(
            desc='Create user "%s" with upper-case principal' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                krbprincipalname=user1.upper())
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),


        dict(
            desc='Create user "%s" with bad realm in principal' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                krbprincipalname='%s@NOTFOUND.ORG' % user1)
            ),
            expected=errors.RealmMismatch()
        ),


        dict(
            desc='Create user "%s" with malformed principal' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                krbprincipalname='%s@BAD@NOTFOUND.ORG' % user1)
            ),
            expected=errors.MalformedUserPrincipal(
                principal='%s@BAD@NOTFOUND.ORG' % user1),
        ),

        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),

        dict(
            desc='Change default home directory',
            command=(
                'config_mod', [], dict(ipahomesrootdir=u'/other-home'),
            ),
            expected=lambda x, output: x is None,
        ),

        dict(
            desc=('Create user "%s" with different default '
                  'home directory' % user1),
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add',
                                       homedirectory=[u'/other-home/tuser1']),
            ),
        ),


        dict(
            desc='Reset default home directory',
            command=(
                'config_mod', [], dict(ipahomesrootdir=u'/home'),
            ),
            expected=lambda x, output: x is None,
        ),

        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),

        dict(
            desc='Change default login shell',
            command=(
                'config_mod', [],
                dict(ipadefaultloginshell=u'/usr/bin/ipython'),
            ),
            expected=lambda x, output: x is None,
        ),

        dict(
            desc='Create user "%s" with different default login shell' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add',
                                       loginshell=[u'/usr/bin/ipython']),
            ),
        ),

        dict(
            desc='Reset default login shell',
            command=(
                'config_mod', [], dict(ipadefaultloginshell=u'/bin/sh'),
            ),
            expected=lambda x, output: x is None,
        ),

        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),

        dict(
            desc='Create "%s" without UPG' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                                          noprivate=True)
            ),
            expected=errors.NotFound(
                reason='Default group for new users is not POSIX'),
        ),

        dict(
            desc='Create "%s" without UPG with GID explicitly set' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2',
                                          noprivate=True, gidnumber=1000)
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(
                    user2, u'Test', u'User2', 'add',
                    objectclass=add_oc(objectclasses.user_base,
                                       u'ipantuserattrs'),
                    gidnumber=[u'1000'],
                    description=[],
                    omit=['mepmanagedentry'],
                ),
            ),
        ),

        dict(
            desc='Delete "%s"' % user2,
            command=('user_del', [user2], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user2,
                value=[user2],
            ),
        ),

        dict(
            desc='Change default user group',
            command=(
                'config_mod', [], dict(ipadefaultprimarygroup=group1),
            ),
            expected=lambda x, output: x is None,
        ),

        dict(
            desc='Create "%s" without UPG' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1',
                                          noprivate=True)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1, u'Test', u'User1', 'add',
                    objectclass=add_oc(objectclasses.user_base,
                                       u'ipantuserattrs'),
                    description=[],
                    memberof_group=[group1],
                    omit=['mepmanagedentry'],
                ),
            ),
            extra_check = not_upg_check,
        ),

        dict(
            desc='Create "%s" without UPG with GID explicitly set' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2',
                                          noprivate=True, gidnumber=1000)
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(
                    user2, u'Test', u'User2', 'add',
                    objectclass=add_oc(objectclasses.user_base,
                                       u'ipantuserattrs'),
                    description=[],
                    gidnumber=[u'1000'],
                    memberof_group=[group1],
                    omit=['mepmanagedentry'],
                ),
            ),
        ),

        dict(
            desc='Set %r as manager of %r' % (user1, user2),
            command=(
                'user_mod', [user2], dict(manager=user1)
            ),
            expected=dict(
                result=get_user_result(user2, u'Test', u'User2', 'mod',
                                       gidnumber=[u'1000'],
                                       memberof_group=[group1],
                                       manager=[user1]),
                summary=u'Modified user "%s"' % user2,
                value=user2,
            ),
        ),

        dict(
            desc='Rename "%s"' % user1,
            command=('user_mod', [user1], dict(rename=renameduser1)),
            expected=dict(
                result=get_user_result(
                    renameduser1, u'Test', u'User1', 'mod',
                    homedirectory=[u'/home/%s' % user1],
                    mail=[u'%s@%s' % (user1, api.env.domain)],
                    memberof_group=[group1],
                ),
                summary=u'Modified user "%s"' % user1,
                value=user1,
            ),
        ),

        dict(
            desc='Retrieve %r and check that manager is renamed' % user2,
            command=(
                'user_show', [user2], {'all': True}
            ),
            expected=dict(
                result=get_user_result(
                    user2, u'Test', u'User2', 'show-all',
                    gidnumber=[u'1000'],
                    memberof_group=[group1],
                    manager=[renameduser1],
                    objectclass=add_oc(objectclasses.user_base,
                                       u'ipantuserattrs'),
                    omit=['mepmanagedentry'],
                ),
                value=user2,
                summary=None,
            ),
        ),

        dict(
            desc='Delete %r' % renameduser1,
            command=('user_del', [renameduser1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % renameduser1,
                value=[renameduser1],
            ),
        ),

        dict(
            desc='Retrieve %r and check that manager is gone' % user2,
            command=(
                'user_show', [user2], {'all': True}
            ),
            expected=dict(
                result=get_user_result(
                    user2, u'Test', u'User2', 'show-all',
                    gidnumber=[u'1000'],
                    memberof_group=[group1],
                    objectclass=add_oc(objectclasses.user_base,
                                       u'ipantuserattrs'),
                    omit=['mepmanagedentry'],
                ),
                value=user2,
                summary=None,
            ),
        ),

        dict(
            desc='Reset default user group',
            command=(
                'config_mod', [], dict(ipadefaultprimarygroup=u'ipausers'),
            ),
            expected=lambda x, output: x is None,
        ),

        dict(
            desc='Try to remove the original admin user "%s"' % admin1,
            command=('user_del', [admin1], {}),
            expected=errors.LastMemberError(key=admin1, label=u'group',
                container=admins_group),
        ),

        dict(
            desc='Try to disable the original admin user "%s"' % admin1,
            command=('user_disable', [admin1], {}),
            expected=errors.LastMemberError(key=admin1, label=u'group',
                container=admins_group),
        ),


        dict(
            desc='Create 2nd admin user "%s"' % admin2,
            command=(
                'user_add', [admin2], dict(givenname=u'Second', sn=u'Admin')
            ),
            expected=dict(
                value=admin2,
                summary=u'Added user "%s"' % admin2,
                result=get_user_result(admin2, u'Second', u'Admin', 'add'),
            ),
        ),

        dict(
            desc='Add "%s" to the admins group "%s"' % (admin2, admins_group),
            command=('group_add_member', [admins_group], dict(user=admin2)),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result={
                        'dn': get_group_dn(admins_group),
                        'member_user': [admin1, admin2],
                        'gidnumber': [fuzzy_digits],
                        'cn': [admins_group],
                        'description': [u'Account administrators group'],
                },
            ),
        ),


        dict(
            desc=('Retrieve admins group "%s" to verify membership is '
                  '"%s","%s"' % (admins_group, admin1, admin2)),
            command=('group_show', [admins_group], {}),
            expected=dict(
                value=admins_group,
                result=dict(
                    cn=[admins_group],
                    gidnumber=[fuzzy_digits],
                    description=[u'Account administrators group'],
                    dn=get_group_dn(admins_group),
                    member_user=[admin1, admin2],
                ),
                summary=None,
            ),
        ),

        dict(
            desc=('Disable 2nd admin user "%s", admins group "%s" should also '
                  'contain enabled "%s"' % (admin2, admins_group, admin1)),
            command=(
                'user_disable', [admin2], {}
            ),
            expected=dict(
                result=True,
                value=admin2,
                summary=u'Disabled user account "%s"' % admin2,
            ),
        ),

        dict(
            desc='Assert 2nd admin user "%s" is disabled' % admin2,
            command=('user_find', [admin2], {}),
            expected=dict(
                result=[lambda d: d['nsaccountlock'] is True],
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),

        dict(
            desc='Try to disable the origin admin user "%s"' % admin1,
            command=('user_disable', [admin1], {}),
            expected=errors.LastMemberError(key=admin1, label=u'group',
                container=admins_group),
        ),

        dict(
            desc='Try to remove the original admin user "%s"' % admin1,
            command=('user_del', [admin1], {}),
            expected=errors.LastMemberError(key=admin1, label=u'group',
                container=admins_group),
        ),

        dict(
            desc='Delete 2nd admin "%s"' % admin2,
            command=('user_del', [admin2], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % admin2,
                value=[admin2],
            ),
        ),

        dict(
            desc=('Retrieve admins group "%s" to verify membership is "%s"'
                  % (admins_group, admin1)),
            command=('group_show', [admins_group], {}),
            expected=dict(
                value=admins_group,
                result=dict(
                    cn=[admins_group],
                    gidnumber=[fuzzy_digits],
                    description=[u'Account administrators group'],
                    dn=get_group_dn(admins_group),
                    member_user=[admin1],
                ),
                summary=None,
            ),
        ),

        dict(
            desc='Assert original admin user "%s" is enabled' % admin1,
            command=('user_find', [admin1], {}),
            expected=dict(
                result=[lambda d: d['nsaccountlock'] is False],
                summary=u'1 user matched',
                count=1,
                truncated=False,
            ),
        ),

        dict(
            desc='Try to remove the original admin user "%s"' % admin1,
            command=('user_del', [admin1], {}),
            expected=errors.LastMemberError(key=admin1, label=u'group',
                container=admins_group),
        ),

        dict(
            desc='Try to disable the original admin user "%s"' % admin1,
            command=('user_disable', [admin1], {}),
            expected=errors.LastMemberError(key=admin1, label=u'group',
                container=admins_group),
        ),

        dict(
            desc='Set default automember group for groups as ipausers',
            command=(
                'automember_default_group_set', [], dict(
                    type=u'group',
                    automemberdefaultgroup=u'ipausers'
                    )
            ),
            expected=dict(
                result=dict(
                    cn=[u'Group'],
                    automemberdefaultgroup=[DN(('cn', 'ipausers'),
                                               ('cn', 'groups'),
                                               ('cn', 'accounts'),
                                               api.env.basedn)],
                ),
                value=u'group',
                summary=u'Set default (fallback) group for automember "group"',
            ),
        ),

        dict(
            desc='Delete "%s"' % user2,
            command=('user_del', [user2], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user2,
                value=[user2],
            ),
        ),

        dict(
            desc='Create %r' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "tuser2"',
                result=get_user_result(user2, u'Test', u'User2', 'add'),
            ),
        ),

        dict(
            desc='Create "%s" with UID 999' % user1,
            command=(
                'user_add', [user1], dict(
                    givenname=u'Test', sn=u'User1', uidnumber=999)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add',
                                       uidnumber=[u'999'],
                                       gidnumber=[u'999']),
            ),
            extra_check = upg_check,
        ),

        dict(
            desc='Delete "%s"' % user1,
            command=('user_del', [user1], {}),
            expected=dict(
                result=dict(failed=[]),
                summary=u'Deleted user "%s"' % user1,
                value=[user1],
            ),
        ),

        dict(
            desc='Create "%s" with old DNA_MAGIC uid 999' % user1,
            command=(
                'user_add', [user1], dict(
                    givenname=u'Test', sn=u'User1', uidnumber=999,
                    version=u'2.49')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(
                    user1, u'Test', u'User1', 'add',
                    uidnumber=[lambda v: int(v) != 999],
                    gidnumber=[lambda v: int(v) != 999],
                ),
            ),
            extra_check = upg_check,
        ),

        dict(
            desc='Set ipauserauthtype for "%s"' % user1,
            command=('user_mod', [user1], dict(ipauserauthtype=u'password')),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                                       ipauserauthtype=[u'password'],
                ),
                value=user1,
                summary='Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Retrieve "%s" to verify ipauserauthtype' % user1,
            command=('user_show', [user1], {}),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'show',
                                       ipauserauthtype=[u'password'],
                ),
                value=user1,
                summary=None,
            ),
        ),

        dict(
            desc='Unset ipauserauthtype for "%s"' % user1,
            command=('user_mod', [user1], dict(ipauserauthtype=None)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod'),
                value=user1,
                summary='Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Query status of "%s"' % user1,
            command=('user_status', [user1], {}),
            expected=dict(
                count=1,
                result=[
                    dict(
                        dn=get_user_dn(user1),
                        krblastfailedauth=[u'N/A'],
                        krblastsuccessfulauth=[u'N/A'],
                        krbloginfailedcount=u'0',
                        now=isodate_re.match,
                        server=api.env.host,
                    ),
                ],
                summary=u'Account disabled: False',
                truncated=False,
            ),
        ),

        dict(
            desc='Test an invalid preferredlanguage "%s"' % invalidlanguage1,
            command=('user_mod', [user1],
                     dict(preferredlanguage=invalidlanguage1)),
            expected=errors.ValidationError(name='preferredlanguage',
                error=(u'must match RFC 2068 - 14.4, e.g., '
                        '"da, en-gb;q=0.8, en;q=0.7"')),
        ),

        dict(
            desc='Test an invalid preferredlanguage "%s"' % invalidlanguage2,
            command=('user_mod', [user1],
                     dict(preferredlanguage=invalidlanguage2)),
            expected=errors.ValidationError(name='preferredlanguage',
                error=(u'must match RFC 2068 - 14.4, e.g., '
                        '"da, en-gb;q=0.8, en;q=0.7"')),
        ),

        dict(
            desc='Test an invalid preferredlanguage "%s"' % invalidlanguage3,
            command=('user_mod', [user1],
                     dict(preferredlanguage=invalidlanguage3)),
            expected=errors.ValidationError(name='preferredlanguage',
                error=(u'must match RFC 2068 - 14.4, e.g., '
                        '"da, en-gb;q=0.8, en;q=0.7"')),
        ),

        dict(
            desc='Test an invalid preferredlanguage "%s"' % invalidlanguage4,
            command=('user_mod', [user1],
                     dict(preferredlanguage=invalidlanguage4)),
            expected=errors.ValidationError(name='preferredlanguage',
                error=(u'must match RFC 2068 - 14.4, e.g., '
                        '"da, en-gb;q=0.8, en;q=0.7"')),
        ),

        dict(
            desc='Test an invalid preferredlanguage "%s"' % invalidlanguage5,
            command=('user_mod', [user1],
                     dict(preferredlanguage=invalidlanguage5)),
            expected=errors.ValidationError(name='preferredlanguage',
                error=(u'must match RFC 2068 - 14.4, e.g., '
                        '"da, en-gb;q=0.8, en;q=0.7"')),
        ),

        dict(
            desc='Set preferredlanguage "%s"' % validlanguage1,
            command=('user_mod', [user1],
                     dict(preferredlanguage=validlanguage1)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                                       preferredlanguage=[validlanguage1],
                ),
                value=user1,
                summary='Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Set preferredlanguage "%s"' % validlanguage2,
            command=('user_mod', [user1],
                     dict(preferredlanguage=validlanguage2)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                                       preferredlanguage=[validlanguage2],
                ),
                value=user1,
                summary='Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Set principal expiration "%s"' % principal_expiration_string,
            command=('user_mod', [user1],
                     dict(krbprincipalexpiration=principal_expiration_string)),
            expected=dict(
                result=get_user_result(user1, u'Test', u'User1', 'mod',
                    krbprincipalexpiration=[principal_expiration_date],
                ),
                value=user1,
                summary='Modified user "%s"' % user1,
            ),
        ),

        dict(
            desc='Set principal expiration "%s"' % invalid_expiration_string,
            command=('user_mod', [user1],
                     dict(krbprincipalexpiration=invalid_expiration_string)),
            expected=errors.ConversionError(name='principal_expiration',
                error=(u'does not match any of accepted formats: '
                        '%Y%m%d%H%M%SZ, %Y-%m-%dT%H:%M:%SZ, %Y-%m-%dT%H:%MZ, '
                        '%Y-%m-%dZ, %Y-%m-%d %H:%M:%SZ, %Y-%m-%d %H:%MZ')
            ),
        ),

    ]


class test_denied_bind_with_expired_principal(XMLRPC_test):

    password = u'random'

    @classmethod
    def setup_class(cls):
        super(test_denied_bind_with_expired_principal, cls).setup_class()

        cls.connection = ldap.initialize('ldap://{host}'
                                         .format(host=api.env.host))

    def test_1_bind_as_test_user(self):
        self.failsafe_add(
            api.Object.user,
            user1,
            givenname=u'Test',
            sn=u'User1',
            userpassword=self.password,
            krbprincipalexpiration=principal_expiration_string
        )

        self.connection.simple_bind_s(str(get_user_dn(user1)), self.password)

    def test_2_bind_as_expired_test_user(self):
        api.Command['user_mod'](
                user1,
                krbprincipalexpiration=expired_expiration_string)

        raises(ldap.UNWILLING_TO_PERFORM,
               self.connection.simple_bind_s,
               str(get_user_dn(user1)), self.password)

    def test_3_bind_as_renewed_test_user(self):
        api.Command['user_mod'](
                user1,
                krbprincipalexpiration=principal_expiration_string)

        self.connection.simple_bind_s(str(get_user_dn(user1)), self.password)
