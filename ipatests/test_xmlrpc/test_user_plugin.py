# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   Filip Skola <fskola@redhat.com>
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
Test the `ipaserver/plugins/user.py` module.
"""

import pytest
import datetime
import ldap
import re

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import (
    assert_deepequal, assert_equal, assert_not_equal, raises)
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test, fuzzy_digits, fuzzy_uuid, fuzzy_password,
    Fuzzy, fuzzy_dergeneralizedtime, add_sid, add_oc, raises_exact)
from ipapython.dn import DN
from ipapython.ipaldap import ldap_initialize

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.group_plugin import GroupTracker
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker

admin1 = u'admin'
admin_group = u'admins'

invaliduser1 = u'+tuser1'
invaliduser2 = u''.join(['a' for n in range(256)])

sshpubkey = (u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
             'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
             'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
             'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
             'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
             '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
             '0L public key test')
sshpubkeyfp = (u'SHA256:cStA9o5TRSARbeketEOooMUMSWRSsArIAXloBZ4vNsE '
               'public key test (ssh-rsa)')

validlanguages = {
    u'en-US;q=0.987 , en, abcdfgh-abcdefgh;q=1        , a;q=1.000',
    u'*'
    }

invalidlanguages = {
    u'abcdfghji-abcdfghji', u'en-us;q=0,123',
    u'en-us;q=0.1234', u'en-us;q=1.1', u'en-us;q=1.0000'
    }

principal_expiration_string = "2020-12-07T19:54:13Z"
principal_expiration_date = datetime.datetime(2020, 12, 7, 19, 54, 13)

invalid_expiration_string = "2020-12-07 19:54:13"
expired_expiration_string = "1991-12-07T19:54:13Z"

# Date in ISO format (2013-12-10T12:00:00)
isodate_re = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')


@pytest.fixture(scope='class')
def user_min(request):
    """ User tracker fixture for testing user with uid no specified """
    tracker = UserTracker(givenname=u'Testmin', sn=u'Usermin')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user(request):
    tracker = UserTracker(name=u'user1', givenname=u'Test', sn=u'User1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user2(request):
    tracker = UserTracker(name=u'user2', givenname=u'Test2', sn=u'User2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def renameduser(request):
    tracker = UserTracker(name=u'ruser1', givenname=u'Ruser', sn=u'Ruser1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def admin2(request):
    tracker = UserTracker(name=u'admin2', givenname=u'Second', sn=u'Admin')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user_npg(request, group):
    """ User tracker fixture for testing users with no private group """
    tracker = UserTracker(name=u'npguser1', givenname=u'Npguser',
                          sn=u'Npguser1', noprivate=True)
    tracker.track_create()
    del tracker.attrs['mepmanagedentry']
    tracker.attrs.update(
        description=[], memberof_group=[group.cn],
        objectclass=add_oc(objectclasses.user_base, u'ipantuserattrs')
    )
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user_npg2(request, group):
    """ User tracker fixture for testing users with no private group """
    tracker = UserTracker(name=u'npguser2', givenname=u'Npguser',
                          sn=u'Npguser2', noprivate=True, gidnumber=1000)
    tracker.track_create()
    del tracker.attrs['mepmanagedentry']
    tracker.attrs.update(
        gidnumber=[u'1000'], description=[], memberof_group=[group.cn],
        objectclass=add_oc(objectclasses.user_base, u'ipantuserattrs')
    )
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user_radius(request):
    """ User tracker fixture for testing users with radius user name """
    tracker = UserTracker(name=u'radiususer', givenname=u'radiususer',
                          sn=u'radiususer1',
                          ipatokenradiususername=u'radiususer')
    tracker.track_create()
    tracker.attrs.update(
        objectclass=objectclasses.user + [u'ipatokenradiusproxyuser']
    )
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group(request):
    tracker = GroupTracker(name=u'group1')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestNonexistentUser(XMLRPC_test):
    def test_retrieve_nonexistent(self, user):
        """ Try to retrieve a non-existent user """
        user.ensure_missing()
        command = user.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user.uid)):
            command()

    def test_update_nonexistent(self, user):
        """ Try to update a non-existent user """
        user.ensure_missing()
        command = user.make_update_command(
            updates=dict(givenname=u'changed'))
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user.uid)):
            command()

    def test_delete_nonexistent(self, user):
        """ Try to delete a non-existent user """
        user.ensure_missing()
        command = user.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user.uid)):
            command()

    def test_rename_nonexistent(self, user, renameduser):
        """ Try to rename a non-existent user """
        user.ensure_missing()
        command = user.make_update_command(
            updates=dict(setattr=u'uid=%s' % renameduser.uid))
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user.uid)):
            command()


@pytest.mark.tier1
class TestUser(XMLRPC_test):
    def test_retrieve(self, user):
        """ Create user and try to retrieve it """
        user.ensure_exists()
        user.retrieve()

    def test_delete(self, user):
        """ Delete user """
        user.delete()

    def test_query_status(self, user):
        """ Query user_status on a user """
        user.ensure_exists()
        result = user.run_command('user_status', user.uid)
        assert_deepequal(dict(
            count=1,
            result=[dict(
                dn=user.dn,
                krblastfailedauth=[u'N/A'],
                krblastsuccessfulauth=[u'N/A'],
                krbloginfailedcount=u'0',
                now=isodate_re.match,
                server=api.env.host,
                ), ],
            summary=u'Account disabled: False',
            truncated=False,
        ), result)
        user.delete()

    def test_remove_userclass(self, user):
        """ Remove attribute userclass from user entry """
        user.ensure_exists()
        result = user.run_command(
            'user_mod', user.uid, **dict(userclass=u'')
        )
        user.check_update(result)
        user.delete()


@pytest.mark.tier1
class TestFind(XMLRPC_test):
    def test_find(self, user):
        """ Basic check of user-find """
        user.ensure_exists()
        user.find()

    def test_find_with_all(self, user):
        """ Basic check of user-find with --all """
        user.find(all=True)

    def test_find_with_pkey_only(self, user):
        """ Basic check of user-find with primary keys only """
        user.ensure_exists()
        command = user.make_find_command(
            uid=user.uid, pkey_only=True
        )
        result = command()
        user.check_find(result, pkey_only=True)

    def test_find_enabled_user(self, user):
        """Test user-find --disabled=False with enabled user"""
        user.ensure_exists()
        command = user.make_find_command(
            uid=user.uid, pkey_only=True, nsaccountlock=False)
        result = command()
        user.check_find(result, pkey_only=True)

    def test_negative_find_enabled_user(self, user):
        """Test user-find --disabled=True with enabled user, shouldn't
        return any result"""
        user.ensure_exists()
        command = user.make_find_command(
            uid=user.uid, pkey_only=True, nsaccountlock=True)
        result = command()
        user.check_find_nomatch(result)

    def test_find_disabled_user(self, user):
        """Test user-find --disabled=True with disabled user"""
        user.ensure_exists()
        user.disable()
        command = user.make_find_command(
            uid=user.uid, pkey_only=True, nsaccountlock=True)
        result = command()
        user.check_find(result, pkey_only=True)
        user.enable()

    def test_negative_find_disabled_user(self, user):
        """Test user-find --disabled=False with disabled user, shouldn't
        return any results"""
        user.ensure_exists()
        user.disable()
        command = user.make_find_command(
            uid=user.uid, pkey_only=True, nsaccountlock=False)
        result = command()
        user.check_find_nomatch(result)
        user.enable()


@pytest.mark.tier1
class TestActive(XMLRPC_test):
    def test_disable(self, user):
        """ Disable user using user-disable """
        user.ensure_exists()
        user.disable()
        command = user.make_retrieve_command()
        result = command()
        user.check_retrieve(result)

    def test_enable(self, user):
        """ Enable user using user-enable """
        user.ensure_exists()
        user.enable()
        command = user.make_retrieve_command()
        result = command()
        user.check_retrieve(result)

    def test_disable_using_setattr(self, user):
        """ Disable user using setattr """
        user.ensure_exists()
        # we need to update the track manually
        user.attrs['nsaccountlock'] = True

        command = user.make_update_command(
            updates=dict(setattr=u'nsaccountlock=True')
        )
        result = command()
        user.check_update(result)

    def test_enable_using_setattr(self, user):
        """ Enable user using setattr """
        user.ensure_exists()
        user.attrs['nsaccountlock'] = False

        command = user.make_update_command(
            updates=dict(setattr=u'nsaccountlock=False')
        )
        result = command()
        user.check_update(result)

    def test_disable_using_usermod(self, user):
        """ Disable user using user-mod """
        user.update(dict(nsaccountlock=True), dict(nsaccountlock=True))

    def test_enable_using_usermod(self, user):
        """ Enable user using user-mod """
        user.update(dict(nsaccountlock=False), dict(nsaccountlock=False))


@pytest.mark.tier1
class TestUpdate(XMLRPC_test):
    def test_set_virtual_attribute(self, user):
        """ Try to assign an invalid virtual attribute """
        attr = 'random'
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(setattr=(u'%s=xyz123' % attr))
        )
        with raises_exact(errors.ObjectclassViolation(
                info=u'attribute "%s" not allowed' % attr)):
            command()

    def test_update(self, user):
        """ Update a user attribute """
        user.update(dict(givenname=u'Franta'))

    def test_update_krb_ticket_policy(self, user):
        """ Try to update krbmaxticketlife """
        attr = 'krbmaxticketlife'
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(setattr=(u'%s=88000' % attr))
        )
        with raises_exact(errors.ObjectclassViolation(
                info=u'attribute "%s" not allowed' % attr)):
            command()

    def test_rename(self, user, renameduser):
        """ Rename user and than rename it back """
        user.ensure_exists()
        renameduser.ensure_missing()
        olduid = user.uid

        user.update(updates=dict(rename=renameduser.uid))

        # rename the test user back so it gets properly deleted
        user.update(updates=dict(rename=olduid))

    def test_rename_to_the_same_value(self, user):
        """ Try to rename user to the same value """
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(setattr=(u'uid=%s' % user.uid))
        )
        with raises_exact(errors.EmptyModlist()):
            command()

    def test_rename_to_the_same_with_other_mods(self, user):
        """ Try to rename user to the same value while
        including other modifications that should be done """
        user.ensure_exists()
        user.attrs.update(loginshell=[u'/bin/false'])
        command = user.make_update_command(
            updates=dict(setattr=u'uid=%s' % user.uid,
                         loginshell=u'/bin/false')
        )
        result = command()
        user.check_update(result)

    def test_rename_to_too_long_login(self, user):
        """ Try to change user login to too long value """
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(rename=invaliduser2)
            # no exception raised, user is renamed
        )
        with raises_exact(errors.ValidationError(
                name='rename',
                error=u'can be at most 255 characters')):
            command()

    def test_update_illegal_ssh_pubkey(self, user):
        """ Try to update user with an illegal SSH public key """
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(ipasshpubkey=[u"anal nathrach orth' bhais's bethad "
                                       "do che'l de'nmha"])
        )
        with raises_exact(errors.ValidationError(
                name='sshpubkey',
                error=u'invalid SSH public key')):
            command()

    def test_set_ipauserauthtype(self, user):
        """ Set ipauserauthtype to 'password' and than back to None """
        user.ensure_exists()
        user.update(dict(ipauserauthtype=u'password'))
        user.retrieve()

        user.update(dict(ipauserauthtype=None))
        user.delete()

    def test_set_random_password(self, user):
        """ Modify user with random password """
        user.ensure_exists()
        user.attrs.update(
            randompassword=fuzzy_password,
            has_keytab=True,
            has_password=True
        )
        user.update(
            dict(random=True),
            dict(random=None, randompassword=fuzzy_password)
        )
        user.delete()

    def test_rename_to_invalid_login(self, user):
        """ Try to change user login to an invalid value """
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(rename=invaliduser1)
        )
        with raises_exact(errors.ValidationError(
                name='rename',
                error=u'may only include letters, numbers, _, -, . and $')):
            command()

    def test_add_radius_username(self, user):
        """ Test for ticket 7569: Try to add --radius-username """
        user.ensure_exists()
        command = user.make_update_command(
            updates=dict(ipatokenradiususername=u'radiususer')
        )
        command()
        user.delete()


@pytest.mark.tier1
class TestCreate(XMLRPC_test):
    def test_create_user_with_min_values(self, user_min):
        """ Create user with uid not specified """
        user_min.ensure_missing()
        command = user_min.make_create_command()
        command()

    def test_create_with_krb_ticket_policy(self):
        """ Try to create user with krbmaxticketlife set """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test',
            sn=u'Tuser1', setattr=u'krbmaxticketlife=88000'
        )
        command = testuser.make_create_command()
        with raises_exact(errors.ObjectclassViolation(
                info=u'attribute "%s" not allowed' % 'krbmaxticketlife')):
            command()

    def test_create_with_ssh_pubkey(self):
        """ Create user with an assigned SSH public key """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test',
            sn=u'Tuser1', ipasshpubkey=sshpubkey
        )
        testuser.track_create()
        # fingerprint is expected in the tracker attrs
        testuser.attrs.update(sshpubkeyfp=[sshpubkeyfp])
        command = testuser.make_create_command()
        result = command()
        testuser.check_create(result)
        testuser.delete()

    def test_create_with_invalid_login(self):
        """ Try to create user with an invalid login string """
        testuser = UserTracker(
            name=invaliduser1, givenname=u'Test', sn=u'User1'
        )
        command = testuser.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'login',
                error=u'may only include letters, numbers, _, -, . and $')):
            command()

    def test_create_with_too_long_login(self):
        """ Try to create user with too long login string """
        testuser = UserTracker(
            name=invaliduser2, givenname=u'Test', sn=u'User1'
        )
        command = testuser.make_create_command()
        with raises_exact(errors.ValidationError(
                name=u'login',
                error=u'can be at most 255 characters')):
            command()

    def test_create_with_full_address(self):
        """ Create user with full address set """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            street=u'123 Maple Rd', l=u'Anytown', st=u'MD',
            postalcode=u'01234-5678', mobile=u'410-555-1212'
        )
        testuser.create()
        testuser.delete()

    def test_create_with_random_passwd(self):
        """ Create user with random password """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1', random=True
        )
        testuser.track_create()
        testuser.attrs.update(
            randompassword=fuzzy_password,
            has_keytab=True, has_password=True,
            krbextradata=[Fuzzy(type=bytes)],
            krbpasswordexpiration=[fuzzy_dergeneralizedtime],
            krblastpwdchange=[fuzzy_dergeneralizedtime]
        )
        command = testuser.make_create_command()
        result = command()
        testuser.check_create(result)
        testuser.delete()

    def test_create_with_different_default_home(self, user):
        """ Change default home directory and check that a newly created
            user has his home set properly """
        user.ensure_missing()
        user.run_command('config_mod', **{u'ipahomesrootdir': u'/other-home'})
        user.track_create()
        user.attrs.update(homedirectory=[u'/other-home/%s' % user.name])

        command = user.make_create_command()
        result = command()
        user.check_create(result)
        user.run_command('config_mod', **{u'ipahomesrootdir': u'/home'})
        user.delete()

    def test_create_with_different_default_shell(self, user):
        """ Change default login shell and check that a newly created
            user is created with correct login shell value """
        user.ensure_missing()
        user.run_command(
            'config_mod', **{u'ipadefaultloginshell': u'/bin/zsh'}
        )
        user.track_create()
        user.attrs.update(loginshell=[u'/bin/zsh'])
        command = user.make_create_command()
        result = command()
        user.check_create(result)
        user.run_command(
            'config_mod', **{u'ipadefaultloginshell': u'/bin/sh'}
        )
        user.delete()

    def test_create_without_upg(self):
        """ Try to create user without User's Primary GID """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            noprivate=True
        )
        command = testuser.make_create_command()
        with raises_exact(errors.NotFound(
                reason=u'Default group for new users is not POSIX')):
            command()

    def test_create_without_upg_with_gid_set(self):
        """ Create user without User's Primary GID with GID set """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            noprivate=True, gidnumber=1000
        )
        testuser.track_create()
        del testuser.attrs['mepmanagedentry']
        testuser.attrs.update(gidnumber=[u'1000'])
        testuser.attrs.update(
            description=[],
            objectclass=add_oc(objectclasses.user_base, u'ipantuserattrs')
        )
        command = testuser.make_create_command()
        result = command()
        testuser.check_create(result, [u'description'])
        testuser.delete()

    def test_create_with_uid_999(self):
        """ Check that server return uid and gid 999
        when a new client asks for uid 999 """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1', uidnumber=999
        )
        testuser.track_create()
        testuser.attrs.update(
            uidnumber=[u'999'],
            gidnumber=[u'999']
        )
        command = testuser.make_create_command()
        result = command()
        testuser.check_create(result)
        testuser.delete()

    def test_create_with_old_DNA_MAGIC_999(self):
        """ Check that server picks suitable uid and gid
        when an old client asks for the magic uid 999 """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            uidnumber=999, version=u'2.49'
        )
        testuser.track_create()
        testuser.attrs.update(
            uidnumber=[lambda v: int(v) != 999],
            gidnumber=[lambda v: int(v) != 999],
        )
        command = testuser.make_create_command()
        result = command()
        testuser.check_create(result)
        testuser.delete()

    def test_create_duplicate(self, user):
        """ Try to create second user with the same name """
        user.ensure_exists()
        command = user.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'user with name "%s" already exists' %
                user.uid)):
            command()

    def test_create_where_managed_group_exists(self, user, group):
        """ Create a managed group and then try to create user
        with the same name the group has """
        group.create()
        command = user.make_command(
            'user_add', group.cn, **dict(givenname=u'Test', sn=u'User1')
        )
        with raises_exact(errors.ManagedGroupExistsError(group=group.cn)):
            command()

    def test_create_with_username_starting_with_numeric(self):
        """Successfully create a user with name starting with numeric chars"""
        testuser = UserTracker(
            name=u'1234user', givenname=u'First1234', sn=u'Surname1234',
        )
        testuser.create()
        testuser.delete()

    def test_create_with_numeric_only_username(self):
        """Try to create a user with name only contains numeric chars"""
        testuser = UserTracker(
            name=u'1234', givenname=u'NumFirst1234', sn=u'NumSurname1234',
        )
        with raises_exact(errors.ValidationError(
                name=u'login',
                error=u'may only include letters, numbers, _, -, . and $',
        )):
            testuser.create()

    def test_create_with_radius_username(self, user_radius):
        """Test for issue 7569: try to create a user with --radius-username"""
        command = user_radius.make_create_command()
        result = command()
        user_radius.check_create(result)
        user_radius.delete()


@pytest.mark.tier1
class TestUserWithGroup(XMLRPC_test):
    def test_change_default_user_group(self, group):
        """ Change default group for TestUserWithGroup class of tests """
        group.create()
        group.run_command(
            'config_mod', **{u'ipadefaultprimarygroup': group.cn}
        )

    def test_create_without_upg(self, user_npg):
        """ Try to create user without User's Primary GID
        after default group was changed """
        command = user_npg.make_create_command()
        # User without private group has some different attrs upon creation
        # so we won't use make_create, but do own check instead
        # These are set in the fixture
        result = command()
        user_npg.check_create(result, [u'description', u'memberof_group'])

    def test_create_without_upg_with_gid_set(self, user_npg2):
        """ Create user without User's Primary GID with GID set
        after default group was changed """
        command = user_npg2.make_create_command()
        result = command()
        user_npg2.check_create(result, [u'description', u'memberof_group'])

    def test_set_manager(self, user_npg, user_npg2):
        """ Update user with own group with manager with own group """
        user_npg.update(dict(manager=user_npg2.uid))

    def test_check_user_with_renamed_manager(self, user_npg, user_npg2):
        """ Rename manager with own group, retrieve user and check
            if its manager is also renamed """
        renamed_name = u'renamed_npg2'
        old_name = user_npg2.uid

        user_npg2.update(updates=dict(rename=renamed_name))

        user_npg.attrs.update(manager=[renamed_name])
        user_npg.retrieve(all=True)

        user_npg2.update(updates=dict(rename=old_name))

    def test_check_if_manager_gets_removed(self, user_npg, user_npg2):
        """ Delete manager and check if it's gone from user's attributes """
        user_npg2.delete()
        del user_npg.attrs[u'manager']
        del user_npg.attrs[u'description']
        user_npg.retrieve(all=True)

    def test_change_default_user_group_back(self, user_npg, user_npg2):
        """ Change default group back to 'ipausers' and clean up members """
        user_npg.delete()
        user_npg.run_command(
            'config_mod', **{u'ipadefaultprimarygroup': u'ipausers'}
        )


@pytest.mark.tier1
class TestManagers(XMLRPC_test):
    def test_assign_nonexistent_manager(self, user, user2):
        """ Try to assign user a non-existent manager """
        user.ensure_exists()
        user2.ensure_missing()
        command = user.make_update_command(
            updates=dict(manager=user2.uid)
        )
        with raises_exact(errors.NotFound(
                reason=u'manager %s not found' % user2.uid)):
            command()

    def test_assign_manager(self, user, user2):
        """ Make user manager of another user """
        user.ensure_exists()
        user2.ensure_exists()
        user.update(dict(manager=user2.uid))

    def test_search_by_manager(self, user, user2):
        """ Find user by his manager's UID """
        command = user.make_find_command(manager=user2.uid)
        result = command()
        user.check_find(result)

    def test_delete_both_user_and_manager(self, user, user2):
        """ Delete both user and its manager at once """
        result = user.run_command(
            'user_del', [user.uid, user2.uid],
            preserve=False, no_preserve=True
        )
        assert_deepequal(dict(
            value=[user.uid, user2.uid],
            summary=u'Deleted user "%s,%s"' % (user.uid, user2.uid),
            result=dict(failed=[]),
            ), result)
        # mark users as deleted
        user.exists = False
        user2.exists = False


@pytest.mark.tier1
class TestAdmins(XMLRPC_test):
    def test_remove_original_admin(self):
        """ Try to remove the only admin """
        tracker = Tracker()
        command = tracker.make_command('user_del', [admin1])

        with raises_exact(errors.LastMemberError(
                key=admin1, label=u'group', container=admin_group)):
            command()

    def test_disable_original_admin(self):
        """ Try to disable the only admin """
        tracker = Tracker()
        command = tracker.make_command('user_disable', admin1)

        with raises_exact(errors.LastMemberError(
                key=admin1, label=u'group', container=admin_group)):
            command()

    def test_create_admin2(self, admin2):
        """ Test whether second admin gets created """
        admin2.ensure_exists()
        admin2.make_admin()
        admin2.delete()

    def test_last_admin_preservation(self, admin2):
        """ Create a second admin, disable it. Then try to disable and
        remove the original one and receive LastMemberError. Last trial
        are these ops with second admin removed. """
        admin2.ensure_exists()
        admin2.make_admin()
        admin2.disable()
        tracker = Tracker()

        with raises_exact(errors.LastMemberError(
                key=admin1, label=u'group', container=admin_group)):
            tracker.run_command('user_disable', admin1)
        with raises_exact(errors.LastMemberError(
                key=admin1, label=u'group', container=admin_group)):
            tracker.run_command('user_del', admin1)
        admin2.delete()

        with raises_exact(errors.LastMemberError(
                key=admin1, label=u'group', container=admin_group)):
            tracker.run_command('user_disable', admin1)
        with raises_exact(errors.LastMemberError(
                key=admin1, label=u'group', container=admin_group)):
            tracker.run_command('user_del', admin1)


@pytest.mark.tier1
class TestPreferredLanguages(XMLRPC_test):
    def test_invalid_preferred_languages(self, user):
        """ Try to assign various invalid preferred languages to user """
        user.ensure_exists()
        for invalidlanguage in invalidlanguages:
            command = user.make_update_command(
                dict(preferredlanguage=invalidlanguage)
            )

            with raises_exact(errors.ValidationError(
                    name='preferredlanguage',
                    error=(u'must match RFC 2068 - 14.4, e.g., '
                           '"da, en-gb;q=0.8, en;q=0.7"')
            )):
                command()
        user.delete()

    def test_valid_preferred_languages(self, user):
        """ Update user with different preferred languages """
        for validlanguage in validlanguages:
            user.update(dict(preferredlanguage=validlanguage))
        user.delete()


@pytest.mark.tier1
class TestPrincipals(XMLRPC_test):
    def test_create_with_bad_realm_in_principal(self):
        """ Try to create user with a bad realm in principal """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            krbprincipalname=u'tuser1@NOTFOUND.ORG'
        )

        command = testuser.make_create_command()
        with raises_exact(errors.RealmMismatch()):
            command()

    def test_create_with_malformed_principal(self):
        """ Try to create user with wrongly formed principal """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            krbprincipalname=u'tuser1@BAD@NOTFOUND.ORG'
        )

        command = testuser.make_create_command()
        with raises_exact(errors.ConversionError(
                name='principal', error="Malformed principal: '{}'".format(
                    testuser.kwargs['krbprincipalname']))):
            command()

    def test_set_principal_expiration(self, user):
        """ Set principal expiration for user """
        user.update(
            dict(krbprincipalexpiration=principal_expiration_string),
            dict(krbprincipalexpiration=[principal_expiration_date])
        )

    def test_set_invalid_principal_expiration(self, user):
        """ Try to set incorrent principal expiration value for user """
        user.ensure_exists()
        command = user.make_update_command(
            dict(krbprincipalexpiration=invalid_expiration_string)
        )

        with raises_exact(errors.ConversionError(
                name='principal_expiration',
                error=(u'does not match any of accepted formats: '
                       '%Y%m%d%H%M%SZ, %Y-%m-%dT%H:%M:%SZ, %Y-%m-%dT%H:%MZ, '
                       '%Y-%m-%dZ, %Y-%m-%d %H:%M:%SZ, %Y-%m-%d %H:%MZ')
        )):
            command()

    def test_create_with_uppercase_principal(self):
        """ Create user with upper-case principal """
        testuser = UserTracker(
            name=u'tuser1', givenname=u'Test', sn=u'Tuser1',
            krbprincipalname=u'tuser1'.upper()
        )
        testuser.create()
        testuser.delete()


@pytest.mark.tier1
class TestValidation(XMLRPC_test):
    # The assumption for this class of tests is that if we don't
    # get a validation error then the request was processed normally.

    def test_validation_disabled_on_deletes(self):
        """ Test that validation is disabled on user deletes """
        tracker = Tracker()
        command = tracker.make_command('user_del', invaliduser1)
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % invaliduser1)):
            command()

    def test_validation_disabled_on_show(self):
        """ Test that validation is disabled on user retrieves """
        tracker = Tracker()
        command = tracker.make_command('user_show', invaliduser1)
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % invaliduser1)):
            command()

    def test_validation_disabled_on_find(self, user):
        """ Test that validation is disabled on user searches """
        result = user.run_command('user_find', invaliduser1)
        user.check_find_nomatch(result)


@pytest.mark.tier1
class TestDeniedBindWithExpiredPrincipal(XMLRPC_test):

    password = u'random'

    @classmethod
    def setup_class(cls):
        super(TestDeniedBindWithExpiredPrincipal, cls).setup_class()

        cls.connection = ldap_initialize(
            'ldap://{host}'.format(host=api.env.host)
        )

    @classmethod
    def teardown_class(cls):
        super(TestDeniedBindWithExpiredPrincipal, cls).teardown_class()

    def test_bind_as_test_user(self, user):
        """ Bind as user """
        self.failsafe_add(
            api.Object.user,
            user.uid,
            givenname=u'Test',
            sn=u'User1',
            userpassword=self.password,
            krbprincipalexpiration=principal_expiration_string
        )

        self.connection.simple_bind_s(
            str(get_user_dn(user.uid)), self.password
        )

    def test_bind_as_expired_test_user(self, user):
        """ Try to bind as expired user """
        api.Command['user_mod'](
            user.uid,
            krbprincipalexpiration=expired_expiration_string
        )

        raises(ldap.UNWILLING_TO_PERFORM,
               self.connection.simple_bind_s,
               str(get_user_dn(user.uid)), self.password
               )

    def test_bind_as_renewed_test_user(self, user):
        """ Bind as renewed user """
        api.Command['user_mod'](
            user.uid,
            krbprincipalexpiration=principal_expiration_string
        )

        self.connection.simple_bind_s(
            str(get_user_dn(user.uid)), self.password
        )

# This set of functions (get_*, upg_check, not_upg_check)
# is mostly for legacy purposes here, tests using UserTracker
# should not rely on them


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
        krbcanonicalname=[u'%s@%s' % (uid, api.env.realm)],
        krbprincipalname=[u'%s@%s' % (uid, api.env.realm)],
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
            krbcanonicalname=[u'%s@%s' % (uid, api.env.realm)]
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
    """ Get user DN by uid """
    return DN(('uid', uid), api.env.container_user, api.env.basedn)


def get_group_dn(cn):
    """ Get group DN by CN """
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
