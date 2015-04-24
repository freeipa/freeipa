#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipalib/plugins/stageuser.py` module.
"""


import datetime
import ldap
import re
import functools
import pytest

import six

from ipalib import api, errors

from ipatests.test_xmlrpc.ldaptracker import Tracker
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test, fuzzy_digits, fuzzy_uuid, fuzzy_password, fuzzy_string,
    fuzzy_dergeneralizedtime, add_sid, add_oc, raises_exact)

from ipatests.util import (
    assert_equal, assert_deepequal, assert_not_equal, raises)
from ipapython.dn import DN
from ipatests.test_xmlrpc.test_user_plugin import UserTracker, get_user_dn
from ipatests.test_xmlrpc.test_group_plugin import GroupTracker

if six.PY3:
    unicode = str

validuser1 = u'tuser1'
validuser2 = u'tuser2'

uid = u'123'
gid = u'456'
invalidrealm1 = u'suser1@NOTFOUND.ORG'
invalidrealm2 = u'suser1@BAD@NOTFOUND.ORG'

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

options_ok = [
    {u'cn': u'name'},
    {u'initials': u'in'},
    {u'displayname': u'display'},
    {u'homedirectory': u'/home/homedir'},
    {u'gecos': u'gecos'},
    {u'loginshell': u'/bin/shell'},
    {u'mail': u'email@email.email'},
    {u'title': u'newbie'},
    {u'krbprincipalname': u'kerberos@%s' % api.env.realm},
    {u'krbprincipalname': u'KERBEROS@%s' % api.env.realm},
    {u'street': u'first street'},
    {u'l': u'prague'},
    {u'st': u'czech'},
    {u'postalcode': u'12345'},
    {u'telephonenumber': u'123456789'},
    {u'facsimiletelephonenumber': u'123456789'},
    {u'mobile': u'123456789'},
    {u'pager': u'123456789'},
    {u'ou': u'engineering'},
    {u'carlicense': u'abc1234'},
    {u'ipasshpubkey': sshpubkey},
    {u'manager': u'auser1'},
    {u'uidnumber': uid},
    {u'gidnumber': gid},
    {u'uidnumber': uid, u'gidnumber': gid},
    {u'userpassword': u'Secret123'},
    {u'random': True},
    ]


class StageUserTracker(Tracker):
    """ Tracker class for staged user LDAP object

        Implements helper functions for host plugin.
        StageUserTracker object stores information about the user.
    """

    retrieve_keys = {
        u'uid', u'givenname', u'sn', u'homedirectory', u'loginshell',
        u'uidnumber', u'gidnumber', u'mail', u'ou', u'telephonenumber',
        u'title', u'memberof', u'nsaccountlock', u'memberofindirect',
        u'ipauserauthtype', u'userclass', u'ipatokenradiusconfiglink',
        u'ipatokenradiususername', u'krbprincipalexpiration',
        u'usercertificate', u'dn', u'has_keytab', u'has_password',
        u'street', u'postalcode', u'facsimiletelephonenumber',
        u'carlicense', u'ipasshpubkey', u'sshpubkeyfp', u'l',
        u'st', u'mobile', u'pager', }
    retrieve_all_keys = retrieve_keys | {
        u'cn', u'ipauniqueid', u'objectclass', u'description',
        u'displayname', u'gecos', u'initials', u'krbprincipalname', u'manager'}

    create_keys = retrieve_all_keys | {
        u'objectclass', u'ipauniqueid', u'randompassword',
        u'userpassword', u'krbextradata', u'krblastpwdchange',
        u'krbpasswordexpiration', u'krbprincipalkey'}

    update_keys = retrieve_keys - {u'dn', u'nsaccountlock'}
    activate_keys = retrieve_keys | {
        u'has_keytab', u'has_password', u'nsaccountlock'}

    def __init__(self, name, givenname, sn, **kwargs):
        super(StageUserTracker, self).__init__(default_version=None)
        self.uid = name
        self.givenname = givenname
        self.sn = sn
        self.dn = DN(
            ('uid', self.uid), api.env.container_stageuser, api.env.basedn)

        self.kwargs = kwargs

    def make_create_command(self, options=None, force=None):
        """ Make function that creates a staged user using stageuser-add """
        if options is not None:
            self.kwargs = options
        return self.make_command('stageuser_add', self.uid,
                                 givenname=self.givenname,
                                 sn=self.sn, **self.kwargs)

    def make_delete_command(self):
        """ Make function that deletes a staged user using stageuser-del """
        return self.make_command('stageuser_del', self.uid)

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a staged user using stageuser-show """
        return self.make_command('stageuser_show', self.uid, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that finds staged user using stageuser-find """
        return self.make_command('stageuser_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates staged user using stageuser-mod """
        return self.make_command('stageuser_mod', self.uid, **updates)

    def make_activate_command(self):
        """ Make function that activates staged user
            using stageuser-activate """
        return self.make_command('stageuser_activate', self.uid)

    def track_create(self):
        """ Update expected state for staged user creation """
        self.attrs = dict(
            dn=self.dn,
            uid=[self.uid],
            givenname=[self.givenname],
            sn=[self.sn],
            homedirectory=[u'/home/%s' % self.uid],
            displayname=[u'%s %s' % (self.givenname, self.sn)],
            cn=[u'%s %s' % (self.givenname, self.sn)],
            initials=[u'%s%s' % (self.givenname[0], self.sn[0])],
            objectclass=objectclasses.user_base,
            description=[u'__no_upg__'],
            ipauniqueid=[u'autogenerate'],
            uidnumber=[u'-1'],
            gidnumber=[u'-1'],
            krbprincipalname=[u'%s@%s' % (self.uid, self.api.env.realm)],
            mail=[u'%s@%s' % (self.uid, self.api.env.domain)],
            gecos=[u'%s %s' % (self.givenname, self.sn)],
            loginshell=[u'/bin/sh'],
            has_keytab=False,
            has_password=False,
            nsaccountlock=[u'true'],
            )

        for key in self.kwargs:
            if key == u'krbprincipalname':
                self.attrs[key] = [u'%s@%s' % (
                    (self.kwargs[key].split('@'))[0].lower(),
                    (self.kwargs[key].split('@'))[1])]
            elif key == u'manager':
                self.attrs[key] = [unicode(get_user_dn(self.kwargs[key]))]
            elif key == u'ipasshpubkey':
                self.attrs[u'sshpubkeyfp'] = [sshpubkeyfp]
                self.attrs[key] = [self.kwargs[key]]
            elif key == u'random' or key == u'userpassword':
                self.attrs[u'krbextradata'] = [fuzzy_string]
                self.attrs[u'krbpasswordexpiration'] = [
                    fuzzy_dergeneralizedtime]
                self.attrs[u'krblastpwdchange'] = [fuzzy_dergeneralizedtime]
                self.attrs[u'krbprincipalkey'] = [fuzzy_string]
                self.attrs[u'userpassword'] = [fuzzy_string]
                self.attrs[u'has_keytab'] = True
                self.attrs[u'has_password'] = True
                if key == u'random':
                    self.attrs[u'randompassword'] = fuzzy_string
            else:
                self.attrs[key] = [self.kwargs[key]]

        self.exists = True

    def check_create(self, result):
        """ Check 'stageuser-add' command result """
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Added stage user "%s"' % self.uid,
            result=self.filter_attrs(self.create_keys),
        ), result)

    def check_delete(self, result):
        """ Check 'stageuser-del' command result """
        assert_deepequal(dict(
            value=[self.uid],
            summary=u'Deleted stage user "%s"' % self.uid,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Check 'stageuser-show' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        # small override because stageuser-find returns different
        # type of nsaccountlock value than DS, but overall the value
        # fits expected result
        if expected[u'nsaccountlock'] == [u'true']:
            expected[u'nsaccountlock'] = True
        elif expected[u'nsaccountlock'] == [u'false']:
            expected[u'nsaccountlock'] = False

        assert_deepequal(dict(
            value=self.uid,
            summary=None,
            result=expected,
        ), result)

    def check_find(self, result, all=False, raw=False):
        """ Check 'stageuser-find' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        # small override because stageuser-find returns different
        # type of nsaccountlock value than DS, but overall the value
        # fits expected result
        if expected[u'nsaccountlock'] == [u'true']:
            expected[u'nsaccountlock'] = True
        elif expected[u'nsaccountlock'] == [u'false']:
            expected[u'nsaccountlock'] = False

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 user matched',
            result=[expected],
        ), result)

    def check_find_nomatch(self, result):
        """ Check 'stageuser-find' command result when no match is expected """
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 users matched',
            result=[],
        ), result)

    def check_update(self, result, extra_keys=()):
        """ Check 'stageuser-mod' command result """
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Modified stage user "%s"' % self.uid,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def check_restore_preserved(self, result):
        assert_deepequal(dict(
            value=[self.uid],
            summary=u'Staged user account "%s"' % self.uid,
            result=dict(failed=[]),
        ), result)

    def make_fixture_activate(self, request):
        """Make a pytest fixture for a staged user that is to be activated

        The fixture ensures the plugin entry does not exist before
        and after the tests that use it. It takes into account
        that the staged user no longer exists after activation,
        therefore the fixture verifies after the tests
        that the staged user doesn't exist instead of deleting it.
        """
        del_command = self.make_delete_command()
        try:
            del_command()
        except errors.NotFound:
            pass

        def finish():
            with raises_exact(errors.NotFound(
                    reason=u'%s: stage user not found' % self.uid)):
                del_command()

        request.addfinalizer(finish)

        return self

    def create_from_preserved(self, user):
        """ Copies values from preserved user - helper function for
        restoration tests """
        self.attrs = user.attrs
        self.uid = user.uid
        self.givenname = user.givenname
        self.sn = user.sn
        self.dn = DN(
            ('uid', self.uid), api.env.container_stageuser, api.env.basedn)
        self.attrs[u'dn'] = self.dn


@pytest.fixture(scope='class')
def stageduser(request):
    tracker = StageUserTracker(name=u'suser1', givenname=u'staged', sn=u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class', params=options_ok)
def stageduser2(request):
    tracker = StageUserTracker(u'suser2', u'staged', u'user', **request.param)
    return tracker.make_fixture_activate(request)


@pytest.fixture(scope='class')
def stageduser3(request):
    tracker = StageUserTracker(name=u'suser3', givenname=u'staged', sn=u'user')
    return tracker.make_fixture_activate(request)


@pytest.fixture(scope='class')
def stageduser4(request):
    tracker = StageUserTracker(u'tuser', u'test', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user(request):
    tracker = UserTracker(u'auser1', u'active', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user2(request):
    tracker = UserTracker(u'suser3', u'staged', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user3(request):
    tracker = UserTracker(u'auser2', u'active', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user4(request):
    tracker = UserTracker(u'tuser', u'test', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user5(request):
    tracker = UserTracker(u'tuser', u'test', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user6(request):
    tracker = UserTracker(u'suser2', u'staged', u'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user7(request):
    tracker = UserTracker(u'puser1', u'preserved', u'user')
    return tracker.make_fixture_restore(request)


@pytest.mark.tier1
class TestNonexistentStagedUser(XMLRPC_test):
    def test_retrieve_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: stage user not found' % stageduser.uid)):
            command()

    def test_delete_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: stage user not found' % stageduser.uid)):
            command()

    def test_update_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_update_command(
            updates=dict(givenname=u'changed'))
        with raises_exact(errors.NotFound(
                reason=u'%s: stage user not found' % stageduser.uid)):
            command()

    def test_find_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_find_command(uid=stageduser.uid)
        result = command()
        stageduser.check_find_nomatch(result)

    def test_activate_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_activate_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: stage user not found' % stageduser.uid)):
            command()


@pytest.mark.tier1
class TestStagedUser(XMLRPC_test):
    def test_create_duplicate(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'stage user with name "%s" already exists' %
                stageduser.uid)):
            command()

    def test_activate(self, stageduser3, user2):
        stageduser3.ensure_exists()
        user2.ensure_missing()
        user2 = UserTracker(
            stageduser3.uid, stageduser3.givenname, stageduser3.sn)
        user2.create_from_staged(stageduser3)
        command = stageduser3.make_activate_command()
        result = command()
        user2.check_activate(result)

        command = stageduser3.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: stage user not found' % stageduser3.uid)):
            command()
        user2.delete()

    def test_show_stageduser(self, stageduser):
        stageduser.retrieve()

    def test_showall_stageduser(self, stageduser):
        stageduser.retrieve(all=True)

    def test_create_attr(self, stageduser2, user, user6):
        """ Tests creating a user with various valid attributes listed
        in 'options_ok' list"""
        # create staged user with specified parameters
        user.ensure_exists()  # necessary for manager test
        stageduser2.ensure_missing()
        command = stageduser2.make_create_command()
        result = command()
        stageduser2.track_create()
        stageduser2.check_create(result)

        # activate user, verify that specified values were preserved
        # after activation
        user6.ensure_missing()
        user6 = UserTracker(
            stageduser2.uid, stageduser2.givenname,
            stageduser2.sn, **stageduser2.kwargs)
        user6.create_from_staged(stageduser2)
        command = stageduser2.make_activate_command()
        result = command()
        user6.check_activate(result)

        # verify the staged user does not exist after activation
        command = stageduser2.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: stage user not found' % stageduser2.uid)):
            command()

        user6.delete()

    def test_delete_stageduser(self, stageduser):
        stageduser.delete()

    def test_find_stageduser(self, stageduser):
        stageduser.find()

    def test_findall_stageduser(self, stageduser):
        stageduser.find(all=True)

    def test_update_stageduser(self, stageduser):
        stageduser.update(updates=dict(givenname=u'changed',),
                          expected_updates=dict(givenname=[u'changed'],))
        stageduser.retrieve()

    def test_update_uid(self, stageduser):
        stageduser.update(updates=dict(uidnumber=uid),
                          expected_updates=dict(uidnumber=[uid]))
        stageduser.retrieve()

    def test_update_gid(self, stageduser):
        stageduser.update(updates=dict(uidnumber=gid),
                          expected_updates=dict(uidnumber=[gid]))
        stageduser.retrieve()

    def test_update_uid_gid(self, stageduser):
        stageduser.update(updates=dict(uidnumber=uid, gidnumber=gid),
                          expected_updates=dict(
                              uidnumber=[uid], gidnumber=[gid]))
        stageduser.retrieve()


@pytest.mark.tier1
class TestCreateInvalidAttributes(XMLRPC_test):
    def test_create_invalid_uid(self):
        invalid = StageUserTracker(invaliduser1, u'invalid', u'user')
        command = invalid.make_create_command()
        with raises_exact(errors.ValidationError(
            name='login',
                error=u"may only include letters, numbers, _, -, . and $")):
            command()

    def test_create_long_uid(self):
        invalid = StageUserTracker(invaliduser2, u'invalid', u'user')
        command = invalid.make_create_command()
        with raises_exact(errors.ValidationError(
                name='login',
                error=u"can be at most 32 characters")):
            command()

    def test_create_uid_string(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={u'uidnumber': u'text'})
        with raises_exact(errors.ConversionError(
                message=u'invalid \'uid\': must be an integer')):
            command()

    def test_create_gid_string(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={u'gidnumber': u'text'})
        with raises_exact(errors.ConversionError(
                message=u'invalid \'gidnumber\': must be an integer')):
            command()

    def test_create_uid_negative(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={u'uidnumber': u'-123'})
        with raises_exact(errors.ValidationError(
                message=u'invalid \'uid\': must be at least 1')):
            command()

    def test_create_gid_negative(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={u'gidnumber': u'-123'})
        with raises_exact(errors.ValidationError(
                message=u'invalid \'gidnumber\': must be at least 1')):
            command()

    def test_create_krbprincipal_bad_realm(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={u'krbprincipalname': invalidrealm1})
        with raises_exact(errors.RealmMismatch(
                message=u'The realm for the principal does not match '
                'the realm for this IPA server')):
            command()

    def test_create_krbprincipal_malformed(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={u'krbprincipalname': invalidrealm2})
        with raises_exact(errors.MalformedUserPrincipal(
                message=u'Principal is not of the form user@REALM: \'%s\'' %
                invalidrealm2)):
            command()


@pytest.mark.tier1
class TestUpdateInvalidAttributes(XMLRPC_test):
    def test_update_uid_string(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={u'uidnumber': u'text'})
        with raises_exact(errors.ConversionError(
                message=u'invalid \'uid\': must be an integer')):
            command()

    def test_update_gid_string(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={u'gidnumber': u'text'})
        with raises_exact(errors.ConversionError(
                message=u'invalid \'gidnumber\': must be an integer')):
            command()

    def test_update_uid_negative(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={u'uidnumber': u'-123'})
        with raises_exact(errors.ValidationError(
                message=u'invalid \'uid\': must be at least 1')):
            command()

    def test_update_gid_negative(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={u'gidnumber': u'-123'})
        with raises_exact(errors.ValidationError(
                message=u'invalid \'gidnumber\': must be at least 1')):
            command()


@pytest.mark.tier1
class TestActive(XMLRPC_test):
    def test_delete(self, user):
        user.ensure_exists()
        user.track_delete()
        command = user.make_delete_command()
        result = command()
        user.check_delete(result)

    def test_delete_nopreserve(self, user):
        user.ensure_exists()
        user.track_delete()
        command = user.make_delete_command(no_preserve=True)
        result = command()
        user.check_delete(result)

    def test_delete_preserve_nopreserve(self, user):
        user.ensure_exists()
        command = user.make_delete_command(no_preserve=True, preserve=True)
        with raises_exact(errors.MutuallyExclusiveError(
                message=u'preserve and no-preserve cannot be both set')):
            command()

    def test_delete_preserve(self, user):
        user.ensure_exists()
        user.track_delete()
        command = user.make_delete_command(no_preserve=False, preserve=True)
        result = command()
        user.check_delete(result)

        command = user.make_delete_command()
        result = command()
        user.check_delete(result)

        command = user.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user.uid)):
            command()


@pytest.mark.tier1
class TestPreserved(XMLRPC_test):
    def test_search_preserved_invalid(self, user):
        user.make_preserved_user()

        command = user.make_find_command(uid=user.uid)
        result = command()
        user.check_find_nomatch(result)
        user.delete()

    def test_search_preserved_valid(self, user):
        user.make_preserved_user()

        command = user.make_find_command(
            uid=user.uid, preserved=True, all=False)
        result = command()
        user.check_find(result, all=False)
        user.delete()

    def test_search_preserved_valid_all(self, user):
        user.make_preserved_user()

        command = user.make_find_command(
            uid=user.uid, preserved=True, all=True)
        result = command()
        user.check_find(result, all=True)
        user.delete()

    def test_retrieve_preserved(self, user):
        user.make_preserved_user()

        command = user.make_retrieve_command()
        result = command()
        user.check_retrieve(result)
        user.delete()

    def test_permanently_delete_preserved_user(self, user):
        user.make_preserved_user()
        user.delete()

        command = user.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user.uid)):
            command()

    def test_enable_preserved(self, user):
        user.make_preserved_user()
        command = user.make_enable_command()
        with raises_exact(errors.MidairCollision(
                message=u'change collided with another change')):
            command()
        user.delete()

    def test_reactivate_preserved(self, user):
        user.make_preserved_user()

        command = user.make_retrieve_command(all=True)
        result = command()
        attr_check = {
            u'ipauniqueid': result[u'result'][u'ipauniqueid'],
            u'uidnumber': result[u'result'][u'uidnumber'],
            u'gidnumber': result[u'result'][u'gidnumber']
            }

        command = user.make_undelete_command()
        result = command()
        user.check_undel(result)
        user.check_attr_preservation(attr_check)

        user.delete()

    def test_staged_from_preserved(self, user7, stageduser):
        user7.make_preserved_user()

        stageduser.ensure_missing()
        stageduser = StageUserTracker(user7.uid, user7.givenname, user7.sn)
        stageduser.create_from_preserved(user7)
        command = user7.make_stage_command()
        result = command()
        stageduser.check_restore_preserved(result)
        stageduser.exists = True

        command = user7.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % stageduser.uid)):
            command()

        command = stageduser.make_retrieve_command()
        result = command()
        stageduser.check_retrieve(result)

        stageduser.delete()


@pytest.mark.tier1
class TestManagers(XMLRPC_test):
    def test_staged_manager(self, user, stageduser):
        user.ensure_exists()
        stageduser.ensure_exists()

        command = user.make_update_command(
            updates=dict(manager=stageduser.uid))
        with raises_exact(errors.NotFound(
                reason=u'manager %s not found' % stageduser.uid)):
            command()
        user.delete()
        stageduser.delete()

    def test_preserved_manager(self, user, user3):
        user.ensure_exists()
        user3.make_preserved_user()

        command = user.make_update_command(updates=dict(manager=user3.uid))
        with raises_exact(errors.NotFound(
                reason=u'manager %s not found' % user3.uid)):
            command()

        user3.delete()

    def test_delete_manager_preserved(self, user, user3):
        user3.ensure_exists()

        user.update(
            updates=dict(manager=user3.uid),
            expected_updates=dict(manager=[user3.uid], nsaccountlock=False))

        user3.make_preserved_user()
        del user.attrs[u'manager']

        command = user.make_retrieve_command(all=True)
        result = command()
        user.check_retrieve(result, all=True)

        # verify whether user has a manager attribute
        if u'manager' in result['result']:
            assert False


@pytest.mark.tier1
class TestDuplicates(XMLRPC_test):
    def test_active_same_as_preserved(self, user4, user5):
        user4.ensure_missing()
        user5.make_preserved_user()
        command = user4.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'user with name "%s" already exists' % user4.uid)):
            command()
        user5.delete()

    def test_staged_same_as_active(self, user4, stageduser4):
        user4.ensure_exists()
        stageduser4.create()  # can be created

        command = stageduser4.make_activate_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'active user with name "%s" already exists' %
                user4.uid)):
            command()  # cannot be activated

        user4.delete()
        stageduser4.delete()

    def test_staged_same_as_preserved(self, user5, stageduser4):
        user5.make_preserved_user()
        stageduser4.create()  # can be created

        command = stageduser4.make_activate_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'This entry already exists')):
            command()  # cannot be activated

        user5.delete()
        stageduser4.delete()

    def test_active_same_as_staged(self, user4, stageduser4):
        user4.ensure_missing()
        stageduser4.ensure_exists()
        command = user4.make_create_command()
        result = command()
        user4.track_create()
        user4.check_create(result)  # can be created

        command = stageduser4.make_activate_command()
        with raises_exact(errors.DuplicateEntry(
                message=u'active user with name "%s" already exists' %
                user4.uid)):
            command()  # cannot be activated


@pytest.fixture(scope='class')
def group(request):
    tracker = GroupTracker(u'testgroup')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestGroups(XMLRPC_test):
    def test_stageduser_membership(self, stageduser, group):
        stageduser.ensure_exists()
        group.ensure_exists()
        command = group.make_add_member_command(
            options={u'user': stageduser.uid})
        result = command()
        group.check_add_member_negative(result)

    def test_remove_preserved_from_group(self, user, group):
        user.ensure_exists()
        group.ensure_exists()
        command = group.make_add_member_command(options={u'user': user.uid})
        result = command()
        group.check_add_member(result)

        command = group.make_retrieve_command()
        result = command()
        group.check_retrieve(result)

        command = user.make_delete_command(no_preserve=False, preserve=True)
        result = command()
        user.check_delete(result)

        command = group.make_retrieve_command()
        result = command()

        if (u'member_user' in result[u'result'] and
                user.uid in result['result']['member_user']):
            assert False

        user.delete()
        group.delete()

    def test_preserveduser_membership(self, user, group):
        user.make_preserved_user()
        group.ensure_exists()
        command = group.make_add_member_command(options={u'user': user.uid})
        result = command()
        group.check_add_member_negative(result)
