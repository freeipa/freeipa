#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipaserver/plugins/stageuser.py` module.
"""

import pytest

from collections import OrderedDict
from ipalib import api, errors
from ipalib.constants import ERRMSG_GROUPUSER_NAME
from ipaplatform.constants import constants as platformconstants

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact

from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.group_plugin import GroupTracker
from ipatests.test_xmlrpc.tracker.stageuser_plugin import StageUserTracker

try:
    from ipaserver.plugins.ldap2 import ldap2
except ImportError:
    have_ldap2 = False
else:
    have_ldap2 = True

validuser1 = 'tuser1'
validuser2 = 'tuser2'

uid = '123'
gid = '456'
invalidrealm1 = 'suser1@NOTFOUND.ORG'
invalidrealm2 = 'suser1@BAD@NOTFOUND.ORG'

nonexistentidp = 'IdPDoesNotExist'

invaliduser1 = '+tuser1'
invaliduser2 = 'tuser1234567890123456789012345678901234567890'
invaliduser3 = '1234'

sshpubkey = ('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
             'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
             'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
             'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
             'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
             '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
             '0L public key test')
sshpubkeyfp = ('SHA256:cStA9o5TRSARbeketEOooMUMSWRSsArIAXloBZ4vNsE '
               'public key test (ssh-rsa)')

options_def = OrderedDict([
    ('full name', {'cn': 'name'}),
    ('initials', {'initials': 'in'}),
    ('display name', {'displayname': 'display'}),
    ('home directory', {'homedirectory': '/home/homedir'}),
    ('GECOS', {'gecos': 'gecos'}),
    ('shell', {'loginshell': platformconstants.DEFAULT_SHELL}),
    ('email address', {'mail': 'email@email.email'}),
    ('job title', {'title': 'newbie'}),
    ('kerberos principal', {
        'krbprincipalname': 'kerberos@%s' % api.env.realm}),
    ('uppercase kerberos principal', {
        'krbprincipalname': 'KERBEROS@%s' % api.env.realm}),
    ('street address', {'street': 'first street'}),
    ('city', {'l': 'prague'}),
    ('state', {'st': 'czech'}),
    ('zip code', {'postalcode': '12345'}),
    ('telephone number', {'telephonenumber': '123456789'}),
    ('fax number', {'facsimiletelephonenumber': '123456789'}),
    ('mobile tel. number', {'mobile': '123456789'}),
    ('pager number', {'pager': '123456789'}),
    ('organizational unit', {'ou': 'engineering'}),
    ('car license', {'carlicense': 'abc1234'}),
    ('SSH key', {'ipasshpubkey': sshpubkey}),
    ('manager', {'manager': 'auser1'}),
    ('group ID number', {'gidnumber': gid}),
    ('password', {'userpassword': 'Secret123'}),
    ('random password', {'random': True}),
    ])

options_ok = list(options_def.values())
options_ids = list(options_def.keys())

warn_options_def = OrderedDict([
    ('user ID number', {'uidnumber': uid}),
    ('UID and GID numbers', {'uidnumber': uid, 'gidnumber': gid}),
])

warn_options_ok = list(warn_options_def.values())
warn_options_ids = list(warn_options_def.keys())

@pytest.fixture(scope='class')
def stageduser(request, xmlrpc_setup):
    tracker = StageUserTracker(name='suser1', givenname='staged', sn='user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def stageduser_min(request, xmlrpc_setup):
    tracker = StageUserTracker(givenname='stagedmin', sn='usermin')
    return tracker.make_fixture(request)

@pytest.fixture(scope='class', params=options_ok, ids=options_ids)
def stageduser2(request, xmlrpc_setup):
    tracker = StageUserTracker('suser2', 'staged', 'user', **request.param)
    return tracker.make_fixture_activate(request)


@pytest.fixture(scope='class', params=warn_options_ok, ids=warn_options_ids)
def warn_stageduser(request, xmlrpc_setup):
    tracker = StageUserTracker('warnuser', 'staged', 'user', **request.param)
    return tracker.make_fixture_activate(request)


@pytest.fixture(scope='class')
def user_activated(request, xmlrpc_setup):
    tracker = UserTracker('suser2', 'staged', 'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def stageduser3(request, xmlrpc_setup):
    tracker = StageUserTracker(name='suser3', givenname='staged', sn='user')
    return tracker.make_fixture_activate(request)


@pytest.fixture(scope='class')
def stageduser_notposix(request, xmlrpc_setup):
    tracker = StageUserTracker('notposix', 'notposix', 'notposix')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def stageduser_customattr(request, xmlrpc_setup):
    tracker = StageUserTracker('customattr', 'customattr', 'customattr',
                               setattr='businesscategory=BusinessCat')
    tracker.track_create()
    tracker.attrs.update(
        businesscategory=['BusinessCat']
    )
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user(request, xmlrpc_setup):
    tracker = UserTracker('auser1', 'active', 'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user2(request, xmlrpc_setup):
    tracker = UserTracker('suser3', 'staged', 'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user3(request, xmlrpc_setup):
    tracker = UserTracker('auser2', 'active', 'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user6(request, xmlrpc_setup):
    tracker = UserTracker('suser2', 'staged', 'user')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user7(request, xmlrpc_setup):
    tracker = UserTracker('puser1', 'preserved', 'user')
    return tracker.make_fixture_restore(request)


@pytest.mark.tier1
class TestNonexistentStagedUser(XMLRPC_test):
    def test_retrieve_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason='%s: stage user not found' % stageduser.uid)):
            command()

    def test_delete_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_delete_command()
        with raises_exact(errors.NotFound(
                reason='%s: stage user not found' % stageduser.uid)):
            command()

    def test_update_nonexistent(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_update_command(
            updates=dict(givenname='changed'))
        with raises_exact(errors.NotFound(
                reason='%s: stage user not found' % stageduser.uid)):
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
                reason='%s: stage user not found' % stageduser.uid)):
            command()


@pytest.mark.tier1
class TestStagedUser(XMLRPC_test):
    def test_create_with_min_values(self, stageduser_min):
        """ Create user with uid not specified """
        stageduser_min.ensure_missing()
        command = stageduser_min.make_create_command()
        command()

    def test_create_duplicate(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message='stage user with name "%s" already exists' %
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
                reason='%s: stage user not found' % stageduser3.uid)):
            command()
        user2.delete()

    def test_show_stageduser(self, stageduser):
        stageduser.retrieve()

    def test_showall_stageduser(self, stageduser):
        stageduser.retrieve(all=True)

    def test_create_with_attr(self, stageduser2, user, user_activated):
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
        user_activated.ensure_missing()
        user_activated = UserTracker(
            stageduser2.uid, stageduser2.givenname,
            stageduser2.sn, **stageduser2.kwargs)
        user_activated.create_from_staged(stageduser2)
        command = stageduser2.make_activate_command()
        result = command()
        user_activated.check_activate(result)

        # verify the staged user does not exist after activation
        command = stageduser2.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason='%s: stage user not found' % stageduser2.uid)):
            command()

        user_activated.delete()

    def test_warn_create_with_attr(self, warn_stageduser, user, user_activated):
        """ Tests creating a user with various valid attributes that throw
        a warning listed in 'warn_options_ok' list"""
        # create staged user with specified parameters
        user.ensure_exists()  # necessary for manager test
        warn_stageduser.ensure_missing()
        command = warn_stageduser.make_create_command()
        result = command()
        warn_stageduser.track_create()
        warn_stageduser.check_create_with_warning(result, (13034,))

        # activate user, verify that specified values were preserved
        # after activation
        user_activated.ensure_missing()
        user_activated = UserTracker(
            warn_stageduser.uid, warn_stageduser.givenname,
            warn_stageduser.sn, **warn_stageduser.kwargs)
        user_activated.create_from_staged(warn_stageduser)
        command = warn_stageduser.make_activate_command()
        result = command()
        user_activated.check_activate(result)

        # verify the staged user does not exist after activation
        command = warn_stageduser.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason='%s: stage user not found' % warn_stageduser.uid)):
            command()

        user_activated.delete()

    def test_delete_stageduser(self, stageduser):
        stageduser.delete()

    def test_find_stageduser(self, stageduser):
        stageduser.ensure_exists()
        stageduser.find()

    def test_findall_stageduser(self, stageduser):
        stageduser.find(all=True)

    def test_update_stageduser(self, stageduser):
        stageduser.update(updates=dict(givenname='changed',),
                          expected_updates=dict(givenname=['changed'],))
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

    def test_without_posixaccount(self, stageduser_notposix):
        """Test stageuser-find when the staged user is not a posixaccount.
        """
        stageduser_notposix.ensure_missing()

        # Directly create the user using ldapmod
        # without the posixaccount objectclass
        if not have_ldap2:
            pytest.skip('server plugin not available')
        ldap = ldap2(api)
        ldap.connect()
        ldap.create(
            dn=stageduser_notposix.dn,
            objectclass=['inetorgperson', 'organizationalperson', 'person'],
            uid=stageduser_notposix.uid,
            sn=stageduser_notposix.sn,
            givenname=stageduser_notposix.givenname,
            cn=stageduser_notposix.uid
        )
        # Check that stageuser-find correctly finds the user
        command = stageduser_notposix.make_find_command(
            uid=stageduser_notposix.uid)
        result = command()
        assert result['count'] == 1

    def test_create_withuserauthtype(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'ipauserauthtype': 'password'})
        command()


@pytest.mark.tier1
class TestCreateInvalidAttributes(XMLRPC_test):
    def test_create_invalid_uid(self):
        invalid = StageUserTracker(invaliduser1, 'invalid', 'user')
        command = invalid.make_create_command()
        with raises_exact(errors.ValidationError(
            name='login',
            error=ERRMSG_GROUPUSER_NAME.format('user'),
        )):
            command()

    def test_create_numeric_only_uid(self):
        invalid = StageUserTracker(invaliduser3, 'NumFirst1234',
                                   'NumSurname1234')
        command = invalid.make_create_command()
        with raises_exact(errors.ValidationError(
            name='login',
            error=ERRMSG_GROUPUSER_NAME.format('user'),
        )):
            command()

    def test_create_long_uid(self):
        invalid = StageUserTracker(invaliduser2, 'invalid', 'user')
        command = invalid.make_create_command()
        with raises_exact(errors.ValidationError(
                name='login',
                error="can be at most 32 characters")):
            command()

    def test_create_uid_string(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'uidnumber': 'text'})
        with raises_exact(errors.ConversionError(
                message='invalid \'uid\': must be an integer')):
            command()

    def test_create_gid_string(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'gidnumber': 'text'})
        with raises_exact(errors.ConversionError(
                message='invalid \'gidnumber\': must be an integer')):
            command()

    def test_create_uid_negative(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'uidnumber': '-123'})
        with raises_exact(errors.ValidationError(
                message='invalid \'uid\': must be at least 1')):
            command()

    def test_create_gid_negative(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'gidnumber': '-123'})
        with raises_exact(errors.ValidationError(
                message='invalid \'gidnumber\': must be at least 1')):
            command()

    def test_create_krbprincipal_bad_realm(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'krbprincipalname': invalidrealm1})
        with raises_exact(errors.RealmMismatch(
                message='The realm for the principal does not match '
                'the realm for this IPA server')):
            command()

    def test_create_krbprincipal_malformed(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'krbprincipalname': invalidrealm2})
        with raises_exact(errors.ConversionError(
                name='principal', error="Malformed principal: '{}'".format(
                    invalidrealm2))):
            command()

    def test_create_invalid_idp(self, stageduser):
        stageduser.ensure_missing()
        command = stageduser.make_create_command(
            options={'ipaidpconfiglink': nonexistentidp})
        with raises_exact(errors.NotFound(
                reason="External IdP configuration {} not found".format(
                    nonexistentidp))):
            command()


@pytest.mark.tier1
class TestUpdateInvalidAttributes(XMLRPC_test):
    def test_update_uid_string(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={'uidnumber': 'text'})
        with raises_exact(errors.ConversionError(
                message='invalid \'uid\': must be an integer')):
            command()

    def test_update_gid_string(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={'gidnumber': 'text'})
        with raises_exact(errors.ConversionError(
                message='invalid \'gidnumber\': must be an integer')):
            command()

    def test_update_uid_negative(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={'uidnumber': '-123'})
        with raises_exact(errors.ValidationError(
                message='invalid \'uid\': must be at least 1')):
            command()

    def test_update_gid_negative(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={'gidnumber': '-123'})
        with raises_exact(errors.ValidationError(
                message='invalid \'gidnumber\': must be at least 1')):
            command()

    def test_update_invalididp(self, stageduser):
        stageduser.ensure_exists()
        command = stageduser.make_update_command(
            updates={'ipaidpconfiglink': nonexistentidp})
        with raises_exact(errors.NotFound(
                reason="External IdP configuration {} not found".format(
                    nonexistentidp))):
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
                message='preserve and no-preserve cannot be both set')):
            command()

    def test_delete_preserve(self, user):
        user.ensure_exists()
        user.track_delete(preserve=True)
        command = user.make_delete_command(no_preserve=False, preserve=True)
        result = command()
        user.check_delete(result)

        user.track_delete(preserve=False)
        command = user.make_delete_command()
        result = command()
        user.check_delete(result)

        command = user.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason='%s: user not found' % user.uid)):
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
        user.check_find(result, all=False,
                        expected_override=dict(preserved=True))
        user.delete()

    def test_search_preserved_valid_all(self, user):
        user.make_preserved_user()

        command = user.make_find_command(
            uid=user.uid, preserved=True, all=True)
        result = command()
        user.check_find(result, all=True,
                        expected_override=dict(preserved=True))
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
                reason='%s: user not found' % user.uid)):
            command()

    def test_enable_preserved(self, user):
        user.make_preserved_user()
        command = user.make_enable_command()
        with raises_exact(errors.MidairCollision(
                message='change collided with another change')):
            command()
        user.delete()

    def test_reactivate_preserved(self, user):
        user.make_preserved_user()

        command = user.make_retrieve_command(all=True)
        result = command()
        attr_check = {
            'ipauniqueid': result['result']['ipauniqueid'],
            'uidnumber': result['result']['uidnumber'],
            'gidnumber': result['result']['gidnumber']
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
                reason='%s: user not found' % stageduser.uid)):
            command()

        command = stageduser.make_retrieve_command()
        result = command()
        stageduser.check_retrieve(result)

        stageduser.delete()


@pytest.mark.tier1
class TestCustomAttr(XMLRPC_test):
    """Test for pagure ticket 7597

    When a staged user is activated, preserved and finally staged again,
    the custom attributes are lost.
    """
    def test_stageduser_customattr(self, stageduser_customattr):
        # Create a staged user with attributes not accessible
        # through the options
        # --setattr is needed here
        command = stageduser_customattr.make_create_command()
        result = command()
        stageduser_customattr.check_create(result, ['businesscategory'])

        # Activate the staged user
        user_customattr = UserTracker(
            stageduser_customattr.uid, stageduser_customattr.givenname,
            stageduser_customattr.sn)
        user_customattr.create_from_staged(stageduser_customattr)
        user_customattr.attrs['businesscategory'] = ['BusinessCat']

        command = stageduser_customattr.make_activate_command()
        result = command()
        user_customattr.check_activate(result)

        # Check that the user contains businesscategory
        command = user_customattr.make_retrieve_command(all=True)
        result = command()
        assert 'BusinessCat' in result['result']['businesscategory']

        # delete the user with --preserve
        user_customattr.track_delete(preserve=True)
        command = user_customattr.make_delete_command(no_preserve=False,
                                                      preserve=True)
        result = command()
        user_customattr.check_delete(result)

        # Check that the preserved user contains businesscategory
        command = user_customattr.make_retrieve_command(all=True)
        result = command()
        assert 'BusinessCat' in result['result']['businesscategory']

        # Move the user from preserved to stage
        command = user_customattr.make_stage_command()
        result = command()
        stageduser_customattr.check_restore_preserved(result)

        # Check that the stage user contains businesscategory
        command = stageduser_customattr.make_retrieve_command(all=True)
        result = command()
        assert 'BusinessCat' in result['result']['businesscategory']


@pytest.mark.tier1
class TestManagers(XMLRPC_test):
    def test_staged_manager(self, user, stageduser):
        user.ensure_exists()
        stageduser.ensure_exists()

        command = user.make_update_command(
            updates=dict(manager=stageduser.uid))
        with raises_exact(errors.NotFound(
                reason='manager %s not found' % stageduser.uid)):
            command()
        user.delete()
        stageduser.delete()

    def test_preserved_manager(self, user, user3):
        user.ensure_exists()
        user3.make_preserved_user()

        command = user.make_update_command(updates=dict(manager=user3.uid))
        with raises_exact(errors.NotFound(
                reason='manager %s not found' % user3.uid)):
            command()

        user3.delete()

    def test_delete_manager_preserved(self, user, user3):
        user3.ensure_exists()

        user.update(
            updates=dict(manager=user3.uid),
            expected_updates=dict(manager=[user3.uid], nsaccountlock=False))

        user3.make_preserved_user()
        del user.attrs['manager']

        command = user.make_retrieve_command(all=True)
        result = command()
        user.check_retrieve(result, all=True)

        # verify whether user has a manager attribute
        if 'manager' in result['result']:
            assert False


@pytest.mark.tier1
class TestDuplicates(XMLRPC_test):
    @pytest.fixture
    def user(self, request, xmlrpc_setup):
        tracker = UserTracker("tuser", "test", "user")
        return tracker.make_fixture(request)

    @pytest.fixture
    def stageduser(self, request, xmlrpc_setup):
        tracker = StageUserTracker("tuser", "test", "user")
        return tracker.make_fixture(request)

    def test_active_same_as_preserved(self, user):
        user.make_preserved_user()
        command = user.make_create_command()
        with raises_exact(errors.DuplicateEntry(
                message='user with name "%s" already exists' % user.uid)):
            command()

    def test_staged_same_as_active(self, user, stageduser):
        user.create()
        stageduser.create()  # can be created

        command = stageduser.make_activate_command()
        with raises_exact(errors.DuplicateEntry(
                message='active user with name "%s" already exists' %
                user.uid)):
            command()  # cannot be activated

    def test_staged_same_as_preserved(self, user, stageduser):
        user.make_preserved_user()
        stageduser.create()  # can be created

        command = stageduser.make_activate_command()
        with raises_exact(errors.DuplicateEntry(
                message='This entry already exists')):
            command()  # cannot be activated

    def test_active_same_as_staged(self, user, stageduser):
        stageduser.create()
        user.create()  # can be created

        command = stageduser.make_activate_command()
        with raises_exact(errors.DuplicateEntry(
                message='active user with name "%s" already exists' %
                user.uid)):
            command()  # cannot be activated


@pytest.fixture(scope='class')
def group(request, xmlrpc_setup):
    tracker = GroupTracker('testgroup')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestGroups(XMLRPC_test):
    def test_stageduser_membership(self, stageduser, group):
        stageduser.ensure_exists()
        group.ensure_exists()
        command = group.make_add_member_command(
            options={'user': stageduser.uid})
        result = command()
        group.check_add_member_negative(result)

    def test_remove_preserved_from_group(self, user, group):
        user.ensure_exists()
        group.ensure_exists()
        command = group.add_member(options={'user': user.uid})

        command = group.make_retrieve_command()
        result = command()
        group.check_retrieve(result)

        user.track_delete(preserve=True)
        command = user.make_delete_command(no_preserve=False, preserve=True)
        result = command()
        user.check_delete(result)

        command = group.make_retrieve_command()
        result = command()

        if ('member_user' in result['result'] and
                user.uid in result['result']['member_user']):
            assert False

        user.delete()
        group.delete()

    def test_preserveduser_membership(self, user, group):
        user.make_preserved_user()
        group.ensure_exists()
        command = group.make_add_member_command(options={'user': user.uid})
        result = command()
        group.check_add_member_negative(result)
