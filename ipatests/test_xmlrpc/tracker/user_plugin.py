#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import api, errors
from ipapython.dn import DN

from ipatests.util import assert_deepequal, get_group_dn
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_digits, fuzzy_uuid, raises_exact
from ipatests.test_xmlrpc.tracker.base import Tracker


class UserTracker(Tracker):
    """ Class for host plugin like tests """

    retrieve_keys = {
        u'uid', u'givenname', u'sn', u'homedirectory',
        u'loginshell', u'uidnumber', u'gidnumber', u'mail', u'ou',
        u'telephonenumber', u'title', u'memberof',
        u'memberofindirect', u'ipauserauthtype', u'userclass',
        u'ipatokenradiusconfiglink', u'ipatokenradiususername',
        u'krbprincipalexpiration', u'usercertificate', u'dn', u'has_keytab',
        u'has_password', u'street', u'postalcode', u'facsimiletelephonenumber',
        u'carlicense', u'ipasshpubkey', u'sshpubkeyfp', u'nsaccountlock',
        u'preserved', u'memberof_group', u'l', u'mobile', u'krbextradata',
        u'krblastpwdchange', u'krbpasswordexpiration', u'pager', u'st'
        }

    retrieve_all_keys = retrieve_keys | {
        u'cn', u'ipauniqueid', u'objectclass', u'mepmanagedentry',
        u'displayname', u'gecos', u'initials', u'krbprincipalname', u'manager'}

    retrieve_preserved_keys = retrieve_keys - {u'memberof_group'}
    retrieve_preserved_all_keys = retrieve_all_keys - {u'memberof_group'}

    create_keys = retrieve_all_keys | {
        u'randompassword', u'mepmanagedentry',
        u'krbextradata', u'krbpasswordexpiration', u'krblastpwdchange',
        u'krbprincipalkey', u'randompassword', u'userpassword'
        }
    update_keys = retrieve_keys - {u'dn'}
    activate_keys = retrieve_all_keys - {u'has_keytab', u'has_password',
                                         u'nsaccountlock', u'sshpubkeyfp'}

    find_keys = retrieve_keys - {u'mepmanagedentry', u'memberof_group'}
    find_all_keys = retrieve_all_keys - {u'mepmanagedentry', u'memberof_group'}

    def __init__(self, name, givenname, sn, **kwargs):
        super(UserTracker, self).__init__(default_version=None)
        self.uid = name
        self.givenname = givenname
        self.sn = sn
        self.dn = DN(('uid', self.uid), api.env.container_user, api.env.basedn)

        self.kwargs = kwargs

    def make_create_command(self, force=None):
        """ Make function that crates a user using user-add """
        return self.make_command(
            'user_add', self.uid,
            givenname=self.givenname,
            sn=self.sn, **self.kwargs
            )

    def make_delete_command(self, no_preserve=True, preserve=False):
        """ Make function that deletes a user using user-del """

        if preserve and not no_preserve:
            # necessary to change some user attributes due to moving
            # to different container
            self.attrs[u'dn'] = DN(
                ('uid', self.uid),
                api.env.container_deleteuser,
                api.env.basedn
                )
            self.attrs[u'objectclass'] = objectclasses.user_base

        return self.make_command(
            'user_del', self.uid,
            no_preserve=no_preserve,
            preserve=preserve
            )

    def make_retrieve_command(self, all=False, raw=False):
        """ Make function that retrieves a user using user-show """
        return self.make_command('user_show', self.uid, all=all)

    def make_find_command(self, *args, **kwargs):
        """ Make function that finds user using user-find """
        return self.make_command('user_find', *args, **kwargs)

    def make_update_command(self, updates):
        """ Make function that updates user using user-mod """
        return self.make_command('user_mod', self.uid, **updates)

    def make_undelete_command(self):
        """ Make function that activates preserved user using user-undel """
        return self.make_command('user_undel', self.uid)

    def make_enable_command(self):
        """ Make function that enables user using user-enable """
        return self.make_command('user_enable', self.uid)

    def make_stage_command(self):
        """ Make function that restores preserved user by moving it to
        staged container """
        return self.make_command('user_stage', self.uid)

    def track_create(self):
        """ Update expected state for user creation """
        self.attrs = dict(
            dn=self.dn,
            uid=[self.uid],
            givenname=[self.givenname],
            sn=[self.sn],
            homedirectory=[u'/home/%s' % self.uid],
            displayname=[u'%s %s' % (self.givenname, self.sn)],
            cn=[u'%s %s' % (self.givenname, self.sn)],
            initials=[u'%s%s' % (self.givenname[0], self.sn[0])],
            objectclass=objectclasses.user,
            description=[u'__no_upg__'],
            ipauniqueid=[fuzzy_uuid],
            uidnumber=[fuzzy_digits],
            gidnumber=[fuzzy_digits],
            krbprincipalname=[u'%s@%s' % (self.uid, self.api.env.realm)],
            mail=[u'%s@%s' % (self.uid, self.api.env.domain)],
            gecos=[u'%s %s' % (self.givenname, self.sn)],
            loginshell=[u'/bin/sh'],
            has_keytab=False,
            has_password=False,
            mepmanagedentry=[get_group_dn(self.uid)],
            memberof_group=[u'ipausers'],
            )

        for key in self.kwargs:
            if key == u'krbprincipalname':
                self.attrs[key] = [u'%s@%s' % (
                    (self.kwargs[key].split('@'))[0].lower(),
                    (self.kwargs[key].split('@'))[1]
                    )]
            else:
                self.attrs[key] = [self.kwargs[key]]

        self.exists = True

    def check_create(self, result):
        """ Check 'user-add' command result """
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Added user "%s"' % self.uid,
            result=self.filter_attrs(self.create_keys),
            ), result)

    def check_delete(self, result):
        """ Check 'user-del' command result """
        assert_deepequal(dict(
            value=[self.uid],
            summary=u'Deleted user "%s"' % self.uid,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False):
        """ Check 'user-show' command result """

        if u'preserved' in self.attrs and self.attrs[u'preserved']:
            self.retrieve_all_keys = self.retrieve_preserved_all_keys
            self.retrieve_keys = self.retrieve_preserved_keys
        elif u'preserved' not in self.attrs and all:
            self.attrs[u'preserved'] = False

        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        # small override because stageuser-find returns different type
        # of nsaccountlock value than DS, but overall the value fits
        # expected result
        if u'nsaccountlock' in expected:
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
        """ Check 'user-find' command result """
        self.attrs[u'nsaccountlock'] = True
        self.attrs[u'preserved'] = True

        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 user matched',
            result=[expected],
        ), result)

    def check_find_nomatch(self, result):
        """ Check 'user-find' command result when no user should be found """
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 users matched',
            result=[],
        ), result)

    def check_update(self, result, extra_keys=()):
        """ Check 'user-mod' command result """
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Modified user "%s"' % self.uid,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def create_from_staged(self, stageduser):
        """ Copies attributes from staged user - helper function for
        activation tests """
        self.attrs = stageduser.attrs
        self.uid = stageduser.uid
        self.givenname = stageduser.givenname
        self.sn = stageduser.sn

        self.attrs[u'mepmanagedentry'] = None
        self.attrs[u'dn'] = self.dn
        self.attrs[u'ipauniqueid'] = [fuzzy_uuid]
        self.attrs[u'memberof'] = [u'cn=ipausers,%s,%s' % (
            api.env.container_group, api.env.basedn
            )]
        self.attrs[u'mepmanagedentry'] = [u'cn=%s,%s,%s' % (
            self.uid, api.env.container_group, api.env.basedn
            )]
        self.attrs[u'objectclass'] = objectclasses.user
        if self.attrs[u'gidnumber'] == [u'-1']:
            self.attrs[u'gidnumber'] = [fuzzy_digits]
        if self.attrs[u'uidnumber'] == [u'-1']:
            self.attrs[u'uidnumber'] = [fuzzy_digits]

        if u'ipasshpubkey' in self.kwargs:
                self.attrs[u'ipasshpubkey'] = [str(
                    self.kwargs[u'ipasshpubkey']
                    )]

    def check_activate(self, result):
        """ Check 'stageuser-activate' command result """
        expected = dict(
            value=self.uid,
            summary=u'Stage user %s activated' % self.uid,
            result=self.filter_attrs(self.activate_keys))

        # work around to eliminate inconsistency in returned objectclass
        # (case sensitive assertion)
        expected['result']['objectclass'] = [item.lower() for item in
                                             expected['result']['objectclass']]
        result['result']['objectclass'] = [item.lower() for item in
                                           result['result']['objectclass']]

        assert_deepequal(expected, result)

        self.exists = True

    def check_undel(self, result):
        """ Check 'user-undel' command result """
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Undeleted user account "%s"' % self.uid,
            result=True
            ), result)

    def track_delete(self, preserve=False):
        """Update expected state for host deletion"""
        if preserve:
            self.exists = True
            if u'memberof_group' in self.attrs:
                del self.attrs[u'memberof_group']
            self.attrs[u'nsaccountlock'] = True
            self.attrs[u'preserved'] = True
        else:
            self.exists = False
            self.attrs = {}

    def make_preserved_user(self):
        """ 'Creates' a preserved user necessary for some tests """
        self.ensure_exists()
        self.track_delete(preserve=True)
        command = self.make_delete_command(no_preserve=False, preserve=True)
        result = command()
        self.check_delete(result)

    def check_attr_preservation(self, expected):
        """ Verifies that ipaUniqueID, uidNumber and gidNumber are
        preserved upon reactivation. Also verifies that resulting
        active user is a member of ipausers group only."""
        command = self.make_retrieve_command(all=True)
        result = command()

        assert_deepequal(dict(
            ipauniqueid=result[u'result'][u'ipauniqueid'],
            uidnumber=result[u'result'][u'uidnumber'],
            gidnumber=result[u'result'][u'gidnumber']
            ), expected)

        if (u'memberof_group' not in result[u'result'] or
                result[u'result'][u'memberof_group'] != (u'ipausers',)):
            assert False

    def make_fixture_restore(self, request):
        """Make a pytest fixture for a preserved user that is to be moved to
        staged area.

        The fixture ensures the plugin entry does not exist before
        and after the tests that use it. It takes into account
        that the preserved user no longer exists after restoring it,
        therefore the fixture verifies after the tests
        that the preserved user doesn't exist instead of deleting it.
        """
        del_command = self.make_delete_command()
        try:
            del_command()
        except errors.NotFound:
            pass

        def finish():
            with raises_exact(errors.NotFound(
                    reason=u'%s: user not found' % self.uid)):
                del_command()

        request.addfinalizer(finish)

        return self
