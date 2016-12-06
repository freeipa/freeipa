#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import api, errors
from ipapython.dn import DN

import six

from ipatests.util import assert_deepequal, get_group_dn
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    fuzzy_digits, fuzzy_uuid, raises_exact)
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.kerberos_aliases import KerberosAliasMixin

if six.PY3:
    unicode = str


class UserTracker(KerberosAliasMixin, Tracker):
    """ Class for host plugin like tests """

    retrieve_keys = {
        u'dn', u'uid', u'givenname', u'sn', u'homedirectory', u'loginshell',
        u'uidnumber', u'gidnumber', u'mail', u'ou',
        u'telephonenumber', u'title', u'memberof', u'nsaccountlock',
        u'memberofindirect', u'ipauserauthtype', u'userclass',
        u'ipatokenradiusconfiglink', u'ipatokenradiususername',
        u'krbprincipalexpiration', u'usercertificate;binary',
        u'has_keytab', u'has_password', u'memberof_group', u'sshpubkeyfp',
        u'krbcanonicalname', 'krbprincipalname'
    }

    retrieve_all_keys = retrieve_keys | {
        u'usercertificate', u'street', u'postalcode',
        u'facsimiletelephonenumber', u'carlicense', u'ipasshpubkey',
        u'l', u'mobile', u'krbextradata', u'krblastpwdchange',
        u'krbpasswordexpiration', u'pager', u'st', u'manager', u'cn',
        u'ipauniqueid', u'objectclass', u'mepmanagedentry',
        u'displayname', u'gecos', u'initials', u'preserved'}
    retrieve_cli_keys = retrieve_keys - {'dn'}

    retrieve_preserved_keys = (retrieve_keys - {u'memberof_group'}) | {
        u'preserved'}
    retrieve_preserved_all_keys = retrieve_all_keys - {u'memberof_group'}
    retrieve_preserved_cli_keys = retrieve_cli_keys | {u'preserved'}

    create_keys = retrieve_all_keys | {
        u'krbextradata', u'krbpasswordexpiration', u'krblastpwdchange',
        u'krbprincipalkey', u'userpassword', u'randompassword'}
    create_keys = create_keys - {u'nsaccountlock'}
    create_cli_keys = create_keys - {
        u'dn', u'ipauniqueid', u'mepmanagedentry',
        u'objectclass'}

    update_keys = retrieve_keys - {u'dn'}
    activate_keys = retrieve_keys
    activate_cli_keys = activate_keys - {u'dn', u'nsaccountlock'}

    find_keys = retrieve_keys - {
        u'mepmanagedentry', u'memberof_group', u'has_keytab', u'has_password',
        u'manager',
    }
    find_all_keys = retrieve_all_keys - {
        u'has_keytab', u'has_password'
    }
    find_cli_keys = find_keys - {u'dn'}

    primary_keys = {u'uid', u'dn'}

    mapping_options_user = {
        'carlicense': 'carlicense',
        'cn': 'cn',
        'continue': 'continue',
        'departmentnumber': 'departmentnumber',
        'displayname': 'displayname',
        'employeenumber': 'employeenumber',
        'employeetype': 'employeetype',
        'facsimiletelephonenumber': 'fax',
        'gecos': 'gecos',
        'gidnumber': 'gidnumber',
        'givenname': 'first',
        'homedirectory': 'homedir',
        'in_group': 'in-groups',
        'in_hbacrule': 'in-hbacrules',
        'in_netgroup': 'in-netgroups',
        'in_role': 'in-roles',
        'in_sudorule': 'in-sudorules',
        'initials': 'initials',
        'ipasshpubkey': 'sshpubkey',
        'ipatokenradiusconfiglink': 'radius',
        'ipatokenradiususername': 'radius_username',
        'ipauserauthtype': 'user-auth-type',
        'krbprincipalexpiration': 'principal-expiration',
        'krbprincipalname': 'principal',
        'l': 'city',
        'loginshell': 'shell',
        'mail': 'email',
        'manager': 'manager',
        'mobile': 'mobile',
        'no_members': 'no-members',
        'no_preserve': 'no-preserve',
        'not_in_group': 'not-in-groups',
        'not_in_hbacrule': 'not-in-hbacrules',
        'not_in_netgroup': 'not-in-netgroups',
        'not_in_role': 'not-in-roles',
        'not_in_sudorule': 'not-in-sudorules',
        'ou': 'orgunit',
        'pager': 'pager',
        'pkey_only': 'pkey-only',
        'postalcode': 'postalcode',
        'preferredlanguage': 'preferredlanguage',
        'preserve': 'preserve',
        'preserved': 'preserved',
        'random': 'random',
        'rename': 'rename',
        'rights': 'rights',
        'sizelimit': 'sizelimit',
        'sn': 'last',
        'st': 'state',
        'street': 'street',
        'telephonenumber': 'phone',
        'timelimit': 'timelimit',
        'title': 'title',
        'uid': 'login',
        'uidnumber': 'uid',
        'user': 'users',
        'usercertificate': 'certificate',
        'userclass': 'class',
        'userpassword': 'password',
        }

    mapping_output_user = {
        'Account disabled': 'nsaccountlock',
        'Display name': 'displayname',
        'dn': 'dn',
        'Email address': 'mail',
        'First name': 'givenname',
        'Full name': 'cn',
        'GECOS': 'gecos',
        'GID': 'gidnumber',
        'Home directory': 'homedirectory',
        'Initials': 'initials',
        'ipauniqueid': 'ipauniqueid',
        'Kerberos keys available': 'has_keytab',
        'Last name': 'sn',
        'Login shell': 'loginshell',
        'Member of groups': 'memberof_group',
        'mepmanagedentry': 'mepmanagedentry',
        'nsaccountlock': 'nsaccountlock',
        'objectclass': 'objectclass',
        'Password': 'has_password',
        'Preserved user': 'preserved',
        'Principal alias': 'krbprincipalname',
        'Principal name': 'krbcanonicalname',
        'UID': 'uidnumber',
        'User login': 'uid',
        }

    def __init__(self, name, givenname, sn, **kwargs):
        super(UserTracker, self).__init__(default_version=None)
        self.uid = name
        self.givenname = givenname
        self.sn = sn
        self.dn = DN(('uid', self.uid), api.env.container_user, api.env.basedn)

        self.kwargs = kwargs
        self.mapping_options.update(self.mapping_options_user)
        self.mapping_output.update(self.mapping_output_user)
        self.novalue.extend(['preserve', 'no_preserve'])

    def make_create_command(self):
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

    def make_disable_command(self):
        """ Make function that disables user using user-disable """
        return self.make_command('user_disable', self.uid)

    def make_stage_command(self):
        """ Make function that restores preserved user by moving it to
        staged container """
        return self.make_command('user_stage', self.uid)

    def make_group_add_member_command(self, *args, **kwargs):
        return self.make_command('group_add_member', *args, **kwargs)

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
            krbcanonicalname=[u'%s@%s' % (self.uid, self.api.env.realm)],
            mail=[u'%s@%s' % (self.uid, self.api.env.domain)],
            gecos=[u'%s %s' % (self.givenname, self.sn)],
            loginshell=[u'/bin/sh'],
            has_keytab=False,
            has_password=False,
            mepmanagedentry=[get_group_dn(self.uid)],
            memberof_group=[u'ipausers'],
            nsaccountlock=[u'false'],
            )

        for key in self.kwargs:
            if key == u'krbprincipalname':
                try:
                    self.attrs[key] = [u'%s@%s' % (
                        (self.kwargs[key].split('@'))[0].lower(),
                        (self.kwargs[key].split('@'))[1]
                    )]
                except IndexError:
                    # we can provide just principal part
                    self.attrs[key] = [u'%s@%s' % (
                        (self.kwargs[key].lower(),
                         self.api.env.realm)
                    )]
            else:
                if type(self.kwargs[key]) is not list:
                    self.attrs[key] = [self.kwargs[key]]
                else:
                    self.attrs[key] = self.kwargs[key]

        self.exists = True

    def update(self, updates, expected_updates=None):
        """Helper function to update this user and check the result

        Overriding Tracker method for setting self.attrs correctly;
         * most attributes stores its value in list
         * the rest can be overridden by expected_updates
         * allow deleting parameters if update value is None
        """
        if expected_updates is None:
            expected_updates = {}

        self.ensure_exists()
        command = self.make_update_command(updates)
        result = command()

        for key, value in updates.items():
            if value is None or value is '' or value is u'':
                del self.attrs[key]
            elif key == 'rename':
                new_principal = u'{0}@{1}'.format(value, self.api.env.realm)
                self.attrs['uid'] = [value]
                self.attrs['krbcanonicalname'] = [new_principal]
                if new_principal not in self.attrs['krbprincipalname']:
                    self.attrs['krbprincipalname'].append(new_principal)
            else:
                if type(value) is list:
                    self.attrs[key] = value
                else:
                    self.attrs[key] = [value]
        for key, value in expected_updates.items():
            if value is None or value is '' or value is u'':
                del self.attrs[key]
            else:
                self.attrs[key] = value

        self.check_update(
            result,
            extra_keys=set(updates.keys()) | set(expected_updates.keys())
        )

        if 'rename' in updates:
            self.uid = self.attrs['uid'][0]

    def check_create(self, result, extra_keys=()):
        """ Check 'user-add' command result """
        if self.cli_mode():
            expected = self.filter_attrs(
                self.create_cli_keys | set(extra_keys))
            assert_deepequal(dict(
                summary=u'Added user "%s"' % self.uid,
                result=self.filter_attrs(expected),
                ), result)
        else:
            expected = self.filter_attrs(self.create_keys | set(extra_keys))
            assert_deepequal(dict(
                value=self.uid,
                summary=u'Added user "%s"' % self.uid,
                result=self.filter_attrs(expected),
                ), result)

    def check_delete(self, result):
        """ Check 'user-del' command result """
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Deleted user "%s"' % self.uid,
                result={},
                ), result)
        else:
            assert_deepequal(dict(
                value=[self.uid],
                summary=u'Deleted user "%s"' % self.uid,
                result=dict(failed=[]),
                ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Check 'user-show' command result """
        if u'preserved' in self.attrs and self.attrs[u'preserved']:
            self.retrieve_all_keys = self.retrieve_preserved_all_keys
            self.retrieve_keys = self.retrieve_preserved_keys
            self.retrieve_cli_keys = self.retrieve_preserved_cli_keys
        elif u'preserved' not in self.attrs and all:
            self.attrs[u'preserved'] = False

        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        elif self.cli_mode():
            expected = self.filter_attrs(self.retrieve_cli_keys)
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

        if self.cli_mode():
            if 'dn' in result['result']:
                result['result']['dn'] = result['result']['dn'][0]
            if 'objectclass' in result['result']:
                result['result']['objectclass'] = result[
                    'result']['objectclass'][0].split(", ")
            assert_deepequal(dict(
                summary=None,
                result=expected,
            ), result)
        else:
            assert_deepequal(dict(
                value=self.uid,
                summary=None,
                result=expected,
            ), result)

    def check_find(self, result, all=False, pkey_only=False, raw=False,
                   expected_override=None):
        """ Check 'user-find' command result """
        if all:
            if u'preserved' not in self.attrs:
                self.attrs.update(preserved=False)
            expected = self.filter_attrs(self.find_all_keys)
        elif pkey_only:
            expected = self.filter_attrs(self.primary_keys)
        elif self.cli_mode():
            expected = self.filter_attrs(self.find_cli_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        if all and self.attrs[u'preserved']:
            del expected[u'mepmanagedentry']

        if u'nsaccountlock' in expected:
            if expected[u'nsaccountlock'] == [u'true']:
                expected[u'nsaccountlock'] = True
            elif expected[u'nsaccountlock'] == [u'false']:
                expected[u'nsaccountlock'] = False

        if expected_override:
            assert isinstance(expected_override, dict)
            expected.update(expected_override)

        if self.cli_mode():
            if 'dn' in result['result']:
                result['result']['dn'] = result['result']['dn'][0]
            if 'objectclass' in result['result']:
                result['result']['objectclass'] = result[
                    'result']['objectclass'][0].split(", ")
            assert_deepequal(dict(
                summary=u'Number of entries returned 1',
                result=expected,
            ), result)
        else:
            assert_deepequal(dict(
                count=1,
                truncated=False,
                summary=u'1 user matched',
                result=[expected],
            ), result)

    def check_find_nomatch(self, result):
        """ Check 'user-find' command result when no user should be found """
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Number of entries returned 0',
                result={},
            ), result)
        else:
            assert_deepequal(dict(
                count=0,
                truncated=False,
                summary=u'0 users matched',
                result=[],
            ), result)

    def check_update(self, result, extra_keys=()):
        """ Check 'user-mod' command result """
        expected = self.filter_attrs(self.update_keys | set(extra_keys))
        if expected[u'nsaccountlock'] == [u'true']:
            expected[u'nsaccountlock'] = True
        elif expected[u'nsaccountlock'] == [u'false']:
            expected[u'nsaccountlock'] = False

        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Modified user "%s"' % self.uid,
                result=expected
            ), result)
        else:
            assert_deepequal(dict(
                value=self.uid,
                summary=u'Modified user "%s"' % self.uid,
                result=expected
            ), result)

    def check_enable(self, result):
        """ Check result of enable user operation """
        assert_deepequal(dict(
            value=self.name,
            summary=u'Enabled user account "%s"' % self.name,
            result=True
        ), result)

    def check_disable(self, result):
        """ Check result of disable user operation """
        assert_deepequal(dict(
            value=self.name,
            summary=u'Disabled user account "%s"' % self.name,
            result=True
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
        self.attrs[u'memberof_group'] = [u'ipausers']
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
        self.attrs[u'nsaccountlock'] = [u'false']

    def check_activate(self, result):
        """ Check 'stageuser-activate' command result """
        if self.cli_mode():
            expected = dict(
                summary=u'Stage user %s activated' % self.uid,
                result=self.filter_attrs(self.activate_cli_keys))
        else:
            expected = dict(
                value=self.uid,
                summary=u'Stage user %s activated' % self.uid,
                result=self.filter_attrs(self.activate_keys))

            # small override because stageuser-find returns different
            # type of nsaccountlock value than DS, but overall the value
            # fits expected result
            if expected['result'][u'nsaccountlock'] == [u'true']:
                expected['result'][u'nsaccountlock'] = True
            elif expected['result'][u'nsaccountlock'] == [u'false']:
                expected['result'][u'nsaccountlock'] = False

        assert_deepequal(expected, result)

        self.exists = True

    def check_undel(self, result):
        """ Check 'user-undel' command result """
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Undeleted user account "%s"' % self.uid,
                result={}
                ), result)
        else:
            assert_deepequal(dict(
                value=self.uid,
                summary=u'Undeleted user account "%s"' % self.uid,
                result=True
                ), result)

    def enable(self):
        """ Enable user account if it was disabled """
        if (self.attrs['nsaccountlock'] is True or
                self.attrs['nsaccountlock'] == [u'true']):
            self.attrs.update(nsaccountlock=False)
            result = self.make_enable_command()()
            self.check_enable(result)

    def disable(self):
        """ Disable user account if it was enabled """
        if (self.attrs['nsaccountlock'] is False or
                self.attrs['nsaccountlock'] == [u'false']):
            self.attrs.update(nsaccountlock=True)
            result = self.make_disable_command()()
            self.check_disable(result)

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

        if self.cli_mode():
            group = [u'ipausers']
        else:
            group = (u'ipausers',)
        if (u'memberof_group' not in result[u'result'] or
                result[u'result'][u'memberof_group'] != group):
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
            self.skip_error = True
            del_command()
        except errors.NotFound:
            pass

        def finish():
            with raises_exact(errors.NotFound(
                    reason=u'%s: user not found' % self.uid)):
                del_command()

        request.addfinalizer(finish)

        return self

    def make_admin(self, admin_group=u'admins'):
        """ Add user to the administrator's group """
        result = self.run_command('group_show', admin_group)
        admin_group_content = result[u'result'][u'member_user']
        admin_group_expected = list(admin_group_content) + [self.name]

        command = self.make_group_add_member_command(
            admin_group, **dict(user=self.name)
        )
        result = command()
        assert_deepequal(dict(
            completed=1,
            failed=dict(
                member=dict(group=tuple(), user=tuple())
            ),
            result={
                'dn': get_group_dn(admin_group),
                'member_user': admin_group_expected,
                'gidnumber': [fuzzy_digits],
                'cn': [admin_group],
                'description': [u'Account administrators group'],
            },
        ), result)

    #  Kerberos aliases methods
    def _make_add_alias_cmd(self):
        return self.make_command('user_add_principal', self.name)

    def _make_remove_alias_cmd(self):
        return self.make_command('user_remove_principal', self.name)
