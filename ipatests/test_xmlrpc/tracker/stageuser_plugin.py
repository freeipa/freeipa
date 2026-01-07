#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import copy

from ipalib import api, errors
from ipaplatform.constants import constants as platformconstants

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.passkey_plugin import PasskeyMixin
from ipatests.test_xmlrpc.tracker.kerberos_aliases import KerberosAliasMixin
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    Fuzzy, fuzzy_string, fuzzy_dergeneralizedtime, raises_exact)

from ipatests.util import assert_deepequal
from ipapython.dn import DN

sshpubkey = ('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
             'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
             'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
             'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
             'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
             '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
             '0L public key test')
sshpubkeyfp = ('SHA256:cStA9o5TRSARbeketEOooMUMSWRSsArIAXloBZ4vNsE '
               'public key test (ssh-rsa)')


class StageUserTracker(PasskeyMixin, KerberosAliasMixin, Tracker):
    """ Tracker class for staged user LDAP object

        Implements helper functions for host plugin.
        StageUserTracker object stores information about the user.
    """

    retrieve_keys = {
        'uid', 'givenname', 'sn', 'homedirectory', 'loginshell',
        'uidnumber', 'gidnumber', 'mail', 'ou', 'telephonenumber',
        'title', 'memberof', 'nsaccountlock', 'memberofindirect',
        'ipauserauthtype', 'userclass', 'ipatokenradiusconfiglink',
        'ipatokenradiususername', 'krbprincipalexpiration',
        'usercertificate', 'dn', 'has_keytab', 'has_password',
        'street', 'postalcode', 'facsimiletelephonenumber',
        'carlicense', 'ipasshpubkey', 'sshpubkeyfp', 'l',
        'st', 'mobile', 'pager', 'krbcanonicalname', 'krbprincipalname'}
    retrieve_all_keys = retrieve_keys | {
        'cn', 'ipauniqueid', 'objectclass', 'description',
        'displayname', 'gecos', 'initials', 'manager'}

    create_keys = retrieve_all_keys | {
        'objectclass', 'ipauniqueid', 'randompassword',
        'userpassword', 'krbextradata', 'krblastpwdchange',
        'krbpasswordexpiration', 'krbprincipalkey'}

    update_keys = retrieve_keys - {'dn', 'nsaccountlock'}
    activate_keys = retrieve_keys | {
        'has_keytab', 'has_password', 'nsaccountlock'}

    find_keys = retrieve_keys - {'has_keytab', 'has_password'}
    find_all_keys = retrieve_all_keys - {'has_keytab', 'has_password'}

    def __init__(self, name=None, givenname=None, sn=None, **kwargs):
        """ Check for non-empty string for the required attributes
        in the init method """

        if not (isinstance(givenname, str) and givenname):
            raise ValueError(
                "Invalid first name provided: {!r}".format(givenname)
                )
        if not (isinstance(sn, str) and sn):
            raise ValueError("Invalid second name provided: {!r}".format(sn))

        super(StageUserTracker, self).__init__(default_version=None)
        self.uid = str(name)
        self.givenname = str(givenname)
        self.sn = str(sn)
        self.dn = DN(
            ('uid', self.uid), api.env.container_stageuser, api.env.basedn)

        self.kwargs = kwargs

    def make_create_command(self, options=None):
        """ Make function that creates a staged user using stageuser-add
            with all set of attributes and with minimal values,
            where uid is not specified  """

        if options is not None:
            self.kwargs = options
        if self.uid is not None:
            return self.make_command(
                'stageuser_add', self.uid,
                givenname=self.givenname,
                sn=self.sn, **self.kwargs
                )
        else:
            return self.make_command(
                'stageuser_add',
                givenname=self.givenname,
                sn=self.sn, **self.kwargs
                )

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
            homedirectory=['/home/%s' % self.uid],
            displayname=['%s %s' % (self.givenname, self.sn)],
            cn=['%s %s' % (self.givenname, self.sn)],
            initials=['%s%s' % (self.givenname[0], self.sn[0])],
            objectclass=objectclasses.user_base,
            description=['__no_upg__'],
            ipauniqueid=['autogenerate'],
            uidnumber=['-1'],
            gidnumber=['-1'],
            krbprincipalname=['%s@%s' % (self.uid, self.api.env.realm)],
            krbcanonicalname=['%s@%s' % (self.uid, self.api.env.realm)],
            mail=['%s@%s' % (self.uid, self.api.env.domain)],
            gecos=['%s %s' % (self.givenname, self.sn)],
            loginshell=[platformconstants.DEFAULT_SHELL],
            has_keytab=False,
            has_password=False,
            nsaccountlock=True,
            )

        for key in self.kwargs:
            if key == 'krbprincipalname':
                self.attrs[key] = ['%s@%s' % (
                    (self.kwargs[key].split('@'))[0].lower(),
                    (self.kwargs[key].split('@'))[1])]
                self.attrs['krbcanonicalname'] = self.attrs[key]
            elif key == 'manager':
                self.attrs[key] = [self.kwargs[key]]
            elif key == 'ipasshpubkey':
                self.attrs['sshpubkeyfp'] = [sshpubkeyfp]
                self.attrs[key] = [self.kwargs[key]]
            elif key in {'random', 'userpassword'}:
                self.attrs['krbextradata'] = [Fuzzy(type=bytes)]
                self.attrs['krbpasswordexpiration'] = [
                    fuzzy_dergeneralizedtime]
                self.attrs['krblastpwdchange'] = [fuzzy_dergeneralizedtime]
                self.attrs['krbprincipalkey'] = [Fuzzy(type=bytes)]
                self.attrs['userpassword'] = [Fuzzy(type=bytes)]
                self.attrs['has_keytab'] = True
                self.attrs['has_password'] = True
                if key == 'random':
                    self.attrs['randompassword'] = fuzzy_string
            else:
                self.attrs[key] = [self.kwargs[key]]

        self.exists = True

    def check_create(self, result, extra_keys=()):
        """ Check 'stageuser-add' command result """
        expected = self.filter_attrs(self.create_keys | set(extra_keys))
        assert_deepequal(dict(
            value=self.uid,
            summary='Added stage user "%s"' % self.uid,
            result=self.filter_attrs(expected),
        ), result)

    def check_create_with_warning(self, result,
                                  warning_codes=(), extra_keys=()):
        """ Check 'stageuser-add' command result """
        expected = self.filter_attrs(self.create_keys | set(extra_keys))

        result = copy.deepcopy(result)
        assert 'messages' in result
        assert len(result['messages']) == len(warning_codes)
        codes = [message['code'] for message in result['messages']]
        for code in warning_codes:
            assert code in codes
            codes.pop(codes.index(code))

        del result['messages']

        assert_deepequal(dict(
            value=self.uid,
            summary='Added stage user "%s"' % self.uid,
            result=self.filter_attrs(expected),
        ), result)

    def check_delete(self, result):
        """ Check 'stageuser-del' command result """
        assert_deepequal(dict(
            value=[self.uid],
            summary='Deleted stage user "%s"' % self.uid,
            result=dict(failed=[]),
            ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """ Check 'stageuser-show' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.uid,
            summary=None,
            result=expected,
        ), result)

    def check_find(self, result, all=False, raw=False):
        """ Check 'stageuser-find' command result """
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary='1 user matched',
            result=[expected],
        ), result)

    def check_find_nomatch(self, result):
        """ Check 'stageuser-find' command result when no match is expected """
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary='0 users matched',
            result=[],
        ), result)

    def check_update(self, result, extra_keys=()):
        """ Check 'stageuser-mod' command result """
        assert_deepequal(dict(
            value=self.uid,
            summary='Modified stage user "%s"' % self.uid,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)

    def check_restore_preserved(self, result):
        assert_deepequal(dict(
            value=[self.uid],
            summary='Staged user account "%s"' % self.uid,
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
                    reason='%s: stage user not found' % self.uid)):
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
        self.attrs['dn'] = self.dn

    def _make_add_alias_cmd(self):
        return self.make_command('stageuser_add_principal', self.name)

    def _make_remove_alias_cmd(self):
        return self.make_command('stageuser_remove_principal', self.name)

    # Passkey mapping methods
    def _make_add_passkey(self):
        return self.make_command('stageuser_add_passkey', self.name)

    def _make_remove_passkey(self):
        return self.make_command('stageuser_remove_passkey', self.name)
