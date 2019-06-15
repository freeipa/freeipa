#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import six

from ipalib import api, errors
from ipaplatform.constants import constants as platformconstants

from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.tracker.kerberos_aliases import KerberosAliasMixin
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    Fuzzy, fuzzy_string, fuzzy_dergeneralizedtime, raises_exact)

from ipatests.util import assert_deepequal
from ipapython.dn import DN

if six.PY3:
    unicode = str

sshpubkey = (u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6X'
             'HBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGI'
             'wA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2'
             'No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNm'
             'cSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM01'
             '9Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF'
             '0L public key test')
sshpubkeyfp = (u'SHA256:cStA9o5TRSARbeketEOooMUMSWRSsArIAXloBZ4vNsE '
               'public key test (ssh-rsa)')


class StageUserTracker(KerberosAliasMixin, Tracker):
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
        u'st', u'mobile', u'pager', u'krbcanonicalname', u'krbprincipalname'}
    retrieve_all_keys = retrieve_keys | {
        u'cn', u'ipauniqueid', u'objectclass', u'description',
        u'displayname', u'gecos', u'initials', u'manager'}

    create_keys = retrieve_all_keys | {
        u'objectclass', u'ipauniqueid', u'randompassword',
        u'userpassword', u'krbextradata', u'krblastpwdchange',
        u'krbpasswordexpiration', u'krbprincipalkey'}

    update_keys = retrieve_keys - {u'dn', u'nsaccountlock'}
    activate_keys = retrieve_keys | {
        u'has_keytab', u'has_password', u'nsaccountlock'}

    find_keys = retrieve_keys - {u'has_keytab', u'has_password'}
    find_all_keys = retrieve_all_keys - {u'has_keytab', u'has_password'}

    def __init__(self, name=None, givenname=None, sn=None, **kwargs):
        """ Check for non-empty unicode string for the required attributes
        in the init method """

        if not (isinstance(givenname, str) and givenname):
            raise ValueError(
                "Invalid first name provided: {!r}".format(givenname)
                )
        if not (isinstance(sn, str) and sn):
            raise ValueError("Invalid second name provided: {!r}".format(sn))

        super(StageUserTracker, self).__init__(default_version=None)
        self.uid = unicode(name)
        self.givenname = unicode(givenname)
        self.sn = unicode(sn)
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
            krbcanonicalname=[u'%s@%s' % (self.uid, self.api.env.realm)],
            mail=[u'%s@%s' % (self.uid, self.api.env.domain)],
            gecos=[u'%s %s' % (self.givenname, self.sn)],
            loginshell=[platformconstants.DEFAULT_SHELL],
            has_keytab=False,
            has_password=False,
            nsaccountlock=[u'true'],
            )

        for key in self.kwargs:
            if key == u'krbprincipalname':
                self.attrs[key] = [u'%s@%s' % (
                    (self.kwargs[key].split('@'))[0].lower(),
                    (self.kwargs[key].split('@'))[1])]
                self.attrs[u'krbcanonicalname'] = self.attrs[key]
            elif key == u'manager':
                self.attrs[key] = [self.kwargs[key]]
            elif key == u'ipasshpubkey':
                self.attrs[u'sshpubkeyfp'] = [sshpubkeyfp]
                self.attrs[key] = [self.kwargs[key]]
            elif key in {u'random', u'userpassword'}:
                self.attrs[u'krbextradata'] = [Fuzzy(type=bytes)]
                self.attrs[u'krbpasswordexpiration'] = [
                    fuzzy_dergeneralizedtime]
                self.attrs[u'krblastpwdchange'] = [fuzzy_dergeneralizedtime]
                self.attrs[u'krbprincipalkey'] = [Fuzzy(type=bytes)]
                self.attrs[u'userpassword'] = [Fuzzy(type=bytes)]
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
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

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

    def _make_add_alias_cmd(self):
        return self.make_command('stageuser_add_principal', self.name)

    def _make_remove_alias_cmd(self):
        return self.make_command('stageuser_remove_principal', self.name)
