#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import six
import re

from ipalib import api, errors

from ipatests.test_xmlrpc.tracker.base import Tracker
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
sshpubkeyfp = (u'13:67:6B:BF:4E:A2:05:8E:AE:25:8B:A1:31:DE:6F:1B '
               'public key test (ssh-rsa)')


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
        u'st', u'mobile', u'pager', u'krbcanonicalname', u'krbprincipalname'}
    retrieve_all_keys = retrieve_keys | {
        u'cn', u'ipauniqueid', u'objectclass', u'description',
        u'displayname', u'gecos', u'initials', u'manager'}
    retrieve_cli_keys = retrieve_keys - {u'dn', u'nsaccountlock'}

    create_keys = retrieve_all_keys | {
        u'objectclass', u'ipauniqueid', u'randompassword',
        u'userpassword', u'krbextradata', u'krblastpwdchange',
        u'krbpasswordexpiration', u'krbprincipalkey'}
    create_cli_keys = create_keys - {
        u'description', u'dn', u'ipauniqueid', u'nsaccountlock',
        u'objectclass', u'krbextradata', u'krblastpwdchange',
        u'krbpasswordexpiration', u'krbprincipalkey'}

    update_keys = retrieve_keys - {u'dn', u'nsaccountlock'}
    activate_keys = retrieve_keys | {
        u'has_keytab', u'has_password', u'nsaccountlock'}

    find_keys = retrieve_keys - {u'has_keytab', u'has_password'}
    find_all_keys = retrieve_all_keys - {u'has_keytab', u'has_password'}
    find_cli_keys = find_keys - {u'dn', u'nsaccountlock'}

    mapping_options_stageuser = {
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

    mapping_output_stageuser = {
        'Car License': 'carlicense',
        'City': 'l',
        'Display name': 'displayname',
        'description': 'description',
        'dn': 'dn',
        'Email address': 'mail',
        'Fax Number': 'facsimiletelephonenumber',
        'First name': 'givenname',
        'Full name': 'cn',
        'GECOS': 'gecos',
        'GID': 'gidnumber',
        'Home directory': 'homedirectory',
        'Initials': 'initials',
        'ipauniqueid': 'ipauniqueid',
        'Job Title': 'title',
        'Kerberos keys available': 'has_keytab',
        'Last name': 'sn',
        'Login shell': 'loginshell',
        'Manager': 'manager',
        'Member of groups': 'memberof_group',
        'Mobile Telephone Number': 'mobile',
        'nsaccountlock': 'nsaccountlock',
        'objectclass': 'objectclass',
        'Org. Unit': 'ou',
        'Pager Number': 'pager',
        'Password': 'has_password',
        'Principal alias': 'krbprincipalname',
        'Principal name': 'krbcanonicalname',
        'Random password': 'randompassword',
        'SSH public key': 'ipasshpubkey',
        'SSH public key fingerprint': 'sshpubkeyfp',
        'State/Province': 'st',
        'Street address': 'street',
        'Telephone Number': 'telephonenumber',
        'UID': 'uidnumber',
        'User login': 'uid',
        'ZIP': 'postalcode',
        }

    def __init__(self, name, givenname, sn, **kwargs):
        super(StageUserTracker, self).__init__(default_version=None)
        self.uid = name
        self.givenname = givenname
        self.sn = sn
        self.dn = DN(
            ('uid', self.uid), api.env.container_stageuser, api.env.basedn)

        self.kwargs = kwargs
        self.mapping_options.update(self.mapping_options_stageuser)
        self.mapping_output.update(self.mapping_output_stageuser)
        self.novalue.extend(['preserve', 'no_preserve', 'random'])

    def cli_command(self, name, *args, **options):
        """ Modification of CLI command prepared using BaseTracker method
        In CLI, inputting '--password=<string>' is invalid. If this is present,
        this method changes the resulting command to format:
            echo <string> | command
        """
        cmd = super(StageUserTracker, self).cli_command(name, *args, **options)
        if '--password' in cmd:
            cmd = re.sub("(?<=--password)={}".format(options['userpassword']),
                         '', cmd)
            cmd = "echo {} | {}".format(options['userpassword'], cmd)
        return cmd

    def cli_output(self, result):
        """
        Reformats text output to dictionary to be compared with expected values

        Overrides BaseTracker method due to necessity of different handling
        of SSH pubkey and password data.
        """
        result = result.split("\n")
        modresult = {'result': {}, 'summary': None}
        for line in result:
            if re.match("^-*$", line):
                continue
            elif ':' in line:
                key = self.mapping_output[line.split(':')[0].strip()]
                if "SSH public key fingerprint" in line:
                    value = unicode(line[30:])
                else:
                    value = line.split(':')[1].strip()
                    if value == 'True':
                        value = True
                    elif value == 'False':
                        value = False
                    else:
                        value = unicode(value)

                if key in modresult['result']:
                    modresult['result'][key].append(value)
                elif value is True or value is False:
                    modresult['result'][key] = value
                else:
                    modresult['result'][key] = [value]

                if key is 'has_password':
                    if type(value) is bool:
                        modresult['result'][key] = value
                    else:
                        modresult['result']['userpassword'] = [str(value)]
                elif key is 'randompassword':
                    modresult['result'][key] = value[0]
            else:
                modresult['summary'] = unicode(line)

        return modresult

    def make_create_command(self, options=None):
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
            krbcanonicalname=[u'%s@%s' % (self.uid, self.api.env.realm)],
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
                self.attrs[u'krbcanonicalname'] = self.attrs[key]
            elif key == u'manager':
                self.attrs[key] = [self.kwargs[key]]
            elif key == u'ipasshpubkey':
                self.attrs[u'sshpubkeyfp'] = [sshpubkeyfp]
                self.attrs[key] = [self.kwargs[key]]
            elif key == u'random' or key == u'userpassword':
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
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Added stage user "%s"' % self.uid,
                result=self.filter_attrs(self.create_cli_keys),
            ), result)
        else:
            assert_deepequal(dict(
                value=self.uid,
                summary=u'Added stage user "%s"' % self.uid,
                result=self.filter_attrs(self.create_keys),
            ), result)

    def check_delete(self, result):
        """ Check 'stageuser-del' command result """
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Deleted stage user "%s"' % self.uid,
                result={},
                ), result)
        else:
            assert_deepequal(dict(
                value=[self.uid],
                summary=u'Deleted stage user "%s"' % self.uid,
                result=dict(failed=[]),
                ), result)

    def modify_expected(self, expected):
        """ Small override because stageuser-find returns different
        type of nsaccountlock value than DS, but overall the value
        fits expected result """
        if expected[u'nsaccountlock'] == [u'true']:
            expected[u'nsaccountlock'] = True
        elif expected[u'nsaccountlock'] == [u'false']:
            expected[u'nsaccountlock'] = False
        return expected

    def check_retrieve(self, result, all=False, raw=False):
        """ Check 'stageuser-show' command result """
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
            expected = self.modify_expected(expected)
        elif self.cli_mode():
            expected = self.filter_attrs(self.retrieve_cli_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
            expected = self.modify_expected(expected)

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

    def check_find(self, result, all=False, raw=False):
        """ Check 'stageuser-find' command result """
        if all:
            expected = self.filter_attrs(self.find_all_keys)
            expected = self.modify_expected(expected)
        elif self.cli_mode():
            expected = self.filter_attrs(self.find_cli_keys)
        else:
            expected = self.filter_attrs(self.find_keys)
            expected = self.modify_expected(expected)

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
        """ Check 'stageuser-find' command result when no match is expected """
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
        """ Check 'stageuser-mod' command result """
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Modified stage user "%s"' % self.uid,
                result=self.filter_attrs(self.update_keys | set(extra_keys))
            ), result)
        else:
            assert_deepequal(dict(
                value=self.uid,
                summary=u'Modified stage user "%s"' % self.uid,
                result=self.filter_attrs(self.update_keys | set(extra_keys))
            ), result)

    def check_restore_preserved(self, result):
        if self.cli_mode():
            assert_deepequal(dict(
                summary=u'Staged user account "%s"' % self.uid,
                result={},
            ), result)
        else:
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
            self.skip_error = True
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
