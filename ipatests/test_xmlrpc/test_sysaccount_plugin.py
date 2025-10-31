#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#
"""
Test the `ipaserver/plugins/sysaccount.py` module.
"""

import pytest
import time

from ipalib import errors, api, messages
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipautil import run, ipa_generate_password
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipatests.util import assert_equal, assert_not_equal
from ipaserver.plugins.ldap2 import ldap2

role1 = 'my-app-role'
sysaccount1 = 'my-app'
testuser = 'test_user'


@pytest.fixture(scope='class')
def test_user(request, xmlrpc_setup):
    tracker = UserTracker(testuser, 'test', 'user')

    return tracker.make_fixture(request)


@pytest.mark.tier1
class test_sysaccount(XMLRPC_test):
    """
    Test the `sysaccount` plugin.
    """
    account = sysaccount1
    passwd = None
    dn = None
    kw = {'random': True}

    def test_sysaccount_use(self, test_user):
        """
        Create a system account and use it to change passwords without a reset
        """
        entry = api.Command['sysaccount_add'](self.account, **self.kw)['result']
        assert_attr_equal(entry, 'uid', self.account)
        self.dn = DN(entry.get('dn'))

        privilege = f'{self.account} password change privilege'
        role = f'{self.account} role'

        # FYI: API command names must be normalized using underscore
        # rather than dashes (CLI).
        batch = [
            dict(method='privilege_add', params=([privilege], {})),
            dict(method='privilege_add_permission', params=([privilege],
                 dict(permission='System: Change User password'))),
            dict(method='role_add', params=([role], {})),
            dict(method='role_add_privilege', params=([role],
                 dict(privilege=privilege))),
            dict(method='role_add_member', params=([role],
                 dict(sysaccount=self.account))),
            dict(method='sysaccount_mod', params=([self.account],
                 dict(random=True))),
            dict(method='sysaccount_policy', params=([self.account],
                 dict(privileged=True))),
        ]
        results = api.Command['batch'](methods=batch)

        assert_equal(len(results['results']), len(batch))

        # Last command should return a message to restart the dirsrv
        allow_reset_res = results['results'][-1].get('messages', [])
        assert_not_equal(len(allow_reset_res), 0)
        assert_equal(
            allow_reset_res[0]['code'],
            messages.ServerSysacctMgrUpdateRequired.errno
        )

        # Second to last command should give a new password
        sysaccount_mod_res = results['results'][-2]['result']
        self.passwd = sysaccount_mod_res.get('randompassword', None)
        assert (self.passwd is not None)

        # Requires a 389-ds restart
        dashed_domain = api.env.realm.replace(".", "-")
        cmd = ['systemctl', 'restart', 'dirsrv@{}'.format(dashed_domain)]
        run(cmd)
        # wait a bit to settle down 389-ds after restart
        # it takes roughly 12 seconds to restart dirsrv
        # until compat tree is ready on Azure CI
        time.sleep(15)

        testuser_oldpw = ipa_generate_password()
        testuser_newpw = ipa_generate_password()
        test_user.ensure_exists()

        pwdmod = test_user.make_update_command({'userpassword': testuser_oldpw})
        pwdmod()

        # Change test user's password to a different password
        # we'd use a random password generated for the sysaccount
        # Run ldappasswd as the sysaccount but apply change to the test user
        ldap_uri = f'ldap://{api.env.host}'
        args = [paths.LDAPPASSWD, '-D', str(self.dn),
                '-w', self.passwd, '-a', testuser_oldpw, '-s', testuser_newpw,
                '-x', '-ZZ', '-H', ldap_uri, str(test_user.dn)]
        run(args, raiseonerr=True)

        # Validate that the last password change is not the same as the password
        # expiration date: in case of non-working password reset they'll be the
        # same value.
        user = api.Command['user_show'](test_user.name,
                                        all=True, raw=True)['result']
        assert (
            user['krbLastPwdChange'] != user['krbPasswordExpiration']
        )

        # Attempt to bind as a test_user
        conn = ldap2(api)
        conn.connect(bind_dn=test_user.dn, bind_pw=testuser_newpw)
        conn.disconnect()

        batch = [
            dict(method='role_del', params=([role], {})),
            dict(method='privilege_del', params=([privilege], {})),
            dict(method='sysaccount_policy', params=([self.account],
                 dict(privileged=False))),
            dict(method='sysaccount_del', params=([self.account], {})),
        ]
        api.Command['batch'](methods=batch)
        # Verify that it is gone
        with pytest.raises(errors.NotFound):
            api.Command['sysaccount_show'](self.account)

        test_user.ensure_missing()
