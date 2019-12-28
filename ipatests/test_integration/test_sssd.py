#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for SSSD as used in IPA"""

from __future__ import absolute_import

import time
from contextlib import contextmanager

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths


class TestSSSDWithAdTrust(IntegrationTest):

    topology = 'star'
    num_ad_domains = 1

    users = {
        'ipa': {
            'name': 'user1',
            'password': 'SecretUser1'
        },
        'ad': {
            'name_tmpl': 'testuser@{domain}',
            'password': 'Secret123'
        },
        'fakeuser': {
            'name': 'some_user@some.domain'
        },
    }
    ipa_user = 'user1'
    ipa_user_password = 'SecretUser1'
    intermed_user = 'user2'
    ad_user_tmpl = 'testuser@{domain}'
    ad_user_password = 'Secret123'

    @classmethod
    def install(cls, mh):
        super(TestSSSDWithAdTrust, cls).install(mh)

        cls.ad = cls.ads[0]

        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

        cls.users['ad']['name'] = cls.users['ad']['name_tmpl'].format(
            domain=cls.ad.domain.name)

        # Regression tests for cached_auth_timeout option
        # https://bugzilla.redhat.com/show_bug.cgi?id=1685581
        tasks.user_add(cls.master, cls.intermed_user)
        tasks.create_active_user(cls.master, cls.ipa_user,
                                 cls.ipa_user_password)

    @contextmanager
    def config_sssd_cache_auth(self, cached_auth_timeout):
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        with tasks.remote_ini_file(self.master, paths.SSSD_CONF) as sssd_conf:
            domain_section = 'domain/{}'.format(self.master.domain.name)
            if cached_auth_timeout is None:
                sssd_conf.remove_option(domain_section, 'cached_auth_timeout')
            else:
                sssd_conf.set(domain_section, 'cached_auth_timeout',
                              cached_auth_timeout)
            sssd_conf.set('pam', 'pam_verbosity', '2')

        try:
            tasks.clear_sssd_cache(self.master)
            yield
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

    def is_auth_cached(self, user):
        cmd = ['su', '-l', user['name'], '-c', 'true']
        res = tasks.run_command_as_user(self.master, self.intermed_user, cmd,
                                        stdin_text=user['password'] + '\n')
        return 'Authenticated with cached credentials.' in res.stdout_text

    @pytest.mark.parametrize('user', ['ipa', 'ad'])
    def test_auth_cache_disabled_by_default(self, user):
        with self.config_sssd_cache_auth(cached_auth_timeout=None):
            assert not self.is_auth_cached(self.users[user])
            assert not self.is_auth_cached(self.users[user])

    @pytest.mark.parametrize('user', ['ipa', 'ad'])
    def test_auth_cache_disabled_with_value_0(self, user):
        with self.config_sssd_cache_auth(cached_auth_timeout=0):
            assert not self.is_auth_cached(self.users[user])
            assert not self.is_auth_cached(self.users[user])

    @pytest.mark.parametrize('user', ['ipa', 'ad'])
    def test_auth_cache_enabled_when_configured(self, user):
        timeout = 30
        with self.config_sssd_cache_auth(cached_auth_timeout=timeout):
            start = time.time()
            # check auth is cached after first login
            assert not self.is_auth_cached(self.users[user])
            assert self.is_auth_cached(self.users[user])
            # check cache expires after configured timeout
            elapsed = time.time() - start
            time.sleep(timeout - 5 - elapsed)
            assert self.is_auth_cached(self.users[user])
            time.sleep(10)
            assert not self.is_auth_cached(self.users[user])

    @contextmanager
    def filter_user_setup(self, user):
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        filter_user = {'filter_users': self.users[user]['name']}
        try:
            tasks.modify_sssd_conf(self.master, self.master.domain.name,
                                   filter_user)
            tasks.clear_sssd_cache(self.master)
            yield
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

    @pytest.mark.xfail(
        osinfo.id == 'fedora' and osinfo.version_number <= (29,),
        reason='https://pagure.io/SSSD/sssd/issue/3978')
    @pytest.mark.parametrize('user', ['ad', 'fakeuser'])
    def test_is_user_filtered(self, user):
        """No lookup in data provider from 'filter_users' config option.

        Test for https://bugzilla.redhat.com/show_bug.cgi?id=1685472
        https://bugzilla.redhat.com/show_bug.cgi?id=1724088

        When there are users in filter_users in domain section then no look
        up should be in data provider.
        """
        with self.filter_user_setup(user=user):
            log_file = '{0}/sssd_nss.log'.format(paths.VAR_LOG_SSSD_DIR)
            logsize = tasks.get_logsize(self.master, log_file)
            self.master.run_command(
                ['getent', 'passwd', self.users[user]['name']],
                ok_returncode=2)
            sssd_log = self.master.get_file_contents(log_file)[logsize:]
            dp_req = ("Looking up [{0}] in data provider".format(
                self.users[user]['name']))
            assert not dp_req.encode() in sssd_log
