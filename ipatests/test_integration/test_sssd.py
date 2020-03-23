#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for SSSD as used in IPA"""

from __future__ import absolute_import

import time
from contextlib import contextmanager
import re

import pytest
import subprocess
import textwrap

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.tasks import tasks as platform_tasks
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths
from ipapython.dn import DN


class TestSSSDWithAdTrust(IntegrationTest):

    topology = 'star'
    num_ad_domains = 1
    num_clients = 1

    users = {
        'ipa': {
            'name': 'user1',
            'password': 'SecretUser1',
            'group': 'user1',
        },
        'ad': {
            'name_tmpl': 'testuser@{domain}',
            'password': 'Secret123',
            'group_tmpl': 'testgroup@{domain}',
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
        cls.users['ad']['group'] = cls.users['ad']['group_tmpl'].format(
            domain=cls.ad.domain.name)
        tasks.user_add(cls.master, cls.intermed_user)
        tasks.create_active_user(cls.master, cls.ipa_user,
                                 cls.ipa_user_password)

    @contextmanager
    def config_sssd_cache_auth(self, cached_auth_timeout):
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        with tasks.remote_sssd_config(self.master) as sssd_conf:
            sssd_conf.edit_domain(self.master.domain, 'cached_auth_timeout',
                                  cached_auth_timeout)
            sssd_conf.edit_service('pam', 'pam_verbosity', '2')
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
        """Check credentials not cached with default sssd config.

        Regression test for cached_auth_timeout option
        https://bugzilla.redhat.com/show_bug.cgi?id=1685581
        """
        with self.config_sssd_cache_auth(cached_auth_timeout=None):
            assert not self.is_auth_cached(self.users[user])
            assert not self.is_auth_cached(self.users[user])

    @pytest.mark.parametrize('user', ['ipa', 'ad'])
    def test_auth_cache_disabled_with_value_0(self, user):
        """Check credentials not cached with cached_auth_timeout=0 in sssd.conf

        Regression test for cached_auth_timeout option
        https://bugzilla.redhat.com/show_bug.cgi?id=1685581
        """
        with self.config_sssd_cache_auth(cached_auth_timeout=0):
            assert not self.is_auth_cached(self.users[user])
            assert not self.is_auth_cached(self.users[user])

    @pytest.mark.parametrize('user', ['ipa', 'ad'])
    def test_auth_cache_enabled_when_configured(self, user):
        """Check credentials are cached with cached_auth_timeout=30

        Regression test for cached_auth_timeout option
        https://bugzilla.redhat.com/show_bug.cgi?id=1685581
        """

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
        try:
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(self.master.domain,
                                      'filter_users', self.users[user]['name'])
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

    def test_extdom_group(self):
        """ipa-extdom-extop plugin should allow @ in group name.

        Test for : https://bugzilla.redhat.com/show_bug.cgi?id=1746951

        If group contains @ in group name from AD, eg. abc@pqr@AD.DOMAIN
        then it should fetch successfully on ipa-client.
        """
        client = self.clients[0]
        hosts = [self.master, client]
        ad_group = 'group@group@{0}'.format(self.ad.domain.name)
        expression = '((?P<name>.+)@(?P<domain>[^@]+$))'
        master_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        client_conf_backup = tasks.FileBackup(client, paths.SSSD_CONF)
        for host in hosts:
            with tasks.remote_sssd_config(host) as sssd_conf:
                sssd_conf.edit_service('sssd', 're_expression', expression)
            tasks.clear_sssd_cache(host)
        try:
            cmd = ['getent', 'group', ad_group]
            result = self.master.run_command(cmd)
            assert ad_group in result.stdout_text
            result2 = client.run_command(cmd)
            assert ad_group in result2.stdout_text
        finally:
            master_conf_backup.restore()
            client_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)
            tasks.clear_sssd_cache(client)

    def test_external_group_paging(self):
        """SSSD should fetch external groups without any limit.

        Regression test for https://pagure.io/SSSD/sssd/issue/4058
        1: Add external groups more than limit.
        2: Run the command id aduser@ADDOMAIN.COM
        3: sssd should retrieve all the external groups.
        """
        new_limit = 50
        master = self.master
        conn = master.ldap_connect()
        dn = DN(('cn', 'config'))
        entry = conn.get_entry(dn)  # pylint: disable=no-member
        orig_limit = entry.single_value.get('nsslapd-sizelimit')
        ldap_query = textwrap.dedent("""
            dn: cn=config
            changetype: modify
            replace: nsslapd-sizelimit
            nsslapd-sizelimit: {limit}
        """)
        tasks.ldapmodify_dm(master, ldap_query.format(limit=new_limit))
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        ldap_page_size = new_limit - 1
        group_count = new_limit + 2
        # default ldap_page_size is '1000', adding workaround as
        # ldap_page_size < nsslapd-sizelimit in sssd.conf
        # Related issue : https://pagure.io/389-ds-base/issue/50888
        with tasks.remote_sssd_config(self.master) as sssd_conf:
            sssd_conf.edit_domain(
                self.master.domain, 'ldap_page_size', ldap_page_size)
        tasks.clear_sssd_cache(master)
        tasks.kinit_admin(master)
        for i in range(group_count):
            master.run_command(['ipa', 'group-add', '--external',
                                'ext-ipatest{0}'.format(i)])
        try:
            log_file = '{0}/sssd_{1}.log'.format(
                paths.VAR_LOG_SSSD_DIR, master.domain.name)
            group_entry = b'[%d] external groups found' % group_count
            logsize = tasks.get_logsize(master, log_file)
            master.run_command(['id', self.users['ad']['name']])
            sssd_logs = master.get_file_contents(log_file)[logsize:]
            assert group_entry in sssd_logs
        finally:
            for i in range(group_count):
                master.run_command(['ipa', 'group-del',
                                    'ext-ipatest{0}'.format(i)])
            # reset to original limit
            tasks.ldapmodify_dm(master, ldap_query.format(limit=orig_limit))
            sssd_conf_backup.restore()

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_sssd_cache_refresh(self, user_origin):
        """Check SSSD updates expired cache items for domain and its subdomains

        Regression test for https://pagure.io/SSSD/sssd/issue/4012
        """
        def get_cache_update_time(obj_kind, obj_name):
            res = self.master.run_command(
                ['sssctl', '{}-show'.format(obj_kind), obj_name])
            m = re.search(r'Cache entry last update time:\s+([^\n]+)',
                          res.stdout_text)
            update_time = m.group(1).strip()
            assert update_time
            return update_time

        # by design, sssd does first update of expired records in 30 seconds
        # since start
        refresh_time = 30
        user = self.users[user_origin]['name']
        group = self.users[user_origin]['group']
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        try:
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(
                    self.master.domain, 'refresh_expired_interval', 1)
                sssd_conf.edit_domain(
                    self.master.domain, 'entry_cache_timeout', 1)
            tasks.clear_sssd_cache(self.master)

            start = time.time()
            self.master.run_command(['id', user])
            user_update_time = get_cache_update_time('user', user)
            group_update_time = get_cache_update_time('group', group)
            time.sleep(start + refresh_time - time.time() + 5)
            assert get_cache_update_time('user', user) != user_update_time
            assert (get_cache_update_time('group', group) !=
                    group_update_time)
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

    def test_ext_grp_with_ldap(self):
        """User and group with same name should not break reading AD user data.

        Regression test for https://pagure.io/SSSD/sssd/issue/4073

        When aduser is added in extrnal group and this group is added
        in group with same name of nonprivate ipa user and possix id, then
        lookup of aduser and group should be successful when cache is empty.
        """
        cmd = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.parse_ipa_version(
            cmd.stdout_text.strip())
        if sssd_version <= platform_tasks.parse_ipa_version('2.2.2'):
            pytest.skip("Fix for https://pagure.io/SSSD/sssd/issue/4073 "
                        "unavailable with sssd-2.2.2")
        client = self.clients[0]
        user = 'ipatest'
        userid = '100996'
        ext_group = 'ext-ipatest'
        tasks.kinit_admin(self.master)
        # add user with same uid and gidnumber
        tasks.user_add(self.master, user, extra_args=[
            '--noprivate', '--uid', userid, '--gidnumber', userid])
        # add group with same as user_name and user_id.
        tasks.group_add(self.master, user, extra_args=['--gid', userid])
        tasks.group_add(self.master, ext_group, extra_args=['--external'])
        self.master.run_command(
            ['ipa', 'group-add-member', '--group', ext_group, user])
        self.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            self.users['ad']['name'], ext_group])
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(client)
        try:
            result = client.run_command(['id', self.users['ad']['name']])
            assert '{uid}({name})'.format(uid=userid,
                                          name=user) in result.stdout_text
        finally:
            self.master.run_command(['ipa', 'user-del', user])
            self.master.run_command(['ipa', 'group-del', user, ext_group])

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_external_group_member_mismatch(self, user_origin):
        """Prevent adding IPA objects as external group external members

        External groups must only allow adding non-IPA objects as external
        members in 'ipa group-add-member foo --external bar'.
        """
        master = self.master
        tasks.clear_sssd_cache(master)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'group-add', '--external',
                            'ext-ipatest'])
        try:
            master.run_command(['ipa', '-n', 'group-add-member',
                                'ext-ipatest',
                                '--external',
                                self.users[user_origin]['name']])
        except subprocess.CalledProcessError:
            # Only 'ipa' origin should throw a validation error
            assert user_origin == 'ipa'
        finally:
            master.run_command(['ipa', 'group-del', 'ext-ipatest'])
