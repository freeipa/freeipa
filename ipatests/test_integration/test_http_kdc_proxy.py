#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import re
from contextlib import contextmanager

import pytest

from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.test_integration.base import IntegrationTest


class TestHttpKdcProxy(IntegrationTest):
    topology = "line"
    num_clients = 1
    num_ad_domains = 1

    @classmethod
    def install(cls, mh):
        super().install(mh)

        cls.client = cls.clients[0]
        cls.ad = cls.ads[0]

        tasks.kinit_admin(cls.master)
        cls.master.run_command(['ipa', 'pwpolicy-mod', '--minlife=0'])

        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

    @classmethod
    def uninstall(cls, mh):
        tasks.remove_trust_info_from_ad(
            cls.master, cls.ad.domain.name, cls.ad.hostname)
        super().uninstall(mh)

    @pytest.fixture(autouse=True, scope='function')
    def cleanup_credentials(self):
        tasks.kdestroy_all(self.client)
        tasks.clear_sssd_cache(self.client)

    @pytest.fixture(scope='class')
    def users(self, mh):
        master = mh.master
        ad = mh.ads[0]
        users = {
            'ipa': {
                'name': 'ipa_test_user',
                'password': 'SecretIpaTestUser',
                'domain': mh.master.domain,
                'test_service': 'HTTP/{}@{}'
                .format(master.hostname, master.domain.realm),
            },
            'ad': {
                'name': 'testuser@{}'.format(ad.domain.realm),
                'password': 'Secret123',
                'domain': ad.domain,
                'test_service': 'HTTP/{}@{}'
                .format(ad.hostname, ad.domain.realm),
            }
        }
        tasks.kinit_admin(mh.master)
        tasks.create_active_user(
            mh.master, users['ipa']['name'], users['ipa']['password'])
        yield users
        tasks.kinit_admin(mh.master)
        mh.master.run_command(['ipa', 'user-del', users['ipa']['name']])

    @pytest.fixture()
    def restrict_network_for_client(self, mh):
        fw_rules_allow = [
            ['OUTPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'],
            ['OUTPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'],
            ['OUTPUT', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'],
            ['OUTPUT', '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT']]
        fw = Firewall(self.client)
        fw.prepend_passthrough_rules(fw_rules_allow)
        fw.passthrough_rule(['-P', 'OUTPUT', 'DROP'])
        yield
        fw.passthrough_rule(['-P', 'OUTPUT', 'ACCEPT'])
        fw.remove_passthrough_rules(fw_rules_allow)

    @pytest.fixture()
    def client_use_kdcproxy(self, mh):
        """Configure client for using kdcproxy for IPA and AD domains."""
        def replace_regexp_once(pattern, repl, string):
            res, n = re.subn(pattern, repl, string)
            assert n == 1
            return res

        krb5conf_backup = tasks.FileBackup(
            self.client, self.client.paths.KRB5_CONF
        )
        krb5conf = self.client.get_file_contents(
            self.client.paths.KRB5_CONF, encoding="utf-8"
        )
        kdc_url = 'https://{}/KdcProxy'.format(self.master.hostname)

        # configure kdc proxy for IPA realm
        krb5conf = replace_regexp_once(
            r' kdc = .+', ' kdc = {}'.format(kdc_url), krb5conf)
        krb5conf = replace_regexp_once(
            r'kpasswd_server = .+', 'kpasswd_server = {}'.format(kdc_url),
            krb5conf)

        # configure kdc proxy for Windows AD realm
        ad_realm_config = '''
        {realm} = {{
            kdc = {kdc_url}
            kpasswd_server = {kdc_url}
        }}
        '''.format(realm=self.ad.domain.realm, kdc_url=kdc_url)
        krb5conf = replace_regexp_once(
            r'\[realms\]',
            '[realms]' + ad_realm_config,
            krb5conf
        )

        self.client.put_file_contents(self.client.paths.KRB5_CONF, krb5conf)
        self.client.systemctl.restart("sssd")
        yield
        krb5conf_backup.restore()
        self.client.systemctl.restart("sssd")

    @contextmanager
    def configure_kdc_proxy_for_ad_trust(self, use_tcp):
        backup = tasks.FileBackup(
            self.master, self.master.paths.KDCPROXY_CONFIG
        )
        with tasks.remote_ini_file(
            self.master, self.master.paths.KDCPROXY_CONFIG
        ) as conf:
            conf.set('global', 'use_dns', 'true')
            conf.set('global', 'configs', 'mit')
            if use_tcp:
                conf.add_section(self.ad.domain.realm)
                conf.set(self.ad.domain.realm, 'kerberos',
                         'kerberos+tcp://{}:88'.format(self.ad.hostname))
                conf.set(self.ad.domain.realm, 'kpasswd',
                         'kpasswd+tcp://{}:464'.format(self.ad.hostname))
        try:
            self.master.run_command(['ipactl', 'restart'])
            yield
        finally:
            backup.restore()
            self.master.run_command(['ipactl', 'restart'])

    def check_kerberos_requests(self, user, skip_kpasswd_check=False):
        # KDC AS request
        tasks.kinit_as_user(self.client, user['name'], user['password'])

        # KDC TGS requests
        self.client.run_command(['kvno', user['test_service']])

        # KDC AS requests and kpasswd requests

        # Changing password on Windows AD can not be done now because
        # of default password policy mandating that minimal password lifetime
        # is one day.
        # Once we switch to dynamically creating test users in Windows AD
        # and create an utility for modifying Group Policy Objects then
        # we should update test setup and remove this condition.
        def set_password(old_pass, new_pass):
            with self.client.spawn_expect(['kpasswd', user['name']]) as e:
                e.expect('Password for .+:')
                e.sendline(old_pass)
                e.expect_exact('Enter new password:')
                e.sendline(new_pass)
                e.expect_exact('Enter it again:')
                e.sendline(new_pass)
                e.expect_exit(ignore_remaining_output=True)

        if not skip_kpasswd_check:
            test_password = 'Secret123456'
            set_password(user['password'], test_password)
            # Restore password:
            set_password(test_password, user['password'])

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_user_login_on_client_without_firewall(self, users, user_origin):
        """Basic check for test setup."""
        self.check_kerberos_requests(users[user_origin],
                                     skip_kpasswd_check=user_origin == 'ad')

    @pytest.mark.usefixtures('restrict_network_for_client')
    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_access_blocked_on_client_without_kdcproxy(
            self, users, user_origin):
        """Check for test firewall setup."""
        user = users[user_origin]
        result = tasks.kinit_as_user(
            self.client, user['name'], user['password'], raiseonerr=False)
        expected_errors = [
            ("Cannot contact any KDC for realm '{}' while getting initial "
             "credentials".format(user['domain'].realm)),
            ('Cannot find KDC for realm "{}" while getting initial '
             "credentials".format(user['domain'].realm)),
        ]
        assert (result.returncode == 1
                and any(s in result.stderr_text for s in expected_errors))

    @pytest.mark.usefixtures('restrict_network_for_client',
                             'client_use_kdcproxy')
    def test_ipa_user_login_on_client_with_kdcproxy(self, users):
        self.check_kerberos_requests(users['ipa'])

    @pytest.mark.usefixtures('restrict_network_for_client',
                             'client_use_kdcproxy')
    @pytest.mark.parametrize('use_tcp', [True, False])
    def test_ad_user_login_on_client_with_kdcproxy(self, users, use_tcp):
        with self.configure_kdc_proxy_for_ad_trust(use_tcp):
            self.check_kerberos_requests(users['ad'], skip_kpasswd_check=True)

    @pytest.fixture()
    def windows_small_mtu_size(self, mh):
        new_mtu = 70

        def get_iface_name():
            result = self.ad.run_command([
                'powershell', '-c',
                '(Get-NetIPAddress -IPAddress {}).InterfaceAlias'.format(
                    self.ad.ip)])
            return result.stdout_text.strip()

        def get_mtu(iface_name):
            result = self.ad.run_command([
                'netsh', 'interface', 'ipv4', 'show', 'subinterface',
                iface_name])
            mtu = result.stdout_text.strip().splitlines()[-1].split()[0]
            return int(mtu)

        def set_mtu(iface_name, mtu):
            self.ad.run_command([
                'netsh', 'interface', 'ipv4', 'set', 'subinterface',
                iface_name, 'mtu={}'.format(mtu)])

        iface_name = get_iface_name()
        original_mtu = get_mtu(iface_name)
        set_mtu(iface_name, new_mtu)
        # `netsh` does not report failures with return code so we check
        # it was successful by inspecting the actual value of MTU
        assert get_mtu(iface_name) == new_mtu
        yield
        set_mtu(iface_name, original_mtu)
        assert get_mtu(iface_name) == original_mtu

    @pytest.mark.usefixtures('restrict_network_for_client',
                             'client_use_kdcproxy',
                             'windows_small_mtu_size')
    def test_kdcproxy_handles_small_packets_from_ad(self, users):
        """Check that kdcproxy handles AD response split to several TCP packets

        This is a regression test for the bug in python-kdcproxy:
        https://github.com/latchset/kdcproxy/pull/44
          When the reply from AD is split into several TCP packets the kdc
          proxy software cannot handle it and returns a false error message
          indicating it cannot contact the KDC server.
        """
        with self.configure_kdc_proxy_for_ad_trust(use_tcp=True):
            self.check_kerberos_requests(users['ad'], skip_kpasswd_check=True)
