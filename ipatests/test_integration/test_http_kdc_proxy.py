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
from ipaplatform.paths import paths


@pytest.mark.usefixtures('ipa_ad_trust')
class TestHttpKdcProxy(IntegrationTest):
    topology = "line"
    num_clients = 1
    num_ad_domains = 1

    @classmethod
    def install(cls, mh):
        cls.client = cls.clients[0]
        cls.ad = cls.ads[0]
        super(TestHttpKdcProxy, cls).install(mh)

    @pytest.fixture(scope='class')
    def users(self, mh):
        ad = mh.ads[0]
        users = {
            'ipa': {
                'name': 'ipa_test_user',
                'password': 'SecretIpaTestUser',
                'domain': mh.master.domain
            },
            'ad': {
                'name': 'testuser@{}'.format(ad.domain.realm),
                'password': 'Secret123',
                'domain': ad.domain
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
        krb5conf_backup = tasks.FileBackup(self.client, paths.KRB5_CONF)
        krb5conf = self.client.get_file_contents(
            paths.KRB5_CONF, encoding='utf-8')
        kdc_url = 'https://{}/KdcProxy'.format(self.master.hostname)
        kdc_option = 'kdc = {}'.format(kdc_url)

        # configure kdc proxy for IPA realm
        krb5conf, n = re.subn(r' kdc = .+', kdc_option, krb5conf)
        assert n == 1

        # configure kdc proxy for Windows AD realm
        ad_realm_config = '''
        {realm} = {{
            {kdc}
        }}
        '''.format(realm=self.ad.domain.realm, kdc=kdc_option)
        krb5conf, n = re.subn(
            r'\[realms\]', '[realms]' + ad_realm_config, krb5conf)
        assert n == 1

        self.client.put_file_contents(paths.KRB5_CONF, krb5conf)
        self.client.run_command(['systemctl', 'restart', 'sssd.service'])
        yield
        krb5conf_backup.restore()
        self.client.run_command(['systemctl', 'restart', 'sssd.service'])

    @contextmanager
    def configure_kdc_proxy_for_ad_trust(self, use_tcp):
        backup = tasks.FileBackup(self.master, paths.KDCPROXY_CONFIG)
        with tasks.remote_ini_file(self.master, paths.KDCPROXY_CONFIG) as conf:
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

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_user_login_on_client_without_firewall(self, users, user_origin):
        """Basic check for test setup."""
        tasks.clear_sssd_cache(self.master)
        user = users[user_origin]
        tasks.kinit_as_user(self.client, user['name'], user['password'])

    @pytest.mark.usefixtures('restrict_network_for_client')
    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_access_blocked_on_client_without_kdcproxy(
            self, users, user_origin):
        """Check for test firewall setup."""
        tasks.clear_sssd_cache(self.master)
        user = users[user_origin]
        result = tasks.kinit_as_user(
            self.client, user['name'], user['password'], raiseonerr=False)
        expected_error = (
            "Cannot contact any KDC for realm '{}' while getting initial "
            "credentials".format(user['domain'].realm))
        assert result.returncode == 1 and expected_error in result.stderr_text

    @pytest.mark.usefixtures('restrict_network_for_client',
                             'client_use_kdcproxy')
    def test_ipa_user_login_on_client_with_kdcproxy(self, users):
        tasks.clear_sssd_cache(self.master)
        user = users['ipa']
        tasks.kinit_as_user(self.client, user['name'], user['password'])

    @pytest.mark.usefixtures('restrict_network_for_client',
                             'client_use_kdcproxy')
    @pytest.mark.parametrize('use_tcp', [True, False])
    def test_ad_user_login_on_client_with_kdcproxy(self, users, use_tcp):
        tasks.clear_sssd_cache(self.master)
        user = users['ad']
        with self.configure_kdc_proxy_for_ad_trust(use_tcp):
            tasks.kinit_as_user(self.client, user['name'], user['password'])

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
        tasks.clear_sssd_cache(self.master)
        user = users['ad']
        with self.configure_kdc_proxy_for_ad_trust(use_tcp=True):
            tasks.kinit_as_user(self.client, user['name'], user['password'])
