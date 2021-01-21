import time

import pytest

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestResolvers(IntegrationTest):
    num_clients = 1
    num_ad_domains = 1

    @classmethod
    def install(cls, mh):
        cls.client = cls.clients[0]
        cls.ad = cls.ads[0]

    @classmethod
    def uninstall(cls, mh):
        pass

    def check_dnf_works(self, host):
        host.run_command(['dnf', 'clean', 'all'])
        host.run_command(['dnf', 'install', '-y', 'mc'])
        host.run_command(['dnf', 'remove', '-y', 'mc'])

    def display_resolver_config(self, host):
        host.run_command(['ls', '-l', '/etc/resolv.conf'])
        host.run_command(['cat', '/etc/resolv.conf'])
        # host.run_command(['dig', 'abc'], raiseonerr=False)

    # def check_ad_access(self, host):
    #     tasks.clear_sssd_cache(host)
    #     ad_admin = 'Administrator@%s' % self.ad.domain.name
    #     tasks.kinit_as_user(self.client, ad_admin,
    #                         self.master.config.ad_admin_password)

    @pytest.mark.parametrize('host', ['client'])
    def test_display_resolvers_config_1(self, host):
        host = getattr(self, host)
        self.display_resolver_config(host)

    def test_restart_network_manager(self):
        self.client.run_command(['systemctl', 'restart', 'NetworkManager'])

    @pytest.mark.parametrize('host', ['client'])
    def test_display_resolvers_config_2(self, host):
        host = getattr(self, host)
        self.display_resolver_config(host)

    # @pytest.mark.parametrize('host', ['master', 'client'])
    # def test_dnf_works_without_ipa_installed(self, host):
    #     host = getattr(self, host)
    #     self.check_dnf_works(host)

    # def test_install_ipa(self):
    #     tasks.install_topo('line', self.master, [], [self.client], 1)
    #
    # def test_establish_trust_with_ad(self):
    #     tasks.install_adtrust(self.master)
    #     tasks.configure_dns_for_trust(self.master, self.ad)
    #     tasks.configure_windows_dns_for_trust(self.ad, self.master)
    #     tasks.establish_trust_with_ad(self.master, self.ad.domain.name,
    #                                   extra_args=['--two-way=true'])
    #
    # @pytest.mark.parametrize('host', ['master', 'client'])
    # def test_display_resolvers_config_with_ipa_installed(self, host):
    #     host = getattr(self, host)
    #     self.display_resolver_config(host)
    #
    # @pytest.mark.parametrize('host', ['master', 'client'])
    # def test_dnf_works_with_ipa_installed(self, host):
    #     host = getattr(self, host)
    #     self.check_dnf_works(host)
    #
    # @pytest.mark.parametrize('host', ['master', 'client'])
    # def test_client_access_ad_domain_without_changing_resolv_conf(self, host):
    #     host = getattr(self, host)
    #     self.check_ad_access(host)
    #
    # def test_manually_point_client_resolv_conf_to_ipa_master(self):
    #     self.__class__._resolv_conf_backup = tasks.FileBackup(
    #         self.client, '/etc/resolv.conf')
    #     tasks.config_host_resolvconf_with_master_data(self.master, self.client)
    #
    # def test_display_resolvers_config_with_manual_resolv_conf(self):
    #     self.display_resolver_config(self.client)
    #
    # def test_dnf_works_with_manual_resolv_conf(self):
    #     self.check_dnf_works(self.client)
    #
    # def test_client_access_ad_domain_with_manual_resolv_conf(self):
    #     self.check_ad_access(self.client)
    #
    # def test_wait_15_minutes(self):
    #     time.sleep(15 * 60)
    #
    # def test_display_resolvers_config_after_time_interval(self):
    #     self.display_resolver_config(self.client)
    #
    # def test_dnf_works_after_time_interval(self):
    #     self.check_dnf_works(self.client)
    #
    # def test_client_access_ad_domain_after_time_interval(self):
    #     self.check_ad_access(self.client)
    #
    # def uninstall_ipa(self):
    #     tasks.uninstall_master(self.master)
    #     tasks.uninstall_client(self.client)
    #
    # @pytest.mark.parametrize('host', ['master', 'client'])
    # def test_display_resolvers_config_with_ipa_uninstalled(self, host):
    #     host = getattr(self, host)
    #     self.display_resolver_config(host)
    #
    # @pytest.mark.parametrize('host', ['master', 'client'])
    # def test_dnf_works_with_ipa_uninstalled(self, host):
    #     host = getattr(self, host)
    #     self.check_dnf_works(host)
    #
    # def test_manually_restore_resolv_conf(self):
    #     self.__class__._resolv_conf_backup.restore()
    #
    # def test_display_resolvers_config_with_restored_resolv_conf(self):
    #     self.display_resolver_config(self.client)
    #
    # def test_dnf_works_with_restored_resolv_conf(self):
    #     self.check_dnf_works(self.client)
