#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import os
import re
import nose
from ipaplatform.paths import paths
from ipatests.pytest_plugins.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipalib.constants import DOMAIN_LEVEL_1


class TestSssdSubdomain(IntegrationTest):
    """
    Tests for SSSD Subdomain RFE
    Design Document:
    https://docs.pagure.org/SSSD.sssd/design_pages/subdomain_configuration.html

    # Before running these testcases, please create following AD objects
    1. OUs - 'sales' and 'finance'
    2. Users - 'test1' under 'sales' OU and test2 under 'finance' OU
               'apac1' and 'emea1' users under 'sales' OU
    3. Groups - 'sales-group1' under 'sales' OU
    """
    topology = 'line'
    num_ad_domains = 1
    num_clients = 1
    optional_extra_roles = ['ad_subdomain']
    domain_level = DOMAIN_LEVEL_1

    @classmethod
    def install(cls, mh):
        pkgs_list = {"samba-client": "/usr/bin/rpcclient",
                     "ipa-server-trust-ad": "/usr/sbin/ipa-adtrust-install"}

        for pkg in pkgs_list.keys():
            if not cls.master.transport.file_exists(pkgs_list[pkg]):
                raise nose.SkipTest("Package {} is not available "
                                    "on {}".format(pkg, cls.master.hostname))

        super(TestSssdSubdomain, cls).install(mh)
        cls.ad = cls.ad_domains[0].ads[0]
        cls.ad_domain = cls.ad.domain.name
        cls.client = cls.clients[0]
        cls.clientname = cls.client.run_command(['hostname',
                                                 '-s']).stdout_text.strip()
        cls.sssd_domain = '%s/%s' % (cls.master.domain.name, cls.ad_domain)
        cls.ldap_search_base = "dc=%s" % (",dc=".join(cls.ad_domain.split(".")))
        cls.sales_ou = 'ou=sales,%s' % cls.ldap_search_base
        cls.finance_ou = 'ou=finance,%s' % cls.ldap_search_base
        cls.testuser1 = 'test1@%s' % cls.ad_domain
        cls.testuser2 = 'test2@%s' % cls.ad_domain
        cls.apacuser1 = 'apac1@%s' % cls.ad_domain
        cls.emeauser1 = 'emea1@%s' % cls.ad_domain
        cls.sales_group = 'sales-group1@%s' % cls.ad_domain

        cls.configure_dns_and_time()
        cls.install_adtrust()
        cls.check_sid_generation()

        # Determine whether the subdomain AD is available
        try:
            cls.child_ad = cls.host_by_role(cls.optional_extra_roles[0])
            cls.ad_subdomain = '.'.join(
                cls.child_ad.hostname.split('.')[1:])
        except LookupError:
            cls.ad_subdomain = None

    @classmethod
    def disable_dnssec(cls, host):
        """
        Disable DNSSEC and restart named-pkcs11 service
        """
        named_txt = host.get_file_contents(paths.NAMED_CONF)
        named_txt = re.sub('dnssec-validation yes',
                           'dnssec-validation no',
                           named_txt)
        host.put_file_contents(paths.NAMED_CONF, named_txt)
        tasks.restart_named(host)

    @classmethod
    def configure_dns_and_time(cls):
        cls.disable_dnssec(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad_domain)
        tasks.sync_time(cls.master, cls.ad)
        tasks.add_ad_domain_forward_policy(cls.master,
                                           cls.ad_domain,
                                           cls.ad_domains[0].ads[0].ip)

    @classmethod
    def install_adtrust(cls):
        """Test adtrust support installation"""

        tasks.install_adtrust(cls.master)

    @classmethod
    def check_sid_generation(cls):
        """Test SID generation"""
        command = [paths.IPA, 'user-show', 'admin', '--all', '--raw']
        _sid_identifier_authority = '(0x[0-9a-f]{1,12}|[0-9]{1,10})'
        sid_regex = 'S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s' \
                    % dict(idauth=_sid_identifier_authority)
        stdout_re = re.escape('  ipaNTSecurityIdentifier: ') + sid_regex

        tasks.run_repeatedly(cls.master, command,
                             test=lambda x: re.search(stdout_re, x))

    def test_establish_trust(self):
        """Tests establishing trust with Active Directory"""

        tasks.establish_trust_with_ad(self.master, self.ad_domain,
                                      extra_args=['--range-type', 'ipa-ad-trust'])

    def test_all_trustdomains_found(self):
        """
        Tests that all trustdomains can be found.
        """

        if self.ad_subdomain is None:
            raise nose.SkipTest('AD subdomain is not available.')

        result = self.master.run_command(['ipa',
                                          'trustdomain-find',
                                          self.ad_domain])

        # Check that all trust domains appear in the result
        assert self.ad_domain in result.stdout_text
        assert self.ad_subdomain in result.stdout_text

    def test_0001_basic_sanity_subdomain(self):
        """IDM-IPA-TC: Using ldap_user_search_base with trusted AD domain"""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)
        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0
        cmd = self.client.run_command(['id', self.testuser2], raiseonerr=False)
        assert cmd.returncode != 0
        assert "no such user" in cmd.stdout_text + cmd.stderr_text

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0002_basic_sanity_specific_ou(self):
        """IDM-IPA-TC: Ensure ldap_user_search_base displays users only from specific OU"""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.finance_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)
        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode != 0
        assert "no such user" in cmd.stdout_text + cmd.stderr_text
        cmd = self.client.run_command(['id', self.testuser2], raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0003_basic_sanity_nested_ou(self):
        """IDM-IPA-TC: Ensure users are displayed when nested OU's are present."""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['id', self.apacuser1], raiseonerr=False)
        assert cmd.returncode == 0
        cmd = self.client.run_command(['id', self.emeauser1], raiseonerr=False)
        assert cmd.returncode == 0
        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)
        tasks.clear_sssd_cache(self.client)

    def test_0005_basic_sanity_ldap_group_search_base(self):
        """IDM-IPA-TC: Ensure ldap_group_search_base displays correct information"""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_group_search_base": self.sales_ou,
                "ldap_use_tokengroups": "False",
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['getent', 'group', self.sales_group], raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0006_basic_sanity_alternate_upn(self):
        """IDM-IPA-TC: With UPN set on the AD."""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['sssctl', 'domain-status',
                                       self.ad_domain], raiseonerr=False)
        assert cmd.returncode == 0
        assert "Online status: Online" in cmd.stdout_text + cmd.stderr_text

        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0007_basic_sanity_ad_site(self):
        """IDM-IPA-TC: Ensure ad_site value is set."""
        ad_site = "PNE"

        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ad_site": ad_site,
                "ad_server": self.ad.hostname,
            },
        )

        self.master.run_command(['sssctl', 'logs-remove'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        # Grep ldap_search_base and ldap_group_search_base in sssd debug logs
        log_path = os.path.join(paths.VAR_LOG_SSSD_DIR, "sssd_%s.log" % self.client.domain.name)
        cmd_output = self.master.transport.get_file_contents(log_path)
        assert "Option ad_server has value %s" % self.ad.hostname in cmd_output
        assert "Option ad_site has value %s" % ad_site in cmd_output

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0008_basic_sanity_user_search_base(self):
        """IDM-IPA-TC: Ensure ldap_user_search_base is set."""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        self.master.run_command(['sssctl', 'logs-remove'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        # Grep ldap_search_base and ldap_group_search_base in sssd debug logs
        log_path = os.path.join(paths.VAR_LOG_SSSD_DIR, "sssd_%s.log" % self.client.domain.name)
        cmd = self.master.transport.get_file_contents(log_path)
        assert "Option ldap_search_base has value %s" % self.ldap_search_base in cmd
        assert "Option ldap_user_search_base has value %s" % self.sales_ou in cmd

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0009_basic_sanity_group_search_base(self):
        """IDM-IPA-TC: Ensure ldap_group_search_base displays correct information"""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
                "ldap_group_search_base": self.sales_ou,
            },
        )

        self.master.run_command(['sssctl', 'logs-remove'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        # Grep ldap_search_base and ldap_group_search_base in sssd debug logs
        log_path = os.path.join(paths.VAR_LOG_SSSD_DIR, "sssd_%s.log" % self.client.domain.name)
        cmd = self.master.transport.get_file_contents(log_path)
        assert "Option ldap_search_base has value %s" % self.ldap_search_base in cmd
        assert "Option ldap_user_search_base has value %s" % self.sales_ou in cmd

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0010_basic_sanity_external_trust(self):
        """IDM-IPA-TC: Ensure ldap_user_search_base works with external trust AD setup"""
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.establish_trust_with_ad(self.master, self.ad_domain,
                                      extra_args=['--external=True', '--range-type', 'ipa-ad-trust'])

        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0
        cmd = self.client.run_command(['id', self.testuser2], raiseonerr=False)
        assert cmd.returncode != 0
        assert "no such user" in cmd.stdout_text + cmd.stderr_text

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0011_basic_sanity_external_trust_group_search(self):
        """IDM-IPA-TC: Ensure ldap_group_search_base section works with external trust AD"""
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.establish_trust_with_ad(self.master, self.ad_domain,
                                      extra_args=['--external=True', '--range-type', 'ipa-ad-trust'])

        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['getent', 'group', self.sales_group], raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0012_basic_sanity_two_way_trust(self):
        """IDM-IPA-TC: Ensure ldap_user_search_base works with two-way trust AD setup"""
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.establish_trust_with_ad(self.master, self.ad_domain,
                                      extra_args=['--two-way=True', '--range-type', 'ipa-ad-trust'])

        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0
        cmd = self.client.run_command(['id', self.testuser2], raiseonerr=False)
        assert cmd.returncode != 0
        assert "no such user" in cmd.stdout_text + cmd.stderr_text

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0013_basic_sanity(self):
        """IDM-IPA-TC: Ensure ldap_group_search_base section works with two-way trust AD setup"""
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.establish_trust_with_ad(self.master, self.ad_domain,
                                      extra_args=['--two-way=True', '--range-type', 'ipa-ad-trust'])

        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)

        cmd = self.client.run_command(['getent', 'group', self.sales_group],
                                      raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0014_basic_sanity_with_ipa_user(self):
        """IDM-IPA-TC: Ensure IPA users are looked up when ldap_user_search_base
           is specified in subdomain section
        """
        tasks.remove_trust_with_ad(self.master, self.ad_domain)
        tasks.establish_trust_with_ad(self.master, self.ad_domain,
                                      extra_args=['--range-type', 'ipa-ad-trust'])
        # Add IPA User
        tasks.kinit_admin(self.master)
        testuser = "test1"
        password = "Secret123"
        cmd = self.master.run_command(['ipa', 'user-find', testuser],
                                      raiseonerr=False)
        if cmd.returncode != 0:
            self.master.run_command(['ipa', 'user-add', testuser,
                                     '--first', testuser,
                                     '--last', testuser, '--password'],
                                    stdin_text=password, raiseonerr=False)

        tasks.add_domain_sssd_conf(
            self.client,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )
        tasks.clear_sssd_cache(self.client)

        # Search for AD User
        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0

        # Search for IPA User
        cmd = self.client.run_command(['id', '%s@%s' % (testuser,
                                                        self.master.domain.name)],
                                      raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.client,
                                      domain=self.sssd_domain)

    def test_0015_basic_sanity_ipa_group(self):
        """IDM-IPA-TC: Ensure IPA groups are looked up when
           ldap_group_search_base is specified in subdomain section
        """
        # Add IPA Group
        tasks.kinit_admin(self.master)
        sales_group = "sales-group1"

        cmd = self.master.run_command(['ipa', 'group-find', sales_group],
                                      raiseonerr=False)
        if cmd.returncode != 0:
            self.master.run_command(['ipa', 'group-add', sales_group],
                                    raiseonerr=False)

        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ldap_search_base": self.ldap_search_base,
                "ldap_group_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)

        # Search AD Group
        cmd = self.client.run_command(['getent', 'group', self.sales_group],
                                      raiseonerr=False)
        assert cmd.returncode == 0

        # Search IPA Group
        cmd = self.client.run_command(['getent',
                                       'group',
                                       '%s@%s' % (sales_group,
                                                  self.master.domain.name)],
                                      raiseonerr=False)
        assert cmd.returncode == 0

        tasks.delete_domain_sssd_conf(host=self.master,
                                      domain=self.sssd_domain)

    def test_0016_basic_sanity(self):
        """IDM-IPA-TC: Ensure with ad_server specified, performs correct SRV lookup"""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ad_server": self.ad.hostname,
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)
        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0

        # Grep ad_server in sssd debug logs
        log_path = os.path.join(paths.VAR_LOG_SSSD_DIR,
                                "sssd_%s.log" % self.master.domain.name)
        cmd = self.master.transport.get_file_contents(log_path)
        assert "Status of server '%s' " \
               "is 'name resolved'" % self.ad.hostname in cmd

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)

    def test_0017_basic_sanity(self):
        """IDM-IPA-TC: Ensure with ad_site specified, performs correct SRV lookup"""
        tasks.add_domain_sssd_conf(
            self.master,
            self.sssd_domain,
            {
                "ad_site": self.ad.hostname,
                "ldap_search_base": self.ldap_search_base,
                "ldap_user_search_base": self.sales_ou,
            },
        )

        tasks.clear_sssd_cache(self.client)
        self.client.run_command(['sss_cache', '-E'], raiseonerr=False)
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['sss_cache', '-E'], raiseonerr=False)
        cmd = self.client.run_command(['id', self.testuser1], raiseonerr=False)
        assert cmd.returncode == 0

        # Grep ad_server in sssd debug logs
        log_path = os.path.join(paths.VAR_LOG_SSSD_DIR,
                                "sssd_%s.log" % self.master.domain.name)
        cmd = self.master.transport.get_file_contents(log_path)
        assert "Trying to resolve SRV record " \
               "of '_ldap._tcp.%s._sites.%s'" % (self.ad_domain, self.ad_domain) in cmd

        tasks.delete_domain_sssd_conf(host=self.master, domain=self.sssd_domain)
