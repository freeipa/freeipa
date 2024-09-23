#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for various options of ipa-client-install.
"""

from __future__ import absolute_import

import os
import pytest
import re
import shlex
import textwrap

from ipaplatform.paths import paths
from ipalib.sysrestore import SYSRESTORE_STATEFILE, SYSRESTORE_INDEXFILE
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall


class TestInstallClient(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    def check_dns_lookup_kdc(self, client):
        """Check that dns_lookup_kdc is never set to false.

        https://pagure.io/freeipa/issue/6523

        Setting dns_lookup_kdc to False would result in a hardcoded
        configuration which is less reliable in the long run.
        For instance, adding a trust to an Active Directory forest
        after clients are enrolled would result in clients not being
        able to authenticate AD users. Recycling FreeIPA servers
        could prove problematic if the original hostnames are not
        reused too.
        """

        result = client.run_command(
            shlex.split("grep dns_lookup_kdc /etc/krb5.conf")
        )
        assert 'false' not in result.stdout_text.lower()
        assert 'true' in result.stdout_text.lower()

    def test_dns_lookup_kdc_is_true_with_default_enrollment_options(self):
        self.check_dns_lookup_kdc(self.clients[0])
        tasks.uninstall_client(self.clients[0])

    def test_dns_lookup_kdc_is_true_with_ipa_server_on_cli(self):
        tasks.install_client(
            self.master,
            self.clients[0],
            extra_args=["--server", self.master.hostname]
        )
        self.check_dns_lookup_kdc(self.clients[0])
        tasks.uninstall_client(self.clients[0])

    def test_client_install_with_ssh_trust_dns(self):
        """no host key verification if ssh-trust-dns option is used

        There will be no prompt of host key verificaiton during ssh
        to IPA enrolled machines if ssh-trust-dns option is used during
        ipa-client-install. This was broken for FIPS env which got fixed.
        Test checks for non-existence of param HostKeyAlgorithms in
        ssh_config after client-install.

        related: https://pagure.io/freeipa/issue/8082
        """
        tasks.install_client(self.master, self.clients[0],
                             extra_args=['--ssh-trust-dns'])
        result = self.clients[0].run_command(['cat', '/etc/ssh/ssh_config'])
        assert 'HostKeyAlgorithms' not in result.stdout_text

    def test_client_install_with_krb5(self):
        """Test that SSSD_PUBCONF_KRB5_INCLUDE_D_DIR is not added in krb5.conf

        SSSD already provides a config snippet which includes
        SSSD_PUBCONF_KRB5_INCLUDE_D_DIR, and having both breaks Java.
        Test checks that krb5.conf does not include
        SSSD_PUBCONF_KRB5_INCLUDE_D_DIR.

        related: https://pagure.io/freeipa/issue/9267
        """
        krb5_cfg = self.master.get_file_contents(paths.KRB5_CONF)
        assert 'includedir {dir}'.format(
            dir=paths.SSSD_PUBCONF_KRB5_INCLUDE_D_DIR
        ).encode() not in krb5_cfg
        tasks.uninstall_client(self.clients[0])

    def test_check_ssh_service_is_activated(self):
        """
        This test checks all default services are activated
        in sssd.conf including ssh
        """
        tasks.install_client(self.master, self.clients[0])
        sssd_cfg = self.clients[0].get_file_contents(paths.SSSD_CONF)
        assert 'services = nss, pam, ssh, sudo' in sssd_cfg.decode()
        tasks.uninstall_client(self.clients[0])

    def test_install_with_automount(self):
        """Test that installation with automount is successful"""
        tasks.install_client(self.master, self.clients[0],
                             extra_args=['--automount-location', 'default'])

    def test_uninstall_with_automount(self):
        """Test that uninstall with automount is successful and complete"""
        tasks.uninstall_client(self.clients[0])
        index = os.path.join(
            paths.IPA_CLIENT_SYSRESTORE, SYSRESTORE_INDEXFILE
        )
        state = os.path.join(
            paths.IPA_CLIENT_SYSRESTORE, SYSRESTORE_STATEFILE
        )
        for filepath in (index, state):
            try:
                self.clients[0].get_file_contents(filepath)
            except IOError:
                pass
            else:
                pytest.fail("The client file %s was not removed" % filepath)


class TestClientInstallBind(IntegrationTest):
    """
    The test configures an external bind server on the ipa-server
    (not the IPA-embedded DNS server) that allows unauthenticated nsupdates.
    When the IPA client is registered using ipa-client-install,
    DNS records are added for the client in the bind server using nsupdate.
    The first try is using GSS-TIG but fails as expected, and the client
    installer then tries with unauthenticated nsupdate.
    """

    num_clients = 1

    @classmethod
    def install(cls, mh):
        cls.client = cls.clients[0]

    @pytest.fixture
    def setup_bindserver(self):
        bindserver = self.master
        named_conf_backup = tasks.FileBackup(self.master, paths.NAMED_CONF)
        # create a zone in the BIND server that is identical to the IPA
        add_zone = textwrap.dedent("""
        zone "{domain}" IN {{ type master;
        file "{domain}.db"; allow-query {{ any; }};
        allow-update {{ any; }}; }};
        """).format(domain=bindserver.domain.name)

        namedcfg = bindserver.get_file_contents(
            paths.NAMED_CONF, encoding='utf-8')
        namedcfg += '\n' + add_zone
        bindserver.put_file_contents(paths.NAMED_CONF, namedcfg)

        def update_contents(path, pattern, replace):
            contents = bindserver.get_file_contents(path, encoding='utf-8')
            namedcfg_query = re.sub(pattern, replace, contents)
            bindserver.put_file_contents(path, namedcfg_query)

        update_contents(paths.NAMED_CONF, 'localhost;', 'any;')
        update_contents(paths.NAMED_CONF, "listen-on port 53 { 127.0.0.1; };",
                        "#listen-on port 53 { 127.0.0.1; };")
        update_contents(paths.NAMED_CONF, "listen-on-v6 port 53 { ::1; };",
                        "#listen-on-v6 port 53 { ::1; };")

        add_records = textwrap.dedent("""
        @   IN  SOA     {fqdn}. root.{domain}. (
        1001    ;Serial
        3H      ;Refresh
        15M     ;Retry
        1W      ;Expire
        1D      ;Minimum 1D
        )
        @      IN  NS      {fqdn}.
        ns1 IN  A       {bindserverip}
        _kerberos.{domain}. IN TXT {zoneupper}
        {fqdn}.    IN  A       {bindserverip}
        ipa-ca.{domain}.        IN  A       {bindserverip}
        _kerberos-master._tcp.{domain}. IN SRV 0 100 88 {fqdn}.
        _kerberos-master._udp.{domain}. IN SRV 0 100 88 {fqdn}.
        _kerberos._tcp.{domain}. 	IN SRV 0 100 88 {fqdn}.
        _kerberos._udp.{domain}. 	IN SRV 0 100 88 {fqdn}.
        _kpasswd._tcp.{domain}. 	IN SRV 0 100 464 {fqdn}.
        _kpasswd._udp.{domain}. 	IN SRV 0 100 464 {fqdn}.
        _ldap._tcp.{domain}. 		IN SRV 0 100 389 {fqdn}.
        """).format(
            fqdn=bindserver.hostname,
            domain=bindserver.domain.name,
            bindserverip=bindserver.ip,
            zoneupper=bindserver.domain.name.upper()
        )
        bindserverdb = "/var/named/{0}.db".format(bindserver.domain.name)
        bindserver.put_file_contents(bindserverdb, add_records)
        bindserver.run_command(['systemctl', 'start', 'named'])
        Firewall(bindserver).enable_services(["dns"])
        yield
        named_conf_backup.restore()
        bindserver.run_command(['rm', '-rf', bindserverdb])

    def test_client_nsupdate(self, setup_bindserver):
        """Test secure nsupdate failed, then try unsecure nsupdate..

        Test to verify when bind is configured with dynamic update policy,
        and during client-install 'nsupdate -g' fails then it should run with
        second call using unauthenticated nsupdate.

        Related : https://pagure.io/freeipa/issue/8402
        """
        # with pre-configured bind server, install ipa-server without dns.
        tasks.install_master(self.master, setup_dns=False)
        self.client.resolver.backup()
        self.client.resolver.setup_resolver(
            self.master.ip, self.master.domain.name)
        try:
            self.client.run_command(['ipa-client-install', '-U',
                                     '--domain', self.client.domain.name,
                                     '--realm', self.client.domain.realm,
                                     '-p', self.client.config.admin_name,
                                     '-w', self.client.config.admin_password,
                                     '--server', self.master.hostname])
            # call unauthenticated nsupdate if GSS-TSIG nsupdate failed.
            str1 = "nsupdate (GSS-TSIG) failed"
            str2 = "'/usr/bin/nsupdate', '/etc/ipa/.dns_update.txt'"
            client_log = self.client.get_file_contents(
                paths.IPACLIENT_INSTALL_LOG, encoding='utf-8'
            )
            assert str1 in client_log and str2 in client_log
            dig_after = self.client.run_command(
                ['dig', '@{0}'.format(self.master.ip), self.client.hostname,
                 '-t', 'SSHFP'])
            assert "ANSWER: 0" not in dig_after.stdout_text.strip()
        finally:
            self.client.resolver.restore()
