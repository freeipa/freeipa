#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for various options of ipa-client-install.
"""

from __future__ import absolute_import

import pytest
import re
import shlex
import textwrap

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.test_integration.test_authselect import (check_authselect_profile,
                                                       default_profile)


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
        try:
            tasks.install_client(self.master, self.clients[0],
                                 extra_args=['--ssh-trust-dns'])
            result = self.clients[0].run_command(['cat', '/etc/ssh/ssh_config'])
            assert 'HostKeyAlgorithms' not in result.stdout_text
        finally:
            tasks.uninstall_client(self.clients[0])


class TestClientInstallParams(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_client_install_sssd_params(self):
        """
        --permit
        Configure  SSSD  to  permit all access.
        Otherwise, the machine will be controlled
        by the Host-based Access Controls (HBAC) on the IPA server.
        """
        client = self.clients[0]
        tasks.install_client(self.master, client,
                             extra_args=['--permit',
                                         '--enable-dns-updates',
                                         '--no-krb5-offline-passwords'])
        try:
            sssd_conf = client.transport.get_file_contents(paths.SSSD_CONF,
                                                           encoding='utf-8')
            exp_val_permit = "access_provider = permit"
            assert exp_val_permit in sssd_conf

            """
            --enable-dns-updates
            This option tells SSSD to automatically update DNS with
            the  IP  address  of  this client.
            """
            exp_val_dyndns_update = "dyndns_update = True"
            assert exp_val_dyndns_update in sssd_conf

            """
            --no-krb5-offline-passwords
            Configure SSSD not to store user
            password when the server is offline.
            """
            unexp_val_krb5_pass = "krb5_store_password_if_offline = True"
            assert unexp_val_krb5_pass not in sssd_conf
        finally:
            tasks.uninstall_client(client)

    def test_client_install_authconfig_params(self):
        """
        --mkhomedir
        Configure PAM to create a users home directory
        if it does not exist
        """
        client = self.clients[0]
        tasks.install_client(self.master, client,
                             extra_args=['--mkhomedir'])

        options = ('with-mkhomedir',)
        check_authselect_profile(client,
                                 default_profile,
                                 expected_options=options)

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


class TestClientInstallNegative(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_client_install_no_params(self):
        """Installation with no parameters"""
        cmd = self.clients[0].run_command("ipa-client-install -U",
                                          raiseonerr=False)
        assert cmd.returncode != 0
        exp_msg = ["password", "principal", "keytab", "required"]
        assert all(x in cmd.stderr_text.lower() for x in exp_msg)

    def test_install_invalid_domain(self):
        """Installation with invalid domain"""
        client = self.clients[0]
        cmd = client.run_command(
            "ipa-client-install "
            "--domain=xxx.xx "
            f"-p {client.config.admin_name} "
            f"-w {client.config.admin_password} "
            "-U",
            raiseonerr=False)
        assert cmd.returncode != 0
        exp_msg = "Unable to find IPA Server to join"
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_no_domain(self):
        """
        Installation with the server but without
        the required param domain specified
        """
        client = self.clients[0]
        cmd = client.run_command(
            "ipa-client-install --server=xxx",
            raiseonerr=False)
        assert cmd.returncode != 0
        exp_msg = "--server cannot be used without providing --domain"
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_invalid_server(self):
        """Installation with invalid server"""
        client = self.clients[0]
        cmd = client.run_command(
            "ipa-client-install --server=xxx --domain=xxx.xx",
            raiseonerr=False)
        assert cmd.returncode != 0
        exp_msg = "failed to verify that xxx is an ipa server"
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_invalid_hostname(self):
        cmd = tasks.install_client(
            self.master, self.clients[0],
            extra_args=['--hostname', 'nonexistent'],
            raiseonerr=False
        )
        exp_msg = "invalid hostname"
        assert cmd.returncode != 0
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_password_no_principal(self):
        cmd = self.clients[0].run_command(
            "ipa-client-install --password=random123 -U",
            raiseonerr=False)
        exp_msg = "invalid credentials"
        assert cmd.returncode != 0
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_nonexistent_principal(self):
        cmd = tasks.install_client(
            self.master, self.clients[0],
            user="nonexistentprincipal",
            raiseonerr=False
        )
        exp_msg = "not found in Kerberos database"
        assert cmd.returncode != 0
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_non_admin_principal(self):
        non_admin_user = "testuser"
        tasks.create_active_user(self.master,
                                 non_admin_user,
                                 "RandomPassword123")
        cmd = tasks.install_client(
            self.master, self.clients[0],
            user=non_admin_user,
            raiseonerr=False
        )
        exp_msg = "Password incorrect while getting initial credentials"
        assert cmd.returncode != 0
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_install_invalid_password(self):
        cmd = tasks.install_client(
            self.master, self.clients[0],
            password="incorrect+password",
            raiseonerr=False
        )
        exp_msg = "Password incorrect while getting initial credentials"
        assert cmd.returncode != 0
        assert exp_msg.lower() in cmd.stderr_text.lower()

    def test_client_force_parameter(self):
        """
        Second installation should fail except when --force
        parameter is provided
        """
        tasks.install_client(self.master, self.clients[0])

        try:
            # second installation
            exp_msg = "IPA client is already configured on this system"

            result = tasks.install_client(self.master,
                                          self.clients[0],
                                          raiseonerr=False)
            assert result.returncode != 0
            assert exp_msg.lower() in result.stderr_text.lower()

            # second installation, but with force - should still fail
            result = tasks.install_client(self.master, self.clients[0],
                                          extra_args=['--force'],
                                          raiseonerr=False)
            assert result.returncode != 0
            assert exp_msg.lower() in result.stderr_text.lower()
        finally:
            tasks.uninstall_client(self.clients[0], raiseonerr=False)

    def test_client_install_hostname_localhost(self):
        def modify_local_hostname(hostname):
            # first modify using hostnamectl
            client.run_command(['hostnamectl',
                                'set-hostname',
                                hostname],
                               raiseonerr=True)

            # then modify entry in /etc/hosts
            orig_hosts = client.get_file_contents(paths.HOSTS,
                                                  encoding='utf-8')
            new_hosts = []
            for line in orig_hosts.split('\n'):
                if client.hostname in line:
                    curr_ip = line.split(' ')[0]
                    new_hosts.append(f"{curr_ip}   {hostname}")
                else:
                    new_hosts.append(line)
            client.put_file_contents(paths.HOSTS, '\n'.join(new_hosts))

        client = self.clients[0]
        hosts_bcp = tasks.FileBackup(client, paths.HOSTS)
        exp_msg = "Invalid hostname"

        try:
            modify_local_hostname('localhost.localdomain')
            # client_install method fixes the hostname,
            # so we cannot use it here
            client_install_command = ['ipa-client-install', '-U',
                                      '--domain', client.domain.name,
                                      '--realm', client.domain.realm,
                                      '-p', client.config.admin_name,
                                      '-w', client.config.admin_password,
                                      '--server', self.master.hostname]
            result = client.run_command(client_install_command,
                                        raiseonerr=False)
            assert result.returncode != 0
            assert exp_msg.lower() in result.stderr_text.lower()

            modify_local_hostname('localhost')
            result = client.run_command(client_install_command,
                                        raiseonerr=False)
            assert result.returncode != 0
            assert exp_msg.lower() in result.stderr_text.lower()
        finally:
            hosts_bcp.restore()


class TestClientInstallReplica(IntegrationTest):
    num_clients = 1
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)

    def test_client_install_join_replica(self):
        try:
            result = tasks.install_client(self.replicas[0], self.clients[0])
            assert result.returncode == 0
        finally:
            # now uninstall
            tasks.uninstall_client(self.clients[0], raiseonerr=True)

    def test_client_install_replica_with_master_down(self):
        self.master.run_command(['ipactl', 'stop'], raiseonerr=True)
        try:
            result = tasks.install_client(self.replicas[0], self.clients[0])
            assert result.returncode == 0
            tasks.uninstall_client(self.clients[0], raiseonerr=True)
        finally:
            self.master.run_command(['ipactl', 'start'], raiseonerr=True)
