#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#
"""This covers tests for DNS over TLS related feature"""

from __future__ import absolute_import
import pytest
import textwrap
import os
from ipatests.test_integration.test_caless import ExternalCA
from cryptography.hazmat.primitives import serialization
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_dns import TestDNS
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths


def apply_enforced_dns_preconfig(host, master_ip, master_host,
                                 ca_cert_path, dest_cert_name):
    """
    Apply pre-configurations required for enforced
    DNS policy on client and replica.

    Args:
        host: The host object (client or replica) to configure
        master_ip: IP address of the IPA server/master
        master_host: The master host object to get certificate from
        ca_cert_path: Path to the CA certificate on the master
        dest_cert_name: Destination certificate filename in trust anchors
    """
    # Get the network interface for routing
    iface_cmd = host.run_command([
        "bash", "-c",
        "nmcli -t -f DEVICE c show --active | head -1"
    ])
    iface = iface_cmd.stdout_text.strip()

    # Copy CA certificate to trust anchors using file operations
    ca_cert_data = master_host.get_file_contents(ca_cert_path)
    dest_ca_path = f"/etc/pki/ca-trust/source/anchors/{dest_cert_name}"
    host.put_file_contents(dest_ca_path, ca_cert_data)
    host.run_command(["update-ca-trust", "extract"])

    if osinfo.id in ['rhel', 'centos']:
        # RHEL/CentOS configuration
        # Install and configure dnsconfd
        tasks.install_packages(host, ['dnsconfd'])
        host.run_command(["dnsconfd", "config", "install"])
        host.run_command(["systemctl", "enable", "--now", "dnsconfd"])
        host.run_command(["nmcli", "g", "reload"])

        # Configure DNS over TLS via NetworkManager
        host.run_command([
            "nmcli", "device", "modify", iface,
            "ipv4.dns", f"dns+tls://{master_ip}"
        ])

    elif osinfo.id == 'fedora':
        # Fedora configuration
        # Configure systemd-resolved for DNS over TLS
        host.run_command([
            "ln", "-sf", "../run/systemd/resolve/stub-resolv.conf",
            "/etc/resolv.conf"
        ])
        host.run_command(["systemctl", "restart", "systemd-resolved"])

        # Configure DNS over TLS via systemd-resolve
        host.run_command([
            "systemd-resolve", "--set-dns", master_ip,
            "--set-dnsovertls=yes", f"--interface={iface}"
        ])
    else:
        raise ValueError(
            f"Unsupported OS for enforced DNS policy: {osinfo.id}"
        )


def setup_dns_over_tls_environment(cls):
    """
    Setup DNS over TLS environment for test classes.

    Args:
        cls: The test class with master, replicas, and clients attributes
    """
    # Configuration: (host, setup_firewall, install_package)
    hosts_config = [
        (cls.master, True, True),
        (cls.replicas[0], True, True),
        (cls.clients[0], False, True),
    ]

    for host, setup_firewall, install_package in hosts_config:
        # Setup firewall if requested
        if setup_firewall:
            Firewall(host).enable_service("dns-over-tls")
        # Install appropriate package based on host type
        if install_package:
            # Detect if client or server based on hostname
            if 'client' in host.hostname.lower():
                package = '*ipa-client-encrypted-dns'
            else:
                package = '*ipa-server-encrypted-dns'
            tasks.install_packages(host, [package])


def verify_queries_encrypted(master, replicas, clients,
                             forwarder="1.1.1.1#853",
                             dns_hostname="freeipa.org"):
    """
    Helper function to verify that queries are encrypted and
    routed to the specified forwarder.
    """
    unbound_log_cfg = textwrap.dedent("""
    server:
        verbosity: 3
        log-queries: yes
        cache-min-ttl: 0
        cache-max-ttl: 0
    """)

    for server in [master] + replicas:
        server.put_file_contents(
            os.path.join(paths.UNBOUND_CONFIG_DIR, "log.conf"),
            unbound_log_cfg,
        )
        server.run_command(["systemctl", "restart", "unbound"])
        server.run_command(
            ["journalctl", "--flush", "--rotate", "--vacuum-time=1s"]
        )
        server.run_command(["dig", dns_hostname])
        log_output = server.run_command(
            ["journalctl", "-u", "unbound", "--grep", forwarder]
        )
        assert forwarder in log_output.stdout_text, (
            f"Forwarder {forwarder} not found in logs on "
            f"{server.hostname}"
        )
        server.run_command(
            ["journalctl", "--flush", "--rotate", "--vacuum-time=1s"]
        )

    for client in clients:
        client.run_command(["dig", dns_hostname])
        log_output = master.run_command(
            ["journalctl", "-u", "unbound", "--grep", forwarder]
        )

        assert forwarder in log_output.stdout_text, (
            f"Forwarder {forwarder} not found in logs on master for "
            f"client {client.hostname}"
        )


@pytest.mark.skipif(
    osinfo.id == 'fedora' and osinfo.version_number == (41,),
    reason='Encrypted DNS not supported in fedora 41')
class TestDNSOverTLS(IntegrationTest):
    """Tests for DNS over TLS feature."""

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        setup_dns_over_tls_environment(cls)

    def test_install_dnsovertls_invalid_ca(self):
        """
        This test checks that the installers throws an error
        when invalid cert is specified.
        """
        bad_ca_cnf = textwrap.dedent("""
        [ req ]
        x509_extensions = v3_ca
        [ v3_ca ]
        basicConstraints = critical,CA:false
        """)
        self.master.put_file_contents("/bad_ca.cnf", bad_ca_cnf)
        self.master.run_command(["openssl", "req", "-newkey", "rsa:2048",
                                 "-nodes", "-keyout",
                                 "/etc/pki/tls/certs/privkey-invalid.pem",
                                 "-x509", "-days", "36500", "-out",
                                 "/etc/pki/tls/certs/certificate-invalid.pem",
                                 "-subj",
                                 ("/C=ES/ST=Andalucia/L=Sevilla/O=CompanyName/"
                                  "OU=IT/CN=www.example.com/"
                                  "emailAddress=email@example.com"),
                                 "-config", "/bad_ca.cnf"])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--dns-over-tls-cert",
            "/etc/pki/tls/certs/certificate-invalid.pem",
            "--dns-over-tls-key",
            "/etc/pki/tls/certs/privkey-invalid.pem"
        ]
        res = tasks.install_master(self.master, extra_args=args,
                                   raiseonerr=False)
        assert "Not a valid CA certificate: " in res.stderr_text
        tasks.uninstall_master(self.master)

    def test_install_dnsovertls_without_setup_dns_master(self):
        """
        This test installs an IPA server using the --dns-over-tls option
        without using setup-dns option, and captures warnings that appear.
        """
        self.master.run_command(["ipa-server-install", "--uninstall", "-U"])
        args = [
            "--dns-over-tls",
        ]
        res = tasks.install_master(
            self.master, extra_args=args, setup_dns=False)
        assert ("Warning: --dns-over-tls option specified without "
                "--setup-dns, ignoring") in res.stdout_text
        tasks.uninstall_master(self.master)

    def test_install_dnsovertls_with_invalid_ipaddress_master(self):
        """
        This test installs an IPA server using the --dns-over-tls
        option with an invalid IP address.
        """
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "198.168.0.0.1#example-dns.test",
        ]
        res = tasks.install_master(self.master, extra_args=args,
                                   raiseonerr=False)
        assert ("--dot-forwarder invalid: DoT forwarder must be in "
                "the format of '1.2.3.4#dns.example.test'") in res.stderr_text
        tasks.uninstall_master(self.master)

    def test_validate_DoT_options_master(self):
        """
        Tests that DoT options are displayed correctly on master.
        """
        cmdout = self.master.run_command(
            ['ipa-server-install', '--help'])
        assert '''--dot-forwarder=DOT_FORWARDERS
                        Add a DNS over TLS forwarder. This option can be used
                        multiple times''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls-cert=DNS_OVER_TLS_CERT
                        Certificate to use for DNS over TLS. If empty, a new
                        certificate will be requested from IPA CA''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls-key=DNS_OVER_TLS_KEY
                        Key for certificate specified in --dns-over-tls-cert''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls      Configure DNS over TLS''' in cmdout.stdout_text  # noqa: E501

    def test_validate_DoT_options_replica(self):
        """
        Tests that DoT options are displayed correctly on replica.
        """
        cmdout = self.replicas[0].run_command(
            ['ipa-server-install', '--help'])
        assert '''--dot-forwarder=DOT_FORWARDERS
                        Add a DNS over TLS forwarder. This option can be used
                        multiple times''' in cmdout.stdout_text
        assert '''--dns-over-tls-cert=DNS_OVER_TLS_CERT
                        Certificate to use for DNS over TLS. If empty, a new
                        certificate will be requested from IPA CA''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls-key=DNS_OVER_TLS_KEY
                        Key for certificate specified in --dns-over-tls-cert''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls      Configure DNS over TLS''' in cmdout.stdout_text  # noqa: E501

    def test_validate_DoT_options_client(self):
        """
        Tests that DoT options are displayed correctly on client.
        """
        cmdout = self.clients[0].run_command(
            ['ipa-client-install', '--help'])
        assert '''--dns-over-tls      Configure DNS over TLS''' in cmdout.stdout_text  # noqa: E501


@pytest.mark.skipif(
    osinfo.id == 'fedora' and osinfo.version_number < (42,),
    reason='Encrypted DNS not supported in Fedora < 42')
class TestDNSOverTLS_RelaxedPolicy(IntegrationTest):
    """Tests for DNS over TLS feature."""

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        setup_dns_over_tls_environment(cls)

    def test_dot_relaxed_dns_policy_with_IPA_CA(self):
        """
        This test installs IPA server, replica, and client with
        --no-dnssec-validation option, relaxed DNS policy, and
        with IPA CA, ensuring all queries are encrypted.
        """
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--no-dnssec-validation",
            "--dns-policy", "relaxed"
        ]
        tasks.install_master(self.master, extra_args=args)

        self.clients[0].put_file_contents(
            paths.RESOLV_CONF,
            "nameserver %s" % self.master.ip
        )
        args = [
            "--dns-over-tls",
            "--no-dnssec-validation"
        ]
        tasks.install_client(
            self.master,
            self.clients[0],
            nameservers=None,
            extra_args=args
        )

        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--no-dnssec-validation",
            "--dns-policy", "relaxed"
        ]
        tasks.install_replica(
            self.master,
            self.replicas[0],
            setup_dns=True,
            extra_args=args
        )
        verify_queries_encrypted(
            self.master,
            [self.replicas[0]],
            [self.clients[0]]
        )

    def test_uninstall_all(self):
        """
        This test ensures that all hosts can be uninstalled correctly.
        """
        tasks.uninstall_client(self.clients[0])
        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.uninstall_master(self.master)

    def test_dot_relaxed_dns_policy_with_external_ca(self):
        """
        This test installs IPA server, replica, and client with
        --no-dnssec-validation option, relaxed DNS policy, and
        with external CA, ensuring all queries are encrypted.
        """
        # Install Master with external CA
        # Create external CA cert + key.
        external_ca = ExternalCA(days=36500)
        cert_pem = external_ca.create_ca()
        key_pem = external_ca.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_dest = "/etc/pki/tls/certs/certificate.pem"
        key_dest = "/etc/pki/tls/certs/privkey.pem"

        self.master.put_file_contents(cert_dest, cert_pem)
        self.master.put_file_contents(key_dest, key_pem)

        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--dns-over-tls-cert", cert_dest,
            "--dns-over-tls-key", key_dest,
            "--no-dnssec-validation",
            "--dns-policy", "relaxed"
        ]
        tasks.install_master(self.master, extra_args=args)

        # Install Client with external CA
        self.clients[0].put_file_contents(
            paths.RESOLV_CONF,
            "nameserver %s" % self.master.ip
        )
        dest_file = "/etc/pki/ca-trust/source/anchors/certificate.pem"
        data = self.master.get_file_contents(cert_dest)
        self.clients[0].transport.put_file_contents(dest_file, data)
        self.clients[0].run_command(["update-ca-trust", "extract"])

        args = [
            "--dns-over-tls",
            "--no-dnssec-validation"
        ]
        tasks.install_client(
            self.master,
            self.clients[0],
            nameservers=None,
            extra_args=args
        )

        # Install Replica with external CA
        dest_file = "/etc/pki/ca-trust/source/anchors/certificate.pem"
        data = self.master.get_file_contents(cert_dest)
        self.clients[0].transport.put_file_contents(dest_file, data)

        self.replicas[0].run_command(["update-ca-trust", "extract"])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--no-dnssec-validation",
            "--dns-policy", "relaxed"
        ]
        tasks.install_replica(
            self.master,
            self.replicas[0],
            setup_dns=True,
            extra_args=args
        )

        verify_queries_encrypted(
            self.master,
            [self.replicas[0]],
            [self.clients[0]]
        )


@pytest.mark.skipif(
    osinfo.id == 'fedora' and osinfo.version_number < (42,),
    reason='Encrypted DNS not supported in Fedora < 42')
class TestDNSOverTLS_EnforcedPolicy_IPA_CA(IntegrationTest):
    """Tests for DNS over TLS feature with enforced policy and IPA CA."""

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        setup_dns_over_tls_environment(cls)

    def test_dot_enforced_dns_policy_with_ipa_ca(self):
        """
        This test installs IPA server, replica, and client with
        --no-dnssec-validation option, enforced DNS policy, and
        with IPA CA, ensuring all queries are encrypted.
        """
        # Install master first with enforced policy
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--no-dnssec-validation",
            "--dns-policy", "enforced",
            "--ip-address", self.master.ip
        ]
        tasks.install_master(self.master, extra_args=args)

        # Apply pre-configuration on client before installation
        apply_enforced_dns_preconfig(
            self.clients[0], self.master.ip, self.master,
            paths.IPA_CA_CRT, "ca.crt"
        )

        # Configure client nameserver
        self.clients[0].put_file_contents(
            paths.RESOLV_CONF,
            "nameserver %s" % self.master.ip
        )

        # Install client with enforced policy
        args = [
            "--dns-over-tls",
            "--no-dnssec-validation",
            "--ip-address", self.clients[0].ip
        ]
        tasks.install_client(
            self.master,
            self.clients[0],
            nameservers=None,
            extra_args=args
        )

        # Apply pre-configuration on replica before installation
        apply_enforced_dns_preconfig(
            self.replicas[0], self.master.ip, self.master,
            paths.IPA_CA_CRT, "ipa-ca.crt"
        )

        # Install replica with enforced policy
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--no-dnssec-validation",
            "--dns-policy", "enforced"
        ]
        tasks.install_replica(
            self.master,
            self.replicas[0],
            setup_dns=True,
            extra_args=args
        )

        # Verify that queries are encrypted
        verify_queries_encrypted(
            self.master,
            [self.replicas[0]],
            [self.clients[0]]
        )

    def test_uninstall_all_enforced_ipa_ca(self):
        """
        This test ensures that all hosts can be uninstalled correctly.
        """
        tasks.uninstall_client(self.clients[0])
        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.uninstall_master(self.master)


@pytest.mark.skipif(
    osinfo.id == 'fedora' and osinfo.version_number < (42,),
    reason='Encrypted DNS not supported in Fedora < 42')
class TestDNSOverTLS_EnforcedPolicy_External_CA(IntegrationTest):
    """Tests for DNS over TLS feature with enforced policy and external CA."""

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        setup_dns_over_tls_environment(cls)

    def test_dot_enforced_dns_policy_with_external_ca(self):
        """
        This test installs IPA server, replica, and client with
        --no-dnssec-validation option, enforced DNS policy, and
        with external CA, ensuring all queries are encrypted.
        """
        # Create external CA cert + key
        external_ca = ExternalCA(days=36500)
        cert_pem = external_ca.create_ca()
        key_pem = external_ca.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_dest = "/etc/pki/tls/certs/certificate.pem"
        key_dest = "/etc/pki/tls/certs/privkey.pem"

        self.master.put_file_contents(cert_dest, cert_pem)
        self.master.put_file_contents(key_dest, key_pem)

        # Install master with external CA and enforced policy
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--dns-over-tls-cert", cert_dest,
            "--dns-over-tls-key", key_dest,
            "--no-dnssec-validation",
            "--dns-policy", "enforced",
            "--ip-address", self.master.ip
        ]
        tasks.install_master(self.master, extra_args=args)

        # Apply pre-configuration on client before installation
        # (includes CA cert setup)
        apply_enforced_dns_preconfig(
            self.clients[0], self.master.ip, self.master,
            cert_dest, "certificate.pem"
        )

        # Configure client nameserver
        self.clients[0].put_file_contents(
            paths.RESOLV_CONF,
            "nameserver %s" % self.master.ip
        )

        # Install client with enforced policy
        args = [
            "--dns-over-tls",
            "--no-dnssec-validation",
            "--ip-address", self.clients[0].ip
        ]
        tasks.install_client(
            self.master,
            self.clients[0],
            nameservers=None,
            extra_args=args
        )

        # Apply pre-configuration on replica before installation
        # (includes CA cert setup)
        apply_enforced_dns_preconfig(
            self.replicas[0], self.master.ip, self.master,
            cert_dest, "certificate.pem"
        )

        # Install replica with external CA and enforced policy
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--no-dnssec-validation",
            "--dns-policy", "enforced"
        ]
        tasks.install_replica(
            self.master,
            self.replicas[0],
            setup_dns=True,
            extra_args=args
        )

        # Verify that queries are encrypted
        verify_queries_encrypted(
            self.master,
            [self.replicas[0]],
            [self.clients[0]]
        )

    def test_uninstall_all_enforced_external_ca(self):
        """
        This test ensures that all hosts can be uninstalled correctly.
        """
        tasks.uninstall_client(self.clients[0])
        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.uninstall_master(self.master)


@pytest.mark.skipif(
    osinfo.id == 'fedora' and osinfo.version_number == (41,),
    reason='Encrypted DNS not supported in fedora 41')
class TestDNS_DoT(TestDNS):

    @classmethod
    def install(cls, mh):
        tasks.install_packages(cls.master, ['*ipa-server-encrypted-dns'])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com"
        ]
        tasks.install_master(cls.master, extra_args=args)

    def test_check_dot_forwarder_added_in_ipa_conf(self):
        """
        This test checks that forwarders is listed in
        dnsserver-show command and also the dot forwarder is
        added to unbound and included in
        /etc/unbound/conf.d/zzz-ipa.conf
        """
        msg = 'Forwarders: 127.0.0.55'
        cmd1 = self.master.run_command(
            ["ipa", "dnsserver-show", self.master.hostname]
        )
        assert msg in cmd1.stdout_text
        contents = self.master.get_file_contents(
            paths.UNBOUND_CONF, encoding='utf-8'
        )
        assert 'forward-addr: 1.1.1.1#cloudflare-dns.com' in contents
