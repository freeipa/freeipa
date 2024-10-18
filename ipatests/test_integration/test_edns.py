#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#
"""This covers tests for DNS over TLS related feature"""

from __future__ import absolute_import
import textwrap

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.firewall import Firewall


def pre_enable_dnsovertls(host, master_ip):
    # Pre-enable eDNS in the specified host prior to
    # server/client install, using systemd-resolved
    host.run_command(["ln", "-sf",
                      "/run/systemd/resolve/stub-resolv.conf",
                      "/etc/resolv.conf"])
    host.run_command(["systemctl", "restart", "systemd-resolved"])
    host.run_command(["systemd-resolve", "--set-dns={}".format(master_ip),
                      "--set-dnsovertls=yes", "--interface=eth0"])


class TestDNSOverTLS(IntegrationTest):
    """Tests for DNS over TLS feature."""

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        Firewall(cls.master).enable_service("dns-over-tls")
        Firewall(cls.replicas[0]).enable_service("dns-over-tls")

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

    def test_install_dnsovertls_master(self):
        """
        This tests installs IPA server with --dns-over-tls option.
        """
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
        ]
        return tasks.install_master(self.master, extra_args=args)

    def test_install_dnsovertls_client(self):
        """
        This tests installs IPA client with --dns-over-tls option.
        """
        pre_enable_dnsovertls(self.clients[0], self.master.ip)
        args = [
            "--dns-over-tls"
        ]
        return tasks.install_client(self.master,
                                    self.clients[0], extra_args=args)

    def test_install_dnsovertls_replica(self):
        """
        This tests installs IPA replica with --dns-over-tls option.
        """
        pre_enable_dnsovertls(self.replicas[0], self.master.ip)
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
        ]
        return tasks.install_replica(self.master, self.replicas[0],
                                     setup_dns=True, extra_args=args)

    def test_queries_encrypted(self):
        """
        This test performs queries from each of the hosts
        and ensures they were routed to 1.1.1.1#853 (eDNS).
        """
        unbound_log_cfg = textwrap.dedent("""
        server:
            verbosity: 3
            log-queries: yes
        """)
        # Test servers first (querying to local Unbound)
        for server in [self.master, self.replicas[0]]:
            server.put_file_contents("/etc/unbound/conf.d/log.conf",
                                     unbound_log_cfg)
            server.run_command(["systemctl", "restart", "unbound"])
            server.run_command(["journalctl", "--flush", "--rotate",
                                "--vacuum-time=1s"])
            server.run_command(["dig", "freeipa.org"])
            server.run_command(["journalctl", "-u", "unbound",
                                "--grep=1.1.1.1#853"])
            server.run_command(["journalctl", "--flush", "--rotate",
                                "--vacuum-time=1s"])
        # Now, test the client (redirects query to master)
        self.clients[0].run_command(["dig", "redhat.com"])
        self.master.run_command(["journalctl", "-u", "unbound",
                                 "--grep=1.1.1.1#853"])

    def test_uninstall_all(self):
        """
        This test ensures that all hosts can be uninstalled correctly.
        """
        self.clients[0].run_command(["ipa-client-install",
                                     "--uninstall", "-U"])
        self.replicas[0].run_command(["ipa-server-install",
                                      "--uninstall", "-U"])
        self.master.run_command(["ipa-server-install", "--uninstall", "-U"])

    def test_install_dnsovertls_master_external_ca(self):
        """
        This test ensures that IPA server can be installed
        with DoT using an external CA.
        """
        self.master.run_command(["openssl", "req", "-newkey", "rsa:2048",
                                 "-nodes", "-keyout",
                                 "/etc/pki/tls/certs/privkey.pem", "-x509",
                                 "-days", "36500", "-out",
                                 "/etc/pki/tls/certs/certificate.pem", "-subj",
                                 ("/C=ES/ST=Andalucia/L=Sevilla/O=CompanyName/"
                                  "OU=IT/CN={}/"
                                  "emailAddress=email@example.com")
                                 .format(self.master.hostname)])
        self.master.run_command(["chown", "named:named",
                                 "/etc/pki/tls/certs/privkey.pem",
                                 "/etc/pki/tls/certs/certificate.pem"])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--dns-over-tls-cert", "/etc/pki/tls/certs/certificate.pem",
            "--dns-over-tls-key", "/etc/pki/tls/certs/privkey.pem"
        ]
        return tasks.install_master(self.master, extra_args=args)

    def test_enrollments_external_ca(self):
        """
        Test that replicas and clients can be deployed when the master
        uses an external CA.
        """
        tasks.copy_files(self.master, self.clients[0],
                         ["/etc/pki/tls/certs/certificate.pem"])
        self.clients[0].run_command(["mv",
                                     "/etc/pki/tls/certs/certificate.pem",
                                     "/etc/pki/ca-trust/source/anchors/"])
        self.clients[0].run_command(["update-ca-trust", "extract"])
        self.test_install_dnsovertls_client()
        self.test_install_dnsovertls_replica()
        self.test_queries_encrypted()
