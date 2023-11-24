#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for ipa-client-install with PKINIT
"""
import os

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestPkinitClientInstall(IntegrationTest):
    num_clients = 1

    certfile = "/etc/pki/tls/certs/client.pem"
    keyfile = "/etc/pki/tls/private/client.key"
    tmpbundle = "/tmp/kdc-ca-bundle.pme"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    def enforce_password_and_otp(self):
        """enforce otp by default and password for admin """
        self.master.run_command(
            [
                "ipa",
                "config-mod",
                "--user-auth-type=otp",
            ]
        )
        self.master.run_command(
            [
                "ipa",
                "user-mod",
                "admin",
                "--user-auth-type=password",
            ]
        )

    def add_certmaperule(self):
        """add certmap rule to map SAN dNSName to host entry"""
        self.master.run_command(
            [
                "ipa",
                "certmaprule-add",
                "pkinit-host",
                "--matchrule=<ISSUER>CN=Certificate Authority,.*",
                "--maprule=(fqdn={subject_dns_name})",
            ]
        )

    def add_host(self):
        """Add host entry for client

        Allow master to manage client so it can create a certificate.
        """
        client = self.clients[0]
        self.master.run_command(
            ["ipa", "host-add", "--force", client.hostname]
        )
        self.master.run_command(
            [
                "ipa",
                "host-add-managedby",
                f"--hosts={self.master.hostname}",
                client.hostname,
            ]
        )

    def create_cert(self):
        """Create and copy certificate for client"""
        client = self.clients[0]
        self.master.run_command(
            [
                "mkdir",
                "-p",
                os.path.dirname(self.certfile),
                os.path.dirname(self.keyfile),
            ]
        )
        self.master.run_command(
            [
                "ipa-getcert",
                "request",
                "-w",
                # fmt: off
                "-f", self.certfile,
                "-k", self.keyfile,
                "-N", client.hostname,
                "-D", client.hostname,
                "-K", f"host/{client.hostname}",
                # fmt: on
            ]
        )
        # copy cert, key, and bundle to client
        for filename in (self.certfile, self.keyfile):
            data = self.master.get_file_contents(filename)
            client.put_file_contents(filename, data)

        cabundle = self.master.get_file_contents(paths.KDC_CA_BUNDLE_PEM)
        client.put_file_contents(self.tmpbundle, cabundle)

    def test_restart_krb5kdc(self):
        tasks.kinit_admin(self.master)
        self.enforce_password_and_otp()
        self.master.run_command(['systemctl', 'stop', 'krb5kdc.service'])
        self.master.run_command(['systemctl', 'start', 'krb5kdc.service'])
        self.master.run_command(['systemctl', 'stop', 'kadmin.service'])
        self.master.run_command(['systemctl', 'start', 'kadmin.service'])

    def test_client_install_pkinit(self):
        tasks.kinit_admin(self.master)
        self.add_certmaperule()
        self.add_host()
        self.create_cert()

        tasks.install_client(
            self.master,
            self.clients[0],
            pkinit_identity=f"FILE:{self.certfile},{self.keyfile}",
            extra_args=[f"--pkinit-anchor=FILE:{self.tmpbundle}"],
        )
