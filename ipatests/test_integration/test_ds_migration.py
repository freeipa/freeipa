#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

"""
ipa-migrate-ds migration acceptance tests.
"""

from __future__ import absolute_import

import os
import textwrap

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# 389-ds instance name and base DN on the client
DS_INSTANCE_NAME = "dsinstance_01"
DS_BASEDN = "dc=testrealm,dc=test"
DS_PORT = 389
DS_SECURE_PORT = 636


def _setup_389ds_on_client(client, admin_password):
    """
    Install 389 Directory Server on the client and load migration
    test data from instance1.ldif i.e (ou=People, ou=groups,
    sample user/group).
    """
    tasks.install_packages(client, ["389-ds-base"])

    # Create instance via dscreate
    inf_content = textwrap.dedent("""\
        [general]
        full_machine_name = {hostname}
        [slapd]
        instance_name = {instance}
        port = {port}
        secure_port = {secure_port}
        root_dn = cn=Directory Manager
        root_password = {password}
        [backend-userroot]
        sample_entries = no
        suffix = {basedn}
    """).format(
        hostname=client.hostname,
        instance=DS_INSTANCE_NAME,
        port=DS_PORT,
        secure_port=DS_SECURE_PORT,
        password=admin_password,
        basedn=DS_BASEDN,
    )
    client.put_file_contents("/tmp/ds-instance.inf", inf_content)
    client.run_command(
        ["dscreate", "from-file", "/tmp/ds-instance.inf"], raiseonerr=True
    )

    # Load migration test data from instance1.ldif
    test_dir = os.path.dirname(os.path.abspath(__file__))
    ldif_path = os.path.join(
        test_dir, "data", "ds_migration", "instance1.ldif"
    )
    with open(ldif_path) as f:
        ldif_content = f.read()
    # Ensure content ends with newline so /tmp/instance1.ldif is valid
    if ldif_content and not ldif_content.endswith("\n"):
        ldif_content = ldif_content + "\n"
    client.put_file_contents("/tmp/instance1.ldif", ldif_content)
    client.run_command(
        [
            "/usr/bin/ldapmodify",
            "-a", "-x", "-h", "localhost", "-p", str(DS_PORT),
            "-D", "cn=Directory Manager", "-w", admin_password,
            "-f", "/tmp/instance1.ldif",
        ],
        raiseonerr=True,
    )


class TestDSMigrationConfig(IntegrationTest):
    """
    Test ipa migrate-ds related scenarios.

    Uses a client host with 389-ds populated from instance1.ldif
    (ou=People, ou=groups, dc=testrealm,dc=test) for migration tests.
    """

    topology = "line"
    num_replicas = 0
    num_clients = 1

    @classmethod
    def install(cls, mh):
        # Install master and IPA client (full topology)
        super(TestDSMigrationConfig, cls).install(mh)
        # On the client host, set up 389-ds with migration test data
        _setup_389ds_on_client(
            cls.clients[0],
            cls.master.config.admin_password,
        )

    def test_attempt_migration_with_configuration_false(self):
        """
        Test attempts ipa-migrate-ds with migration disabled.
        """
        tasks.kinit_admin(self.master)
        # Ensure migration is disabled
        self.master.run_command(
            ["ipa", "config-mod", "--enable-migration", "FALSE"],
            raiseonerr=True,
        )
        client_host = self.clients[0].hostname
        ldap_uri = "ldap://{}:{}".format(client_host, DS_PORT)
        result = self.master.run_command(
            [
                "ipa",
                "migrate-ds",
                "--user-container=ou=People",
                "--group-container=ou=groups",
                ldap_uri,
            ],
            stdin_text=self.master.config.admin_password,
            raiseonerr=False,
        )
        assert (
            result.returncode != 0
        ), "migrate-ds should fail when migration is disabled"
        err_lower = (result.stdout_text + result.stderr_text).lower()
        assert (
            "migration" in err_lower and "disabled" in err_lower
        ), "Expected 'migration' and 'disabled' in output, got: %s" % (
            result.stdout_text + result.stderr_text
        )

    def test_migration_over_ldaps(self):
        """
        Migrate from the client's 389-ds over LDAPS (port 636).
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "config-mod", "--enable-migration", "TRUE"],
            raiseonerr=True,
        )

        # Copy 389-ds CA cert from client to master for LDAPS verification
        client = self.clients[0]
        ds_cert_dir = "/etc/dirsrv/slapd-{}".format(DS_INSTANCE_NAME)
        cert_result = client.run_command(
            [
                "certutil", "-d", ds_cert_dir, "-L", "-n",
                "Self-Signed-CA", "-a",
            ],
            raiseonerr=True,
        )
        self.master.put_file_contents(
            "/etc/ipa/remoteds.crt", cert_result.stdout_text
        )
        self.master.run_command(
            ["restorecon", "/etc/ipa/remoteds.crt"], raiseonerr=False
        )

        client_host = client.hostname
        ldaps_uri = "ldaps://{}:{}".format(client_host, DS_SECURE_PORT)
        user_container = "ou=People,{}".format(DS_BASEDN)
        group_container = "ou=groups,{}".format(DS_BASEDN)
        ca_cert_file = "/etc/ipa/remoteds.crt"

        result = self.master.run_command(
            [
                "ipa",
                "migrate-ds",
                "--with-compat",
                "--user-container",
                user_container,
                "--group-container",
                group_container,
                ldaps_uri,
                "--ca-cert-file",
                ca_cert_file,
            ],
            stdin_text=self.master.config.admin_password,
            raiseonerr=True,
        )
        assert result.returncode == 0, (
            "migrate-ds over LDAPS should succeed: %s" % result.stderr_text
        )

        # Verify migrated user and group from instance1.ldif
        self.master.run_command(
            ["ipa", "user-show", "ldapuser_0001"], raiseonerr=True
        )
        self.master.run_command(
            ["ipa", "group-show", "ldapgroup_0001"], raiseonerr=True
        )

        # Clean up migrated user and group
        self.master.run_command(
            ["ipa", "user-del", "ldapuser_0001"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "ldapgroup_0001"], raiseonerr=False
        )
