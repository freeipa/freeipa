#
# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
#

"""
ipa-migrate-ds migration acceptance tests.
"""

from __future__ import absolute_import

import os
import textwrap
import time

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
        ["dscreate", "from-file", "/tmp/ds-instance.inf"]
    )

    # Load migration test data from instance1.ldif
    test_dir = os.path.dirname(os.path.abspath(__file__))
    ldif_path = os.path.join(
        test_dir, "data", "ds_migration", "instance1.ldif"
    )
    with open(ldif_path) as f:
        ldif_content = f.read()
    client.put_file_contents("/tmp/instance1.ldif", ldif_content)
    client.run_command(
        [
            "/usr/bin/ldapmodify",
            "-a", "-x", "-H", "ldap://localhost:{}".format(DS_PORT),
            "-D", "cn=Directory Manager", "-w", admin_password,
            "-f", "/tmp/instance1.ldif",
        ]
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

    MIGRATED_USERS = [
        "ldapuser_0001", "mgr_user", "user_with_mgr",
        "posixuser_no_privgrp",
    ]
    MIGRATED_GROUPS = [
        "ldapgroup_0001", "dupgid_group",
        "HR Managers", "Directory Administrators",
    ]

    @classmethod
    def install(cls, mh):
        # Install master and IPA client (full topology)
        super(TestDSMigrationConfig, cls).install(mh)
        # On the client host, set up 389-ds with migration test data
        _setup_389ds_on_client(
            cls.clients[0],
            cls.master.config.admin_password,
        )
        cls.ldap_uri = "ldap://{}:{}".format(
            cls.clients[0].hostname, DS_PORT
        )
        # RHEL IdM LDAP migration procedure:
        # Disable schema compat.
        # Restart Directory Server before migrate-ds.
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa-compat-manage", "disable"],
            stdin_text=cls.master.config.admin_password,
        )
        tasks.service_control_dirsrv(cls.master, "restart")

    def cleanup_migrated_data(self, extra_users=None, extra_groups=None):
        """Remove all users and groups that migrate-ds may have created."""
        users = list(self.MIGRATED_USERS)
        if extra_users:
            users.extend(extra_users)
        for user in users:
            self.master.run_command(
                ["ipa", "user-del", user], raiseonerr=False
            )
        groups = list(self.MIGRATED_GROUPS)
        if extra_groups:
            groups.extend(extra_groups)
        for group in groups:
            self.master.run_command(
                ["ipa", "group-del", group], raiseonerr=False
            )

    def test_attempt_migration_with_configuration_false(self):
        """
        Test attempts ipa-migrate-ds with migration disabled.
        """
        tasks.kinit_admin(self.master)
        # Ensure migration is disabled
        cmd = ["ipa", "config-mod", "--enable-migration", "FALSE"]
        error_msg = "ipa: ERROR: no modifications to be performed"
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode != 0
        tasks.assert_error(result, error_msg)
        result = self.master.run_command(
            [
                "ipa",
                "migrate-ds",
                "--user-container=ou=People",
                "--group-container=ou=groups",
                self.ldap_uri,
            ],
            stdin_text=self.master.config.admin_password,
            raiseonerr=False,
        )
        assert (
            result.returncode != 0
        ), "migrate-ds should fail when migration is disabled"
        assert "migration mode is disabled" in (
            result.stdout_text + result.stderr_text
        ).lower()

    def test_migration_over_ldaps(self):
        """
        Migrate from the client's 389-ds over LDAPS (port 636).
        """
        ca_cert_file = "/etc/ipa/remoteds.crt"
        tasks.kinit_admin(self.master)
        # Ensure migration is enabled
        self.master.run_command(
            ["ipa", "config-mod", "--enable-migration", "TRUE"],
        )

        # Copy 389-ds CA cert from client to master for LDAPS verification
        client = self.clients[0]
        ds_cert_dir = "/etc/dirsrv/slapd-{}".format(DS_INSTANCE_NAME)
        cert_result = client.run_command(
            [
                "certutil", "-d", ds_cert_dir, "-L", "-n",
                "Self-Signed-CA", "-a",
            ],
        )
        self.master.put_file_contents(
            ca_cert_file, cert_result.stdout_text
        )
        self.master.run_command(
            ["restorecon", ca_cert_file], raiseonerr=False
        )

        client_host = client.hostname
        ldaps_uri = "ldaps://{}:{}".format(client_host, DS_SECURE_PORT)
        user_container = "ou=People,{}".format(DS_BASEDN)
        group_container = "ou=groups,{}".format(DS_BASEDN)

        self.master.run_command(
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
        )
        # Verify migrated user and group from instance1.ldif
        self.master.run_command(
            ["ipa", "user-show", "ldapuser_0001"]
        )
        self.master.run_command(
            ["ipa", "group-show", "ldapgroup_0001"]
        )

        self.cleanup_migrated_data()

    def test_bz804807_invalid_user_and_group_container_rdn(self):
        """
        bz804807 — Invalid RDN for user or group container must not return
        Internal Server Error.
        https://bugzilla.redhat.com/show_bug.cgi?id=804807
        """
        tasks.kinit_admin(self.master)
        # Migration is already enabled by test_migration_over_ldaps.
        pwd = self.master.config.admin_password
        base_dn = "ou=Boston,{}".format(DS_BASEDN)

        result_user = self.master.run_command(
            [
                "ipa",
                "migrate-ds",
                "--user-container",
                "BostonUsers",
                "--group-container",
                "ou=BostonGroups",
                "--base-dn",
                base_dn,
                self.ldap_uri,
            ],
            stdin_text=pwd,
            raiseonerr=False,
        )
        out_user = result_user.stdout_text + result_user.stderr_text
        assert "Internal Server Error" not in out_user, out_user
        assert (
            "ERROR: invalid 'user_container': "
            "malformed RDN string" in out_user
        ), out_user
        result_group = self.master.run_command(
            [
                "ipa",
                "migrate-ds",
                "--user-container",
                "ou=BostonUsers",
                "--group-container",
                "BostonGroups",
                "--base-dn",
                base_dn,
                self.ldap_uri,
            ],
            stdin_text=pwd,
            raiseonerr=False,
        )
        out_group = result_group.stdout_text + result_group.stderr_text
        assert "Internal Server Error" not in out_group, out_group
        assert (
            "ERROR: invalid 'group_container': "
            "malformed RDN string" in out_group
        ), out_group

    def test_bz786185_basedn_passed_to_migrate_ds(self):
        """
        basedn should be allowed to be passed into
        migrateds, bz786185.
        https://bugzilla.redhat.com/show_bug.cgi?id=786185
        """
        tasks.kinit_admin(self.master)
        # Migration is already enabled by test_migration_over_ldaps.
        pwd = self.master.config.admin_password

        self.master.run_command(
            [
                "ipa",
                "migrate-ds",
                "--user-container",
                "ou=BostonUsers",
                "--group-container",
                "ou=BostonGroups",
                "--base-dn",
                "ou=Boston,{}".format(DS_BASEDN),
                self.ldap_uri,
            ],
            stdin_text=pwd,
        )
        self.master.run_command(["ipa", "user-show", "bosusr"])
        self.master.run_command(["ipa", "group-show", "bosgrp"])
        # Outside ou=Boston,dc=testrealm,dc=test must not be migrated
        res = self.master.run_command(
            ["ipa", "user-show", "ldapuser_0001"], raiseonerr=False
        )
        assert res.returncode == 2, res.stderr_text
        for group_name in ("ldapgroup_0001", "HR Managers"):
            res = self.master.run_command(
                ["ipa", "group-show", group_name], raiseonerr=False
            )
            assert res.returncode == 2, res.stderr_text
        self.master.run_command(
            ["ipa", "user-del", "bosusr"], raiseonerr=False
        )
        self.master.run_command(
            ["ipa", "group-del", "bosgrp"], raiseonerr=False
        )

    def test_bz783270_01_warning_when_compat_plugin_enabled(self):
        """
        bz783270 (1/2): With compat enabled, plain migrate-ds must fail
        and report that the compat plug-in is enabled.

        https://bugzilla.redhat.com/show_bug.cgi?id=783270
        """
        tasks.kinit_admin(self.master)
        pwd = self.master.config.admin_password

        try:
            self.master.run_command(
                ["ipa-compat-manage", "enable"],
                stdin_text=pwd,
            )
            tasks.service_control_dirsrv(self.master, "restart")
            # when 389-ds restarts, the compat tree plugin
            # is not available immediately, takes few seconds
            # to finish initialization.
            time.sleep(10)
            result_fail = self.master.run_command(
                ["ipa", "migrate-ds", self.ldap_uri],
                stdin_text=pwd,
                raiseonerr=False,
            )
            out_fail = (
                result_fail.stdout_text + result_fail.stderr_text
            )
            assert result_fail.returncode == 1, out_fail
            assert "The compat plug-in is enabled." in out_fail, out_fail
        finally:
            self.master.run_command(
                ["ipa-compat-manage", "disable"],
                stdin_text=pwd,
                raiseonerr=False,
            )
            tasks.service_control_dirsrv(self.master, "restart")
            self.cleanup_migrated_data()

    def test_bz783270_02_migrate_ds_with_compat_enabled(self):
        """
        bz783270 (2/2): With compat enabled, migrate-ds --with-compat
        succeeds; migrated user and groups are visible.

        https://bugzilla.redhat.com/show_bug.cgi?id=783270
        """
        tasks.kinit_admin(self.master)
        pwd = self.master.config.admin_password

        try:
            compat_enable = self.master.run_command(
                ["ipa-compat-manage", "enable"],
                stdin_text=pwd,
                raiseonerr=False,
            )
            if compat_enable.returncode != 0:
                out_en = (
                    compat_enable.stdout_text
                    + compat_enable.stderr_text
                )
                assert "Plugin already Enabled" in out_en, out_en

            tasks.service_control_dirsrv(self.master, "restart")
            # when 389-ds restarts, the compat tree plugin
            # is not available immediately, takes few seconds
            # to finish initialization.
            time.sleep(10)

            self.master.run_command(
                [
                    "ipa",
                    "migrate-ds",
                    "--with-compat",
                    self.ldap_uri,
                ],
                stdin_text=pwd,
            )
            self.master.run_command(
                ["ipa", "user-show", "ldapuser_0001"]
            )
            self.master.run_command(
                ["ipa", "group-show", "ldapgroup_0001"]
            )
            self.master.run_command(
                ["ipa", "group-show", "HR Managers"],
            )
        finally:
            self.master.run_command(
                ["ipa-compat-manage", "disable"],
                stdin_text=pwd,
                raiseonerr=False,
            )
            tasks.service_control_dirsrv(self.master, "restart")
            self.cleanup_migrated_data()

    def test_bz804609_user_show_all_no_internal_error(self):
        """
        bz804609: ipa user-show --all on a migrated user with a manager
        attribute must not return an internal error.
        https://bugzilla.redhat.com/show_bug.cgi?id=804609
        """
        tasks.kinit_admin(self.master)
        pwd = self.master.config.admin_password

        # --group-container=ou=nonexistent so that no groups are migrated.
        try:
            self.master.run_command(
                [
                    "ipa",
                    "migrate-ds",
                    "--user-container=ou=People",
                    "--group-container=ou=nonexistent",
                    "--continue",
                    self.ldap_uri,
                ],
                stdin_text=pwd,
            )
            result = self.master.run_command(
                ["ipa", "user-show", "--all", "user_with_mgr"],
            )
            out = result.stdout_text + result.stderr_text
            assert "an internal error has occurred" not in out.lower(), out
            assert "mgr_user" in result.stdout_text
        finally:
            self.cleanup_migrated_data()

    def test_bz753966_delete_migrated_group_with_spaces(self):
        """
        bz753966: Migrated groups with spaces in their names must be
        deletable via ipa group-del.
        https://bugzilla.redhat.com/show_bug.cgi?id=753966
        """
        tasks.kinit_admin(self.master)
        pwd = self.master.config.admin_password

        try:
            self.master.run_command(
                [
                    "ipa",
                    "migrate-ds",
                    "--user-container=ou=People",
                    "--group-container=ou=Groups",
                    self.ldap_uri,
                ],
                stdin_text=pwd,
            )
            self.master.run_command(
                ["ipa", "group-find", "HR Managers"]
            )
            self.master.run_command(
                ["ipa", "group-del", "HR Managers"]
            )
            result = self.master.run_command(
                ["ipa", "group-find", "HR Managers"],
                raiseonerr=False,
            )
            assert "0 groups matched" in result.stdout_text
        finally:
            self.cleanup_migrated_data()

    def kerberos_keys_available(self, uid):
        """Return True if Kerberos keys are available for *uid*."""
        result = self.master.run_command(
            ["ipa", "user-show", uid],
        )
        return "Kerberos keys available: True" in result.stdout_text

    def migrate_bind(self, username, password):
        """LDAP simple bind as *username* to trigger key generation."""
        base_dn = self.master.domain.basedn
        bind_dn = "uid={},cn=users,cn=accounts,{}".format(
            username, base_dn
        )
        self.master.run_command(
            [
                "ldapwhoami", "-x",
                "-H", "ldap://localhost",
                "-D", bind_dn,
                "-w", password,
            ],
        )

    def test_hashedpwd_migration(self):
        """
        Migrate users whose passwords are stored as SSHA hashes in
        a remote 389-ds, trigger Kerberos key generation via an LDAP
        simple bind, then verify kinit succeeds.
        The ipa_pwd_extop plugin generates Kerberos keys on any
        successful simple bind when migration mode is enabled.
        """
        user1 = "puser1"
        user2 = "puser2"
        user1pwd = "fo0m4nchU"
        user2pwd = "Secret123"

        test_dir = os.path.dirname(os.path.abspath(__file__))
        ldif_path = os.path.join(
            test_dir, "data", "ds_migration", "instance_hashedpwd.ldif"
        )
        with open(ldif_path) as f:
            ldif_content = f.read()
        remote_ldif = "/tmp/instance_hashedpwd.ldif"
        self.clients[0].put_file_contents(remote_ldif, ldif_content)
        self.clients[0].run_command(
            [
                "/usr/bin/ldapmodify",
                "-a", "-x",
                "-H", "ldap://localhost:{}".format(DS_PORT),
                "-D", "cn=Directory Manager",
                "-w", self.master.config.admin_password,
                "-f", remote_ldif,
            ]
        )

        tasks.kinit_admin(self.master)
        pwd_admin = self.master.config.admin_password
        user_container = "ou=People,{}".format(DS_BASEDN)
        group_container = "ou=groups,{}".format(DS_BASEDN)
        try:
            self.master.run_command(
                [
                    "ipa",
                    "migrate-ds",
                    "--user-container",
                    user_container,
                    "--group-container",
                    group_container,
                    self.ldap_uri,
                ],
                stdin_text=pwd_admin,
            )

            assert not self.kerberos_keys_available(user1)
            assert not self.kerberos_keys_available(user2)

            self.migrate_bind(user1, user1pwd)
            assert self.kerberos_keys_available(user1)
            tasks.kinit_as_user(self.master, user1, user1pwd)

            self.migrate_bind(user2, user2pwd)
            assert self.kerberos_keys_available(user2)
            tasks.kinit_as_user(self.master, user2, user2pwd)
        finally:
            tasks.kinit_admin(self.master)
            self.cleanup_migrated_data(
                extra_users=[user1, user2]
            )

    def test_bz809560_no_private_group_for_migrated_posix_user(self):
        """
        bz809560: Private groups must not be created for migrated posix
        users whose GID points to another group.
        https://bugzilla.redhat.com/show_bug.cgi?id=809560
        """
        tasks.kinit_admin(self.master)
        pwd = self.master.config.admin_password

        try:
            self.master.run_command(
                [
                    "ipa",
                    "migrate-ds",
                    "--user-container=ou=People",
                    "--group-container=ou=Groups",
                    self.ldap_uri,
                ],
                stdin_text=pwd,
            )
            self.master.run_command(
                ["ipa", "user-show", "posixuser_no_privgrp"]
            )
            result = self.master.run_command(
                ["ipa", "group-show", "posixuser_no_privgrp"],
                raiseonerr=False,
            )
            assert result.returncode != 0, (
                "Private group should not exist for migrated posix user"
            )
        finally:
            self.cleanup_migrated_data()

    def test_bz813389_duplicate_gid_warning(self):
        """
        bz813389: When two groups share the same GID, migrate-ds must
        succeed and log a warning instead of failing with a cryptic error.
        https://bugzilla.redhat.com/show_bug.cgi?id=813389
        """
        tasks.kinit_admin(self.master)
        pwd = self.master.config.admin_password

        try:
            result = self.master.run_command(
                [
                    "ipa",
                    "migrate-ds",
                    "--user-container=ou=People",
                    "--group-container=ou=Groups",
                    self.ldap_uri,
                ],
                stdin_text=pwd,
            )
            out = result.stdout_text + result.stderr_text
            assert "Expected 1" not in out, (
                "Migration should not fail with cryptic error"
            )
            self.master.run_command(
                ["ipa", "user-show", "ldapuser_0001"]
            )
            log = self.master.get_file_contents(
                "/var/log/httpd/error_log", encoding="utf-8"
            )
            assert (
                "should match 1 group, but it matched 2 groups" in log
            )
        finally:
            self.cleanup_migrated_data()
