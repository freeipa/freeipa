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


def _setup_389ds_on_client(client, admin_password, sample_entries=False):
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
        sample_entries = {sample}
        suffix = {basedn}
    """).format(
        hostname=client.hostname,
        instance=DS_INSTANCE_NAME,
        port=DS_PORT,
        secure_port=DS_SECURE_PORT,
        password=admin_password,
        basedn=DS_BASEDN,
        sample="yes" if sample_entries else "no",
    )
    client.put_file_contents("/tmp/ds-instance.inf", inf_content)
    client.run_command(
        ["dscreate", "from-file", "/tmp/ds-instance.inf"]
    )

    # Load migration test data from instance1.ldif
    # Use -c (continue) so duplicate entries from sample_entries are skipped
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
            "-a", "-c", "-x",
            "-H", "ldap://localhost:{}".format(DS_PORT),
            "-D", "cn=Directory Manager", "-w", admin_password,
            "-f", "/tmp/instance1.ldif",
        ]
    )


def migrate_ds(master, extra_args=None, password=None, raiseonerr=True):
    """Run ``ipa migrate-ds`` with *extra_args*."""
    pwd = password or master.config.admin_password
    return master.run_command(
        ["ipa", "migrate-ds"] + (extra_args or []),
        stdin_text=pwd,
        raiseonerr=raiseonerr,
    )


def cleanup_migrated_data(master, users, groups,
                          extra_users=None, extra_groups=None):
    """Remove all users and groups that migrate-ds may have created."""
    all_users = list(users)
    if extra_users:
        all_users.extend(extra_users)
    for user in all_users:
        master.run_command(
            ["ipa", "user-del", user], raiseonerr=False
        )
    all_groups = list(groups)
    if extra_groups:
        all_groups.extend(extra_groups)
    for group in all_groups:
        master.run_command(
            ["ipa", "group-del", group], raiseonerr=False
        )


class BaseTestDSMigration(IntegrationTest):
    """
    Common setup for DS migration test classes.

    Installs 389-ds on the client, populates it from instance1.ldif,
    disables the compat plugin and restarts Directory Server.
    """

    topology = "line"
    num_replicas = 0
    num_clients = 1
    sample_entries = False

    @classmethod
    def install(cls, mh):
        super(BaseTestDSMigration, cls).install(mh)
        _setup_389ds_on_client(
            cls.clients[0], cls.master.config.admin_password,
            sample_entries=cls.sample_entries,
        )
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa-compat-manage", "disable"],
            stdin_text=cls.master.config.admin_password,
            raiseonerr=False,
        )
        tasks.service_control_dirsrv(cls.master, "restart")

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


class TestDSMigrationConfig(BaseTestDSMigration):
    """
    Test ipa migrate-ds related scenarios.

    Uses a client host with 389-ds populated from instance1.ldif
    (ou=People, ou=groups, dc=testrealm,dc=test) for migration tests.
    """

    @classmethod
    def install(cls, mh):
        super(TestDSMigrationConfig, cls).install(mh)
        cls.ldap_uri = "ldap://{}:{}".format(
            cls.clients[0].hostname, DS_PORT
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

        # Clean up migrated user and group
        self.master.run_command(
            ["ipa", "user-del", "ldapuser_0001"], raiseonerr=False
        )
        for group in [
            "ldapgroup_0001",
            "HR Managers",
            "Directory Administrators",
        ]:
            self.master.run_command(
                ["ipa", "group-del", group],
                raiseonerr=False,
            )

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
            self.master.run_command(
                ["ipa", "user-del", "ldapuser_0001"], raiseonerr=False
            )
            for group in [
                "ldapgroup_0001",
                "HR Managers",
                "Directory Administrators",
            ]:
                self.master.run_command(
                    ["ipa", "group-del", group],
                    raiseonerr=False,
                )

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
            self.master.run_command(
                ["ipa", "user-del", "ldapuser_0001"],
                raiseonerr=False,
            )
            for group in [
                "ldapgroup_0001",
                "HR Managers",
                "Directory Administrators",
            ]:
                self.master.run_command(
                    ["ipa", "group-del", group],
                    raiseonerr=False,
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
            for user in (user1, user2):
                self.master.run_command(
                    ["ipa", "user-del", user],
                    raiseonerr=False,
                )


class TestDSMigrationOptions(BaseTestDSMigration):
    """
    Option-validation tests and negative scenarios for ipa migrate-ds.
    """
    sample_entries = True

    USER_CONTAINER = "ou=People"
    GROUP_CONTAINER = "ou=Groups"
    CA_CERT_FILE = "/etc/ipa/remoteds.crt"

    COMMON_MIGRATE_OPTS = [
        "--user-container", USER_CONTAINER,
        "--group-container", GROUP_CONTAINER,
        "--ca-cert-file", CA_CERT_FILE,
    ]

    MIGRATED_USERS = (
        "ldapuser_0001", "ldapuser_0002", "ldapuser_0003",
    )
    MIGRATED_GROUPS = (
        "ldapgroup_0001", "HR Managers", "Directory Administrators",
    )

    EXPECTED_BAD_OU_DN = "ou=bad,{}".format(DS_BASEDN)

    @classmethod
    def install(cls, mh):
        super(TestDSMigrationOptions, cls).install(mh)

        # Load additional users needed by negative/exclude tests
        test_dir = os.path.dirname(os.path.abspath(__file__))
        ldif_path = os.path.join(
            test_dir, "data", "ds_migration", "instance_negative.ldif"
        )
        with open(ldif_path) as f:
            ldif_content = f.read()
        cls.clients[0].put_file_contents(
            "/tmp/instance_negative.ldif", ldif_content
        )
        cls.clients[0].run_command(
            [
                "/usr/bin/ldapmodify",
                "-a", "-x",
                "-H", "ldap://localhost:{}".format(DS_PORT),
                "-D", "cn=Directory Manager",
                "-w", cls.master.config.admin_password,
                "-f", "/tmp/instance_negative.ldif",
            ]
        )

        cls.ldaps_uri = "ldaps://{}:{}".format(
            cls.clients[0].hostname, DS_SECURE_PORT
        )

        # Copy 389-ds CA cert from client to master for LDAPS
        ds_cert_dir = "/etc/dirsrv/slapd-{}".format(DS_INSTANCE_NAME)
        cert_result = cls.clients[0].run_command(
            [
                "certutil", "-d", ds_cert_dir, "-L", "-n",
                "Self-Signed-CA", "-a",
            ],
        )
        cls.master.put_file_contents(
            cls.CA_CERT_FILE, cert_result.stdout_text
        )
        cls.master.run_command(
            ["restorecon", cls.CA_CERT_FILE], raiseonerr=False
        )

        # Enable migration mode
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa", "config-mod", "--enable-migration", "TRUE"],
        )

    def test_invalid_directory_server_unreachable(self):
        """migrate-ds against an unreachable LDAP server must fail."""
        tasks.kinit_admin(self.master)
        args = self.COMMON_MIGRATE_OPTS + [
            "ldap://ldap.example.com:389",
        ]
        result = migrate_ds(self.master, args, raiseonerr=False)
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 1, out
        assert "cannot connect" in out.lower(), out
        assert "ldap.example.com" in out

    def test_invalid_user_container(self):
        """migrate-ds with a non-existent user container must fail."""
        tasks.kinit_admin(self.master)
        args = [
            "--user-container", "ou=bad",
            "--ca-cert-file", self.CA_CERT_FILE,
            self.ldaps_uri,
        ]
        result = migrate_ds(self.master, args, raiseonerr=False)
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 2, out
        assert "user LDAP search did not return any result" in out, out
        assert self.EXPECTED_BAD_OU_DN in out, out

    def test_invalid_group_container(self):
        """migrate-ds with a non-existent group container must fail."""
        tasks.kinit_admin(self.master)
        args = [
            "--group-container", "ou=bad",
            "--ca-cert-file", self.CA_CERT_FILE,
            self.ldaps_uri,
        ]
        result = migrate_ds(self.master, args, raiseonerr=False)
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 2, out
        assert "group LDAP search did not return any result" in out, out
        assert self.EXPECTED_BAD_OU_DN in out, out

    def test_invalid_user_object_class(self):
        """migrate-ds with a non-existent user objectclass
        returns no results."""
        tasks.kinit_admin(self.master)
        args = self.COMMON_MIGRATE_OPTS + [
            "--user-objectclass", "badclass",
            self.ldaps_uri,
        ]
        result = migrate_ds(self.master, args, raiseonerr=False)
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 2, out
        assert "user LDAP search did not return any result" in out, out
        assert "badclass" in out, out

    def test_invalid_group_object_class(self):
        """migrate-ds with a non-existent group objectclass
        returns no results."""
        tasks.kinit_admin(self.master)
        args = self.COMMON_MIGRATE_OPTS + [
            "--group-objectclass", "badclass",
            self.ldaps_uri,
        ]
        result = migrate_ds(self.master, args, raiseonerr=False)
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 2, out
        assert "group LDAP search did not return any result" in out, out
        assert "badclass" in out, out

    def test_invalid_schema_option(self):
        """migrate-ds with an invalid --schema value must fail."""
        tasks.kinit_admin(self.master)
        args = self.COMMON_MIGRATE_OPTS + [
            "--schema", "RFC9999",
            self.ldaps_uri,
        ]
        result = migrate_ds(self.master, args, raiseonerr=False)
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 1, out
        assert "invalid 'schema'" in out
        assert "RFC2307" in out, out

    def test_invalid_bind_password(self):
        """migrate-ds with a wrong bind password must fail."""
        tasks.kinit_admin(self.master)
        args = self.COMMON_MIGRATE_OPTS + [
            self.ldaps_uri,
        ]
        result = migrate_ds(
            self.master, args, password="badpWd882", raiseonerr=False
        )
        out = result.stdout_text + result.stderr_text
        assert result.returncode == 1, out
        assert (
            "insufficient access" in out.lower()
            and "invalid credentials" in out.lower()
        ), out

    def test_bind_dn_non_directory_manager(self):
        """migrate-ds using a regular user bind DN succeeds
        when the remote 389-ds has ACIs granting search access
        (created by sample_entries=yes)."""
        tasks.kinit_admin(self.master)
        cleanup_migrated_data(
            self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
        )
        bind_dn = "uid=ldapuser_0001,{},{}".format(
            self.USER_CONTAINER, DS_BASEDN
        )
        args = self.COMMON_MIGRATE_OPTS + [
            "--bind-dn", bind_dn,
            self.ldaps_uri,
        ]
        try:
            result = migrate_ds(
                self.master, args, password="fo0m4nchU", raiseonerr=False
            )
            out = result.stdout_text + result.stderr_text
            assert result.returncode == 0, out
            self.master.run_command(
                ["ipa", "user-show", "ldapuser_0001"]
            )
            self.master.run_command(
                ["ipa", "group-show", "ldapgroup_0001"]
            )
        finally:
            cleanup_migrated_data(
                self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
            )

    def test_exclude_user(self):
        """--exclude-users skips the specified user during migration."""
        tasks.kinit_admin(self.master)
        cleanup_migrated_data(
            self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
        )
        args = self.COMMON_MIGRATE_OPTS + [
            "--exclude-users", "ldapuser_0002",
            self.ldaps_uri,
        ]
        try:
            migrate_ds(self.master, args)
            self.master.run_command(["ipa", "user-show", "ldapuser_0001"])
            assert self.master.run_command(
                ["ipa", "user-show", "ldapuser_0002"],
                raiseonerr=False,
            ).returncode == 2
            self.master.run_command(["ipa", "user-show", "ldapuser_0003"])
            self.master.run_command(["ipa", "group-show", "ldapgroup_0001"])
            self.master.run_command(["ipa", "group-show", "HR Managers"])
        finally:
            cleanup_migrated_data(
                self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
            )

    def test_exclude_group(self):
        """--exclude-groups skips the specified group during migration."""
        tasks.kinit_admin(self.master)
        cleanup_migrated_data(
            self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
        )
        args = self.COMMON_MIGRATE_OPTS + [
            "--exclude-groups", "HR Managers",
            self.ldaps_uri,
        ]
        try:
            migrate_ds(self.master, args)
            for uid in ("ldapuser_0001", "ldapuser_0002", "ldapuser_0003"):
                self.master.run_command(["ipa", "user-show", uid])
            self.master.run_command(["ipa", "group-show", "ldapgroup_0001"])
            assert self.master.run_command(
                ["ipa", "group-show", "HR Managers"],
                raiseonerr=False,
            ).returncode == 2
        finally:
            cleanup_migrated_data(
                self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
            )

    def test_exclude_multiple_users(self):
        """--exclude-users repeated skips multiple users during migration."""
        tasks.kinit_admin(self.master)
        cleanup_migrated_data(
            self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
        )
        args = self.COMMON_MIGRATE_OPTS + [
            "--exclude-users", "ldapuser_0001",
            "--exclude-users", "ldapuser_0002",
            self.ldaps_uri,
        ]
        try:
            migrate_ds(self.master, args)
            assert self.master.run_command(
                ["ipa", "user-show", "ldapuser_0001"],
                raiseonerr=False,
            ).returncode == 2
            assert self.master.run_command(
                ["ipa", "user-show", "ldapuser_0002"],
                raiseonerr=False,
            ).returncode == 2
            self.master.run_command(["ipa", "user-show", "ldapuser_0003"])
            self.master.run_command(["ipa", "group-show", "ldapgroup_0001"])
            self.master.run_command(["ipa", "group-show", "HR Managers"])
        finally:
            cleanup_migrated_data(
                self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
            )

    def test_exclude_multiple_groups(self):
        """--exclude-groups repeated skips multiple groups during migration."""
        tasks.kinit_admin(self.master)
        cleanup_migrated_data(
            self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
        )
        args = self.COMMON_MIGRATE_OPTS + [
            "--exclude-groups", "ldapgroup_0001",
            "--exclude-groups", "HR Managers",
            self.ldaps_uri,
        ]
        try:
            migrate_ds(self.master, args)
            for uid in ("ldapuser_0001", "ldapuser_0002", "ldapuser_0003"):
                self.master.run_command(["ipa", "user-show", uid])
            assert self.master.run_command(
                ["ipa", "group-show", "ldapgroup_0001"],
                raiseonerr=False,
            ).returncode == 2
            assert self.master.run_command(
                ["ipa", "group-show", "HR Managers"],
                raiseonerr=False,
            ).returncode == 2
        finally:
            cleanup_migrated_data(
                self.master, self.MIGRATED_USERS, self.MIGRATED_GROUPS,
            )
