# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Tests to verify ipa-migrate tool.
"""

from __future__ import absolute_import
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths

import pytest
import textwrap


def prepare_ipa_server(master):
    """
    Setup remote IPA server environment
    """
    # Setup IPA users
    for i in range(1, 5):
        master.run_command(
            [
                "ipa",
                "user-add",
                "testuser%d" % i,
                "--first",
                "Test",
                "--last",
                "User%d" % i,
            ]
        )

    # Setup IPA group
    master.run_command(["ipa", "group-add", "testgroup"])

    # Add respective members to each group
    master.run_command(
        ["ipa", "group-add-member", "testgroup", "--users=testuser1"]
    )

    # Adding stage user
    master.run_command(
        [
            "ipa",
            "stageuser-add",
            "--first=Tim",
            "--last=User",
            "--password",
            "tuser1",
        ]
    )

    # Add Custom idrange
    master.run_command(
        [
            "ipa",
            "idrange-add",
            "testrange",
            "--base-id=10000",
            "--range-size=10000",
            "--rid-base=300000",
            "--secondary-rid-base=400000",
        ]
    )

    # Add Automount locations and maps
    master.run_command(["ipa", "automountlocation-add", "baltimore"])
    master.run_command(["ipa", "automountmap-add", "baltimore", "auto.share"])
    master.run_command(
        [
            "ipa",
            "automountmap-add-indirect",
            "baltimore",
            "--parentmap=auto.share",
            "--mount=sub auto.man",
        ]
    )
    master.run_command(
        [
            "ipa",
            "automountkey-add",
            "baltimore",
            "auto.master",
            "--key=/share",
            "--info=auto.share",
        ]
    )

    # Run ipa-adtrust-install
    master.run_command(["dnf", "install", "-y", "ipa-server-trust-ad"])
    master.run_command(
        [
            "ipa-adtrust-install",
            "-a",
            master.config.admin_password,
            "--add-sids",
            "-U",
        ]
    )

    # Generate subids for users
    master.run_command(["ipa", "subid-generate", "--owner=testuser1"])
    master.run_command(["ipa", "subid-generate", "--owner=admin"])

    # Add Sudo rules
    master.run_command(["ipa", "sudorule-add", "readfiles"])
    master.run_command(["ipa", "sudocmd-add", "/usr/bin/less"])
    master.run_command(
        [
            "ipa",
            "sudorule-add-allow-command",
            "readfiles",
            "--sudocmds",
            "/usr/bin/less",
        ]
    )
    master.run_command(
        [
            "ipa",
            "sudorule-add-host",
            "readfiles",
            "--hosts",
            "server.example.com",
        ]
    )
    master.run_command(
        ["ipa", "sudorule-add-user", "readfiles", "--users", "testuser1"]
    )

    # Add Custom CA
    master.run_command(
        [
            "ipa",
            "ca-add",
            "puppet",
            "--desc",
            '"Puppet"',
            "--subject",
            "CN=Puppet CA,O=TESTRELM.TEST",
        ]
    )

    # Add ipa roles and add privileges to the role
    master.run_command(
        ["ipa", "role-add", "--desc=Junior-level admin", "junioradmin"]
    )
    master.run_command(
        [
            "ipa",
            "role-add-privilege",
            "--privileges=User Administrators",
            "junioradmin",
        ]
    )

    # Add permission
    master.run_command(
        [
            "ipa",
            "permission-add",
            "--type=user",
            "--permissions=add",
            "Add Users",
        ]
    )

    # Add otp token for testuser1
    master.run_command(
        [
            "ipa",
            "otptoken-add",
            "--type=totp",
            "--owner=testuser1",
            '--desc="My soft token',
        ]
    )

    # Add a netgroup and user to the netgroup
    master.run_command(
        ["ipa", "netgroup-add", '--desc="NFS admins"', "admins"]
    )
    master.run_command(
        ["ipa", "netgroup-add-member", "--users=testuser2", "admins"]
    )

    # Set krbpolicy policy
    master.run_command(
        ["ipa", "krbtpolicy-mod", "--maxlife=99999", "--maxrenew=99999"]
    )
    master.run_command(["ipa", "krbtpolicy-mod", "admin", "--maxlife=9600"])

    # Add IPA location
    master.run_command(
        ["ipa", "location-add", "location", "--description", "My location"]
    )

    # Add idviews and overrides
    master.run_command(["ipa", "idview-add", "idview1"])
    master.run_command(["ipa", "idoverrideuser-add", "idview1", "testuser1"])
    master.run_command(
        [
            "ipa",
            "idoverrideuser-mod",
            "idview1",
            "testuser1",
            "--shell=/bin/sh",
        ]
    )

    # Add DNSzone
    master.run_command(
        [
            "ipa",
            "dnszone-add",
            "example.test",
            "--admin-email=admin@example.test",
        ]
    )
    master.run_command(
        ["ipa", "dnszone-mod", "example.test", "--dynamic-update=TRUE"]
    )

    # Add hbac rule
    master.run_command(["ipa", "hbacrule-add", "--usercat=all", "test1"])
    master.run_command(
        ["ipa", "hbacrule-add", "--hostcat=all", "testuser_sshd"]
    )
    master.run_command(
        ["ipa", "hbacrule-add-user", "--users=testuser1", "testuser_sshd"]
    )
    master.run_command(
        ["ipa", "hbacrule-add-service", "--hbacsvcs=sshd", "testuser_sshd"]
    )

    # Vault addition
    master.run_command(
        [
            "ipa",
            "vault-add",
            "--password",
            "vault1234",
            "--type",
            "symmetric",
        ]
    )

    # Add Selinuxusermap
    master.run_command(
        [
            "ipa",
            "selinuxusermap-add",
            "--usercat=all",
            "--selinuxuser=xguest_u:s0",
            "test1",
        ]
    )

    # Modify passkeyconfig
    master.run_command(
        ["ipa", "passkeyconfig-mod", "--require-user-verification=FALSE"]
    )


def run_migrate(
    host, mode, remote_host, bind_dn=None, bind_pwd=None, extra_args=None
):
    """
    ipa-migrate tool command
    """
    cmd = ["ipa-migrate"]
    if mode:
        cmd.append(mode)
    if remote_host:
        cmd.append(remote_host)
    if bind_dn:
        cmd.append("-D")
        cmd.append(bind_dn)
    if bind_pwd:
        cmd.append("-w")
        cmd.append(bind_pwd)
    if extra_args:
        for arg in extra_args:
            cmd.append(arg)
    result = host.run_command(cmd, raiseonerr=False)
    return result


class TestIPAMigrateScenario1(IntegrationTest):
    """
    Tier-1 tests for ipa-migrate tool with DNS enabled on
    local and remote server
    """

    num_replicas = 1
    num_clients = 1
    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        prepare_ipa_server(cls.master)
        tasks.install_client(cls.master, cls.clients[0], nameservers=None)

    def test_remote_server(self):
        """
        This test installs IPA server instead of replica on
        system under test with the same realm and domain name.
        """
        tasks.install_master(self.replicas[0], setup_dns=True, setup_kra=True)

    def test_ipa_migrate_without_kinit_as_admin(self):
        """
        This test checks that ipa-migrate tool displays
        error when kerberos ticket is missing for admin
        """
        self.replicas[0].run_command(["kdestroy", "-A"])
        KINIT_ERR_MSG = "ipa: ERROR: Did not receive Kerberos credentials\n"
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        assert result.returncode == 1
        assert KINIT_ERR_MSG in result.stderr_text
        tasks.kinit_admin(self.replicas[0])

    def test_ipa_migrate_log_file_is_created(self):
        """
        This test checks that ipa-migrate.log file is created when ipa-migrate
        tool is run
        """
        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        assert self.replicas[0].transport.file_exists(paths.IPA_MIGRATE_LOG)

    def test_ipa_migrate_with_incorrect_bind_pwd(self):
        """
        This test checks that ipa-migrate tool fails with incorrect
        bind password
        """
        ERR_MSG = (
            "IPA to IPA migration starting ...\n"
            "Failed to bind to remote server: Insufficient access:  "
            "Invalid credentials\n"
        )
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            "incorrect_bind_pwd",
            extra_args=['-x'],
        )
        assert result.returncode == 1
        assert ERR_MSG in result.stderr_text

    def test_ipa_migrate_with_incorrect_bind_dn(self):
        """
        This test checks that ipa-migrate tool fails with incorrect
        bind dn
        """
        ERR_MSG = (
            "IPA to IPA migration starting ...\n"
            "Failed to bind to remote server: Insufficient access:  "
            "Invalid credentials\n"
        )
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Dir Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        assert result.returncode == 1
        assert ERR_MSG in result.stderr_text

    def test_ipa_migrate_with_invalid_host(self):
        """
        This test checks that ipa-migrate tools fails with
        invalid host
        """
        hostname = "server.invalid.host"
        ERR_MSG = (
            "IPA to IPA migration starting ...\n"
            "Failed to bind to remote server: cannot connect to "
            "'ldap://"
            "{}': \n".format(hostname)
        )
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            "server.invalid.host",
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        assert result.returncode == 1
        assert ERR_MSG in result.stderr_text

    def test_dry_run_record_output_ldif(self):
        """
        This testcase run ipa-migrate tool with the
        -o option which captures the output to ldif file
        """
        ldif_file = "/tmp/test.ldif"
        param = ['-x', '-o', ldif_file]
        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        assert self.replicas[0].transport.file_exists("/tmp/test.ldif")

    @pytest.fixture()
    def empty_log_file(self):
        """
        This fixture empties the log file before ipa-migrate tool
        is run since the log is appended everytime the tool is run.
        """
        self.replicas[0].run_command(
            ["truncate", "-s", "0", paths.IPA_MIGRATE_LOG]
        )
        yield

    def test_ipa_sigden_plugin_fail_error(self, empty_log_file):
        """
        This testcase checks that sidgen plugin fail error is
        not seen during migrate prod-mode
        """
        SIDGEN_ERR_MSG = "SIDGEN task failed: \n"
        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        error_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert SIDGEN_ERR_MSG not in error_msg

    def test_ipa_migrate_stage_mode_dry_run(self, empty_log_file):
        """
        Test ipa-migrate stage mode with dry-run option
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        IPA_MIGRATE_STAGE_DRY_RUN_LOG = "--dryrun=True\n"
        IPA_SERVER_UPRGADE_LOG = "Skipping ipa-server-upgrade in dryrun mode.\n"
        IPA_SKIP_SIDGEN_LOG = "Skipping SIDGEN task in dryrun mode."
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert result.returncode == 0
        assert IPA_MIGRATE_STAGE_DRY_RUN_LOG in install_msg
        assert IPA_SERVER_UPRGADE_LOG in install_msg
        assert IPA_SKIP_SIDGEN_LOG in install_msg

    def test_ipa_migrate_prod_mode_dry_run(self, empty_log_file):
        """
        Test ipa-migrate prod mode with dry run option
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        IPA_MIGRATE_PROD_DRY_RUN_LOG = "--dryrun=True\n"
        IPA_SERVER_UPRGADE_LOG = (
            "Skipping ipa-server-upgrade in dryrun mode.\n"
        )
        IPA_SIDGEN_LOG = "Skipping SIDGEN task in dryrun mode.\n"
        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-x'],
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert result.returncode == 0
        assert IPA_MIGRATE_PROD_DRY_RUN_LOG in install_msg
        assert IPA_SERVER_UPRGADE_LOG in install_msg
        assert IPA_SIDGEN_LOG in install_msg

    def test_ipa_migrate_with_skip_schema_option_dry_run(self, empty_log_file):
        """
        This test checks that ipa-migrate tool works
        with -S(schema) options in stage mode
        """
        param = ['-x', '-S']
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        SKIP_SCHEMA_MSG_LOG = "Schema Migration " \
                              "(migrated 0 definitions)\n"
        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert SKIP_SCHEMA_MSG_LOG in install_msg

    def test_ipa_migrate_with_skip_config_option_dry_run(self, empty_log_file):
        """
        This test checks that ipa-migrate tool works
        with -C(config) options in stage mode
        """
        SKIP_MIGRATION_CONFIG_LOG = "DS Configuration Migration " \
                                    "(migrated 0 entries)\n"
        param = ['-x', '-C']
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])

        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert SKIP_MIGRATION_CONFIG_LOG in install_msg

    def test_ipa_migrate_reset_range(self, empty_log_file):
        """
        This test checks the reset range option -r
        along with prod-mode, since stage-mode this is done
        automatically.
        """
        param = ['-r', '-n']
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        RESET_RANGE_LOG = "--reset-range=True\n"
        run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert RESET_RANGE_LOG in install_msg

    def test_ipa_migrate_stage_mode_dry_override_schema(self, empty_log_file):
        """
        This test checks that -O option (override schema) works
        in dry mode
        """
        param = ['-x', '-O', '-n']
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        SCHEMA_OVERRIDE_LOG = "--schema-overwrite=True\n"
        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert SCHEMA_OVERRIDE_LOG in install_msg

    def test_ipa_migrate_stage_mode(self, empty_log_file):
        """
        This test checks that ipa-migrate is successful
        in dry run mode
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        MIGRATION_SCHEMA_LOG_MSG = "Migrating schema ...\n"
        MIGRATION_CONFIG_LOG_MSG = "Migrating configuration ...\n"
        IPA_UPGRADE_LOG_MSG = (
            "Running ipa-server-upgrade ... (this may take a while)\n"
        )
        SIDGEN_TASK_LOG_MSG = "Running SIDGEN task ...\n"
        MIGRATION_COMPLETE_LOG_MSG = "Migration complete!\n"
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-n'],
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert result.returncode == 0
        assert MIGRATION_SCHEMA_LOG_MSG in install_msg
        assert MIGRATION_CONFIG_LOG_MSG in install_msg
        assert IPA_UPGRADE_LOG_MSG in install_msg
        assert SIDGEN_TASK_LOG_MSG in install_msg
        assert MIGRATION_COMPLETE_LOG_MSG in install_msg

    def test_ipa_migrate_prod_mode(self, empty_log_file):
        """
        This test checks that ipa-migrate is successful
        in prod run mode
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        MIGRATION_SCHEMA_LOG_MSG = "Migrating schema ...\n"
        MIGRATION_DATABASE_LOG_MSG = (
            "Migrating database ... (this may take a while)\n"
        )
        IPA_UPGRADE_LOG_MSG = (
            "Running ipa-server-upgrade ... (this may take a while)\n"
        )
        SIDGEN_TASK_LOG_MSG = "Running SIDGEN task ...\n"
        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-n'],
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert result.returncode == 0
        assert MIGRATION_SCHEMA_LOG_MSG in install_msg
        assert MIGRATION_DATABASE_LOG_MSG in install_msg
        assert IPA_UPGRADE_LOG_MSG in install_msg
        assert SIDGEN_TASK_LOG_MSG in install_msg

    def test_ipa_migrate_with_bind_pwd_file_option(self, empty_log_file):
        """
        This testcase checks that ipa-migrate tool
        works with valid bind_pwd specified in a file using '-j'
        option
        """
        DEBUG_MSG = "--bind-pw-file=/tmp/pwd.txt\n"
        bind_pwd_file = "/tmp/pwd.txt"
        bind_pwd_file_content = self.master.config.admin_password
        self.replicas[0].put_file_contents(
            bind_pwd_file, bind_pwd_file_content
        )
        param = ['-j', bind_pwd_file, '-x']
        result = run_migrate(
            host=self.replicas[0],
            mode="stage-mode",
            remote_host=self.master.hostname,
            bind_dn="cn=Directory Manager",
            bind_pwd=None,
            extra_args=param,
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert DEBUG_MSG in install_msg
        assert result.returncode == 0

    def test_ipa_migrate_using_db_ldif(self):
        """
        This test checks that ipa-migrate tool
        works with db ldif file using -C option
        """
        DB_LDIF_LOG = "--db-ldif=/tmp/dse.ldif\n"
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        ldif_file_path = "/tmp/dse.ldif"
        param = ["-f", ldif_file_path, "-n", "-x"]
        realm_name = self.master.domain.realm
        base_dn = str(self.master.domain.basedn)
        dse_ldif = textwrap.dedent(
            f"""
            dn: cn={realm_name},cn=kerberos,{base_dn}
            cn: {realm_name}
            objectClass: top
            objectClass: krbrealmcontainer
            """
        ).format(
            realm_name=self.master.domain.realm,
            base_dn=str(self.master.domain.basedn),
        )
        self.replicas[0].put_file_contents(ldif_file_path, dse_ldif)
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert result.returncode == 0
        assert DB_LDIF_LOG in install_msg

    def test_ipa_migrate_using_invalid_dbldif_file(self):
        """
        This testcase checks that proper error msg is
        displayed when invalid ldif file without realm is used
        as input to schema config option -f
        """
        ERR_MSG = (
            "IPA to IPA migration starting ...\n"
            "Unable to find realm from remote LDIF\n"
        )
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        base_dn = str(self.master.domain.basedn)
        ldif_file = "/tmp/ldif_file"
        param = ["-f", ldif_file, "-n", "-x"]
        dse_ldif = textwrap.dedent(
            """
            version: 1
            dn: cn=schema,{}

            """
        ).format(base_dn)
        self.replicas[0].put_file_contents(ldif_file, dse_ldif)
        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        assert result.returncode == 2
        assert ERR_MSG in result.stderr_text

    def test_ipa_migrate_subtree_option(self):
        """
        This testcase checks the subtree option
        -s along with the ipa-migrate command
        """
        base_dn = str(self.master.domain.basedn)
        subtree = 'cn=security,{}'.format(base_dn)
        params = ['-s', subtree, '-n', '-x']
        base_dn = str(self.master.domain.basedn)
        CUSTOM_SUBTREE_LOG = (
            "Add db entry 'cn=security,{} - custom'"
        ).format(base_dn)
        dse_ldif = textwrap.dedent(
            """
            dn: cn=security,{base_dn}
            changetype: add
            objectClass:top
            objectClass: nscontainer
        """
        ).format(base_dn=base_dn)
        tasks.ldapmodify_dm(self.master, dse_ldif)
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=params,
        )
        assert result.returncode == 0
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert CUSTOM_SUBTREE_LOG in install_msg

    @pytest.fixture()
    def modify_dns_zone(self):
        zone_name = 'ipatest.test'
        self.master.run_command(
            ["ipa", "dnszone-add", zone_name, "--force"]
        )
        yield
        self.replicas[0].run_command(
            ["ipa", "dnszone-del", zone_name]
        )

    def test_ipa_migrate_dns_option(self, modify_dns_zone):
        """
        This testcase checks that when migrate dns option
        -B is used the dns entry is migrated to the
        local host.
        """
        zone_name = "ipatest.test."
        base_dn = str(self.master.domain.basedn)
        DNS_LOG1 = "--migrate-dns=True\n"
        DNS_LOG2 = (
            "DEBUG Added entry: idnsname={},cn=dns,{}\n"
        ).format(zone_name, base_dn)
        DNS_LOG3 = (
            "DEBUG Added entry: idnsname=_kerberos,"
            "idnsname={},cn=dns,{}\n"
        ).format(zone_name, base_dn)
        params = ["-B", "-n"]
        run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=params,
        )
        result = self.replicas[0].run_command(["ipa", "dnszone-find"])
        assert "Zone name: ipatest.test." in result.stdout_text
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert DNS_LOG1 in install_msg
        assert DNS_LOG2 in install_msg
        assert DNS_LOG3 in install_msg

    def test_ipa_migrate_version_option(self):
        """
        The -V option has been removed.
        """
        CONSOLE_LOG = (
            "ipa-migrate: error: the following arguments are "
            "required: mode, hostname"
        )
        result = self.master.run_command(["ipa-migrate", "-V"],
                                         raiseonerr=False)
        assert result.returncode == 2
        assert CONSOLE_LOG in result.stderr_text

    def test_ipa_migrate_with_log_file_option(self):
        """
        This testcase checks that log file is created
        with -l option
        """
        custom_log_file = "/tmp/test.log"
        params = ['-x', '-n', '-l', custom_log_file]
        run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=params,
        )
        assert self.replicas[0].transport.file_exists(custom_log_file)

    def test_ipa_migrate_stage_mode_with_cert(self):
        """
        This testcase checks that ipa-migrate command
        works without the 'ValuerError'
        when -Z <cert> option is used with valid cert
        """
        cert_file = '/tmp/ipa.crt'
        remote_server_cert = self.master.get_file_contents(
            paths.IPA_CA_CRT, encoding="utf-8"
        )
        self.replicas[0].put_file_contents(cert_file, remote_server_cert)
        params = ['-x', '-n', '-Z', cert_file]
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=params,
        )
        assert result.returncode == 0

    def test_ipa_migrate_stage_mode_with_invalid_cert(self):
        """
        This test checks ipa-migrate tool throws
        error when invalid cert is specified with
        -Z option
        """
        cert_file = '/tmp/invaid_cert.crt'
        invalid_cert = (
            b'-----BEGIN CERTIFICATE-----\n'
            b'MIIFazCCDQYJKoZIhvcNAQELBQAw\n'
            b'-----END CERTIFICATE-----\n'
        )
        ERR_MSG = "Failed to connect to remote server: "
        params = ['-x', '-n', '-Z', cert_file]
        self.replicas[0].put_file_contents(cert_file, invalid_cert)
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=params,
        )
        assert result.returncode == 1
        assert ERR_MSG in result.stderr_text
