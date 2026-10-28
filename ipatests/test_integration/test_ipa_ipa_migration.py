# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Integration tests to verify ipa-migrate tool
"""

from __future__ import absolute_import
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths
from ipapython.ipaldap import realm_to_serverid
from collections import Counter

import pytest
import re
import textwrap


# Test SSH public key used for migration testing
TEST_SSHKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5PsFqMAqac5uvri73wVp9B8r1oElyVMlBV"
    "pNdTZgcI test@example.test"
)

# Expected SSH key fingerprint for TEST_SSHKEY
TEST_SSHKEY_FP = "SHA256:PSDEIT8MJGMMLpyjFS1oFNcnPNB1cWf10LeJGyI2h7M"

TEST_ZONE_FORWARDER = "10.11.12.13"

# Extdom extop plugin cn=config (TestIPAMigrationPluginsMigrated)
EXTDOM_EXTOP_PLUGIN_DN = "cn=ipa_extdom_extop,cn=plugins,cn=config"
EXTDOM_EXTOP_BASEDN_ATTR = "nsslapd-basedn"
# Bogus suffix on replica only before migration (valid DN syntax).
EXTDOM_EXTOP_REPLICA_BOGUS_BASEDN = "dc=wrong,dc=value"


def prepare_ipa_server(master):
    """
    Setup remote IPA server environment
    """
    # Setup IPA users
    for i in range(1, 6):
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

    # Add SSH key to normal user
    master.run_command([
        "ipa", "user-mod", "testuser1", "--sshpubkey", TEST_SSHKEY
    ])

    # Add SSH key to staged user
    master.run_command([
        "ipa", "stageuser-mod", "tuser1", "--sshpubkey", TEST_SSHKEY
    ])

    # Add SSH key to testuser5 and preserve it
    master.run_command([
        "ipa", "user-mod", "testuser5", "--sshpubkey", TEST_SSHKEY
    ])
    master.run_command([
        "ipa", "user-del", "testuser5", "--preserve"
    ])

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
    master.run_command(["ipactl", "restart"])

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

    # Modify the default password policy
    master.run_command(
        ["ipa", "pwpolicy-mod", "--minlength=9", "--history=5"]
    )

    # Add IPA locations
    master.run_command(
        ["ipa", "location-add", "brno", "--description", "Brno office"]
    )
    master.run_command(
        ["ipa", "location-add", "raleigh", "--description", "Raleigh office"]
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
            "--sshpubkey", TEST_SSHKEY,
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
    master.run_command(
        [
            "ipa", "dnsrecord-add", "example.test", "migratetest",
            "--a-rec", "192.0.2.100",
        ]
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

    # Add DNSForwardzone
    master.run_command(
        [
            "ipa",
            "dnsforwardzone-add",
            "forwardzone.test",
            "--forwarder",
            TEST_ZONE_FORWARDER,
        ]
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
            "testvault",
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
        [
            "ipa", "passkeyconfig-mod",
            "--require-user-verification=FALSE"
        ]
    )

    # Adding automountlocation, maps, keys
    master.run_command(
        [
            "ipa", "automountlocation-add",
            "baltimore"
        ]
    )

    master.run_command(
        [
            "ipa", "automountmap-add",
            "baltimore",
            "auto.share"
        ]
    )

    master.run_command(
        [
            "ipa", "automountmap-add-indirect",
            "baltimore",
            "--parentmap=auto.share",
            "--mount=sub",
            "auto.man",
        ]
    )

    master.run_command(
        [
            "ipa", "automountkey-add",
            "baltimore",
            "auto.master",
            "--key=/share",
            "--info=auto.share",
        ]
    )

    master.run_command(
        [
            "ipa", "automountkey-add",
            "baltimore",
            "auto.share",
            "--key=export",
            "--info=-ro,soft,rsize=8192,wsize=8192 "
            f"{master.hostname}:/shared/export",
        ]
    )

    # Add sysaccount
    master.run_command(
        ["ipa", "sysaccount-add", "migrate-test-sysaccount", "--random"]
    )

    # Add custom password policy
    # Using existing testgroup for the custom password policy
    master.run_command(
        [
            "ipa", "pwpolicy-add", "testgroup",
            "--maxlife=4", "--minlife=2",
            "--history=2", "--priority=3"
        ]
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


@pytest.fixture()
def empty_log_file(request):
    """
    This fixture empties the log file before ipa-migrate tool
    is run since the log is appended everytime the tool is run.
    """
    request.cls.replicas[0].run_command(
        ["truncate", "-s", "0", paths.IPA_MIGRATE_LOG]
    )
    yield


class MigrationTest(IntegrationTest):
    """
    This class will help setup remote IPA server(cls.master)
    and local IPA server(cls.replicas[0]) and it will
    also prepare the remote IPA before migration actually begins.
    """
    num_replicas = 1
    num_clients = 1
    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        prepare_ipa_server(cls.master)
        for client in cls.clients:
            tasks.install_client(cls.master, client, nameservers=None)
        tasks.install_master(cls.replicas[0], setup_dns=True, setup_kra=True,
                             extra_args=['--allow-zone-overlap'])

        # Make sure the new server can communicate with the old one.
        hosts = cls.replicas[0].get_file_contents(paths.HOSTS, encoding='utf-8')
        hosts += f"\n{cls.master.ip}\t{cls.master.hostname}\n"
        cls.replicas[0].put_file_contents(paths.HOSTS, hosts)


class TestIPAMigrateCLIOptions(MigrationTest):
    """
    Tests to check CLI options for ipa-migrate tool with
    DNS enabled on local and remote server.
    """
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
            "Failed to bind to remote server: cannot connect to "
            "'ldap://{}':".format(hostname)
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
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        assert self.replicas[0].transport.file_exists("/tmp/test.ldif")
        assert result.returncode == 0

    def test_ipa_migrate_stage_mode_dry_run(self):
        """
        Test ipa-migrate stage mode with dry-run option
        This test also checks SIDGEN task failure is
        not seen in ipa migrate log.
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        SIDGEN_ERR_MSG = "SIDGEN task failed: \n"
        IPA_MIGRATE_STAGE_DRY_RUN_LOG = "--dryrun=True\n"
        IPA_SERVER_UPRGADE_LOG = (
            "Skipping ipa-server-upgrade in dryrun mode.\n"
        )
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
        assert SIDGEN_ERR_MSG not in install_msg

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

    def test_ipa_migrate_skip_schema_dry_run(self, empty_log_file):
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

    def test_ipa_migrate_skip_config_dry_run(self, empty_log_file):
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

    def test_ipa_migrate_stage_mode_override_schema(self, empty_log_file):
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
            """
            dn: cn={realm_name},cn=kerberos,{base_dn}
            cn: {realm_name}
            objectClass: top
            objectClass: krbrealmcontainer
            """
        ).format(
            realm_name=realm_name,
            base_dn=base_dn,
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
        """
        This fixture adds dnszone and then removes the zone.
        """
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

    def test_ipa_migrate_dns_forwardzone(self):
        """
        This testcase checks that DNS forwardzone is
        also migrated in prod-mode
        """
        zone_name = "forwardzone.test"
        result = self.replicas[0].run_command(
            ["ipa", "dnsforwardzone-show", zone_name]
        )
        assert 'Zone name: {}'.format(zone_name) in result.stdout_text
        assert 'Active zone: True' in result.stdout_text
        assert f'Zone forwarders: {TEST_ZONE_FORWARDER}' in result.stdout_text
        assert 'Forward policy: first' in result.stdout_text

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
        works without the 'ValueError'
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
        cert_file = '/tmp/invalid_cert.crt'
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


class TestIPAMigrationStageMode(MigrationTest):
    """
    Tests for ipa-migrate tool in stage mode
    """
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
        run_migrate(
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
        assert MIGRATION_SCHEMA_LOG_MSG in install_msg
        assert MIGRATION_CONFIG_LOG_MSG in install_msg
        assert IPA_UPGRADE_LOG_MSG in install_msg
        assert SIDGEN_TASK_LOG_MSG in install_msg
        assert MIGRATION_COMPLETE_LOG_MSG in install_msg

    def test_ipa_migrate_stage_mode_new_user(self):
        """
        This testcase checks that when a new user is added and
        ipa-migrate is run in stage-mode, uid/gid of the
        migrated user is not preserved i.e we have different
        uid/gid for user on remote and local IPA server.
        """
        username = 'testuser4'
        base_dn = str(self.master.domain.basedn)
        LOG_MSG1 = (
            "DEBUG Resetting the DNA range for new entry: "
            "uid={},cn=users,cn=accounts,{}\n"
        ).format(username, base_dn)
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert LOG_MSG1 not in install_msg
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['ipa', 'user-show', username])
        cmd1 = self.master.run_command(['id', username])
        tasks.clear_sssd_cache(self.replicas[0])
        self.replicas[0].run_command(['ipa', 'user-show', username])
        cmd2 = self.replicas[0].run_command(['id', username])
        assert cmd1.stdout_text != cmd2.stdout_text


class TestIPAMigrationProdMode(MigrationTest):
    """
    Tests for ipa-migrate tool in prod mode
    """
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
            extra_args=['-B', '-n'],
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert result.returncode == 0
        assert MIGRATION_SCHEMA_LOG_MSG in install_msg
        assert MIGRATION_DATABASE_LOG_MSG in install_msg
        assert IPA_UPGRADE_LOG_MSG in install_msg
        assert SIDGEN_TASK_LOG_MSG in install_msg

    def test_ipa_migrate_prod_mode_hbac_rule(self):
        """
        This testcase checks that hbac rule is migrated from
        remote server to local server in prod mode.
        """
        hbac_rule_name1 = 'test1'
        hbac_rule_name2 = 'testuser_sshd'
        tasks.kinit_admin(self.replicas[0])
        cmd1 = self.replicas[0].run_command(
            ["ipa", "hbacrule-find", hbac_rule_name1])
        cmd2 = self.replicas[0].run_command(
            ["ipa", "hbacrule-find", hbac_rule_name2])
        assert hbac_rule_name1 in cmd1.stdout_text
        assert hbac_rule_name2 in cmd2.stdout_text

    def test_ipa_migrate_prod_mode_sudo_rule(self):
        """
        This testcase checks that sudo cmd and rules are
        migrated from remote server to local server in prod mode.
        """
        sudorule = 'readfiles'
        sudocmd = '/usr/bin/less'
        tasks.kinit_admin(self.replicas[0])
        cmd1 = self.replicas[0].run_command(
            ["ipa", "sudorule-find", sudorule])
        cmd2 = self.replicas[0].run_command(
            ["ipa", "sudocmd-find", sudocmd])
        assert 'Rule name: readfiles\n' in cmd1.stdout_text
        assert 'Sudo Command: /usr/bin/less\n' in cmd2.stdout_text

    def test_ipa_migrate_prod_mode_roles_privileges(self):
        """
        Test that IPA roles are migrated from remote to local server
        """
        role_name = "junioradmin"
        privilege_name = "User Administrators"
        tasks.kinit_admin(self.replicas[0])
        result = self.replicas[0].run_command(
            ["ipa", "role-show", role_name]
        )
        assert "Role name: {}".format(role_name) in result.stdout_text
        assert "Privileges: {}".format(privilege_name) in result.stdout_text

    def test_ipa_migrate_prod_mode_permission(self):
        """
        Test that PBAC permission is migrated
        """
        permission_name = "Add Users"
        tasks.kinit_admin(self.replicas[0])
        result = self.replicas[0].run_command(
            ["ipa", "permission-show", permission_name]
        )
        assert (f"Permission name: {permission_name}" in
                result.stdout_text)

    def test_ipa_migrate_prod_mode_sysaccounts(self):
        """
        Test that system accounts (sysaccounts) are migrated
        from remote server to local server in prod mode.
        """
        sysaccount_name = "migrate-test-sysaccount"
        tasks.kinit_admin(self.replicas[0])
        result = self.replicas[0].run_command(
            ["ipa", "sysaccount-show", sysaccount_name]
        )
        assert sysaccount_name in result.stdout_text
        assert (f"System account ID: {sysaccount_name}" in
                result.stdout_text)

    def test_ipa_migrate_prod_mode_selinuxusermap(self):
        """
        Test that SELinux usermap is migrated from remote
        to local server.
        """
        usermap_name = "test1"
        tasks.kinit_admin(self.replicas[0])
        result = self.replicas[0].run_command(
            ["ipa", "selinuxusermap-show", usermap_name]
        )
        assert result.returncode == 0
        assert f"Rule name: {usermap_name}" in result.stdout_text
        assert "xguest_u:s0" in result.stdout_text

    def test_ipa_migrate_prod_mode_new_user_sid(self):
        """
        This testcase checks that in prod-mode uid/gid of the
        migrated user is preserved i.e we have same
        uid/gid for user on remote and local IPA server.
        """
        username = 'testuser4'
        tasks.clear_sssd_cache(self.master)
        result1 = self.master.run_command(['id', username])
        tasks.clear_sssd_cache(self.replicas[0])
        result2 = self.replicas[0].run_command(['id', username])
        assert result1.stdout_text == result2.stdout_text

    def test_check_vault_is_not_migrated(self):
        """
        This testcase checks that vault is
        not migrated
        """
        vault_name = "testvault"
        CMD_OUTPUT = "Number of entries returned 0"
        cmd = self.replicas[0].run_command(
            ["ipa", "vault-find", vault_name], raiseonerr=False)
        assert cmd.returncode != 0
        assert CMD_OUTPUT in cmd.stdout_text

    def test_ipa_migrate_subids(self):
        """
        This testcase checks that subids for users are migrated
        to the local server from the remote server
        """
        user_name = 'admin'
        CMD_MSG = "1 subordinate id matched"
        cmd = self.replicas[0].run_command(
            ['ipa', 'subid-find',
             '--owner', user_name]
        )
        assert cmd.returncode == 0
        assert CMD_MSG in cmd.stdout_text

    def test_ipa_hbac_rule_duplication(self):
        """
        This testcase checks that default hbac rules
        are not duplicated on the local server when
        ipa-migrate command is run.
        """
        result = self.replicas[0].run_command(
            ['ipa', 'hbacrule-find']
        )
        lines = result.stdout_text.splitlines()
        line = []
        for i in lines:
            line.append(i.strip())
        count = Counter(line)
        assert count.get('Rule name: allow_all') < 2
        assert count.get('Rule name: allow_systemd-user') < 2

    def test_ipa_migrate_otptoken(self):
        """
        This testcase checks that the otptoken
        is migrated for the user.
        """
        owner = "testuser1"
        CMD_OUTPUT = "1 OTP token matched"
        result = self.replicas[0].run_command([
            "ipa", "otptoken-find"
        ])
        assert CMD_OUTPUT in result.stdout_text
        assert 'Type: TOTP' in result.stdout_text
        assert 'Owner: {}'.format(owner) in result.stdout_text

    def test_ipa_migrate_check_passkey_config(self):
        """
        This testcase checks that passkey config
        is migrated
        """
        CMD_OUTPUT = "Require user verification: False"
        result = self.replicas[0].run_command([
            "ipa", "passkeyconfig-show"
        ])
        assert CMD_OUTPUT in result.stdout_text

    def test_ipa_migrate_custom_pwpolicy(self):
        """
        This testcase checks that custom password policies
        are migrated from remote server to local server in prod mode.
        """
        policy_name = "testgroup"
        result = self.replicas[0].run_command([
            "ipa", "pwpolicy-show", policy_name
        ])
        assert result.returncode == 0
        assert f"Group: {policy_name}" in result.stdout_text
        assert "Max lifetime (days): 4" in result.stdout_text
        assert "Min lifetime (hours): 2" in result.stdout_text
        assert "History size: 2" in result.stdout_text
        assert "Priority: 3" in result.stdout_text

        # Verify that the corresponding COS template entry was also migrated
        cosdn = f"cn=costemplates,cn=accounts,{self.replicas[0].domain.basedn}"
        ldap_result = self.replicas[0].run_command([
            "ldapsearch", "-Y", "GSSAPI",
            "-b", cosdn,
            "(krbPwdPolicyReference=*testgroup*)"
        ])
        assert ldap_result.returncode == 0
        assert "krbPwdPolicyReference:" in ldap_result.stdout_text
        assert "costemplate" in ldap_result.stdout_text.lower()

    def test_ipa_migrate_default_pwpolicy(self):
        """
        This testcase checks that the default (global) password policy
        modifications are migrated from remote server to local server
        in prod mode.
        """
        result = self.replicas[0].run_command([
            "ipa", "pwpolicy-show"
        ])
        assert result.returncode == 0
        assert "Min length: 9" in result.stdout_text
        assert "History size: 5" in result.stdout_text

    def test_ipa_migrate_check_service_status(self):
        """
        This testcase checks that ipactl and sssd
        services are running post ipa-migrate tool
        successful runs completed
        """
        cmd1 = self.replicas[0].run_command([
            "ipactl", "status"
        ])
        assert cmd1.returncode == 0
        cmd2 = self.replicas[0].run_command([
            "systemctl", "status", "sssd"
        ])
        assert cmd2.returncode == 0

    def test_custom_idrange_is_migrated(self):
        """
        This testcase checks that custom idrange is migrated
        from remote server to local server in production
        mode.
        """
        range_name = "testrange"
        CMD_OUTPUT = (
            "---------------\n"
            "1 range matched\n"
            "---------------\n"
            "  Range name: testrange\n"
            "  First Posix ID of the range: 10000\n"
            "  Number of IDs in the range: 10000\n"
            "  First RID of the corresponding RID range: 300000\n"
            "  First RID of the secondary RID range: 400000\n"
            "  Range type: local domain range\n"
            "----------------------------\n"
            "Number of entries returned 1\n"
            "----------------------------\n"
        )
        cmd = self.replicas[0].run_command(
            ["ipa", "idrange-find", range_name])
        assert CMD_OUTPUT in cmd.stdout_text

    def test_automountlocation_is_migrated(self):
        """
        This testcase checks that automount location/maps
        and keys are migrated.
        """
        base_dn = str(self.master.domain.basedn)
        automount_cn = "automount"
        loc_name = "baltimore"
        auto_map_name = "auto.share"
        DEBUG_LOG = (
            "Added entry: cn={},cn={},{}\n"
        ).format(loc_name, automount_cn, base_dn)
        CMD1_OUTPUT = (
            "  Location: baltimore\n"
        )
        CMD2_OUTPUT = (
            "  Map: auto.share\n"
        )
        CMD3_OUTPUT = (
            "------------------------\n"
            "2 automount keys matched\n"
            "------------------------\n"
            "  Key: export\n"
            "  Mount information: -ro,soft,rsize=8192,wsize=8192 "
            f"{self.master.hostname}:/shared/export\n\n"
            "  Key: sub\n"
            "  Mount information: -fstype=autofs ldap:auto.man\n"
            "----------------------------\n"
            "Number of entries returned 2\n"
            "----------------------------\n"
        )
        cmd1 = self.replicas[0].run_command(
            ["ipa", "automountlocation-show", loc_name])
        cmd2 = self.replicas[0].run_command(
            ["ipa", "automountmap-find", loc_name])
        cmd3 = self.replicas[0].run_command(
            ["ipa", "automountkey-find", loc_name, auto_map_name]
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert CMD1_OUTPUT in cmd1.stdout_text
        assert CMD2_OUTPUT in cmd2.stdout_text
        assert CMD3_OUTPUT in cmd3.stdout_text
        assert DEBUG_LOG in install_msg

    def test_ipa_locations_are_migrated(self):
        """
        This testcase checks that IPA locations are migrated
        from remote server to local server in prod mode.
        """
        location1 = 'brno'
        location2 = 'raleigh'
        tasks.kinit_admin(self.replicas[0])
        cmd1 = self.replicas[0].run_command(
            ["ipa", "location-find", location1])
        cmd2 = self.replicas[0].run_command(
            ["ipa", "location-find", location2])
        assert 'Location name: brno\n' in cmd1.stdout_text
        assert 'Description: Brno office\n' in cmd1.stdout_text
        assert 'Location name: raleigh\n' in cmd2.stdout_text
        assert 'Description: Raleigh office\n' in cmd2.stdout_text

    def test_sshpubkey_migration_for_user(self):
        """
        This testcase checks that SSH public key is migrated
        for a normal user.
        """
        username = "testuser1"
        result = self.replicas[0].run_command(
            ["ipa", "user-show", username]
        )
        # Default output shows fingerprint, not the full key
        expected_fp = "SSH public key fingerprint: {}".format(
            TEST_SSHKEY_FP
        )
        assert expected_fp in result.stdout_text
        assert "test@example.test" in result.stdout_text
        assert "(ssh-ed25519)" in result.stdout_text

    def test_sshpubkey_migration_for_stageuser(self):
        """
        This testcase checks that SSH public key is migrated
        for a staged user.
        """
        username = "tuser1"
        result = self.replicas[0].run_command(
            ["ipa", "stageuser-show", username]
        )
        # Default output shows fingerprint, not the full key
        expected_fp = "SSH public key fingerprint: {}".format(
            TEST_SSHKEY_FP
        )
        assert expected_fp in result.stdout_text
        assert "test@example.test" in result.stdout_text
        assert "(ssh-ed25519)" in result.stdout_text

    def test_sshpubkey_migration_for_preserved_user(self):
        """
        This testcase checks that SSH public key is migrated
        for a preserved user (deleted with --preserve).
        """
        username = "testuser5"
        result = self.replicas[0].run_command(
            ["ipa", "user-show", username]
        )
        # Default output shows fingerprint, not the full key
        expected_fp = "SSH public key fingerprint: {}".format(
            TEST_SSHKEY_FP
        )
        assert expected_fp in result.stdout_text
        assert "test@example.test" in result.stdout_text
        assert "(ssh-ed25519)" in result.stdout_text

    def test_sshpubkey_migration_for_idoverride(self):
        """
        This testcase checks that SSH public key is migrated
        for a user ID override.
        Note: Outputs are different from user's ones
        """
        idview_name = "idview1"
        username = "testuser1"
        result = self.replicas[0].run_command(
            ["ipa", "idoverrideuser-show", idview_name, username]
        )
        # Default output shows fingerprint, not the full key
        expected_fp = "SSH public key: {}".format(TEST_SSHKEY)
        assert expected_fp in result.stdout_text
        assert "test@example.test" in result.stdout_text
        assert "ssh-ed25519" in result.stdout_text

    def test_ipa_migrate_skip_replication_conflicts(self):
        """
        Test that ipa-migrate skips replication conflict entries
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])

        # Get DS instance name
        instance_name = realm_to_serverid(self.master.domain.realm)

        # Stop IPA on master to export database
        self.master.run_command(['ipactl', 'stop'])

        # Export database using dsctl
        ldif_file = "/tmp/userroot.ldif"
        self.master.run_command([
            'dsctl', instance_name, 'db2ldif', 'userroot', ldif_file
        ])

        # Start IPA back on master
        self.master.run_command(['ipactl', 'start'])

        # Copy LDIF to replica
        ldif_content = self.master.get_file_contents(
            ldif_file, encoding="utf-8"
        )
        replica_ldif = "/tmp/userroot_with_conflict.ldif"

        # Add mocked replication conflict entry to the LDIF
        users_dn = "cn=users,cn=accounts," + str(self.master.domain.basedn)
        conflict_entry = textwrap.dedent(
            """
            # entry-id: 12345678
            dn: nsuniqueid=12345678-1234+uid=conflictuser,{users_dn}
            uid: conflictuser
            cn: Conflict User
            uidNumber: 1234
            gidNumber: 1234
            sn: User
            objectClass: top
            objectClass: person
            objectClass: inetorgperson
            objectClass: nsds5replconflict
            nsds5ReplConflict: namingConflict uid=conflictuser,{users_dn}

            """
        ).format(users_dn=users_dn)

        # Append conflict entry to LDIF
        modified_ldif = ldif_content + conflict_entry
        self.replicas[0].put_file_contents(replica_ldif, modified_ldif)

        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=["-f", replica_ldif, "-n", "-x"],
        )

        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )

        assert result.returncode == 0
        assert "Skipping replication conflict entry" in install_msg


class TestIPAMigrationDNSRecords(MigrationTest):
    """
    Tests to verify all DNS zones, forward zones, and DNS records
    are migrated when ipa-migrate is run with --migrate-dns (-B).
    "By default all DNS entries are migrated" / -B to migrate DNS.
    """
    num_replicas = 1
    num_clients = 1
    topology = "line"

    @pytest.fixture(autouse=True)
    def run_migration_with_dns(self):
        """
        Run full prod-mode migration with -B so that DNS is migrated
        to the local server. All tests in this class assume DNS has
        been migrated.
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=["-B", "-n"],
        )

    def test_dns_zone_example_test_migrated(self):
        """
        Check that DNS zone example.test (from prepare_ipa_server)
        is migrated to the local server.
        """
        zone_name = "example.test"
        result = self.replicas[0].run_command(
            ["ipa", "dnszone-show", zone_name]
        )
        assert result.returncode == 0
        assert "Zone name: {}".format(zone_name) in result.stdout_text

    def test_dns_zone_dynamic_update_preserved(self):
        """
        Check that zone attribute dynamic update is preserved
        (prepare_ipa_server sets dynamic-update=TRUE for example.test).
        """
        zone_name = "example.test"
        result = self.replicas[0].run_command(
            ["ipa", "dnszone-show", zone_name]
        )
        assert result.returncode == 0
        assert "Dynamic update: True" in result.stdout_text

    def test_dns_zone_has_system_records(self):
        """
        Check that migrated zone has system records (NS/SOA).
        """
        zone_name = "example.test"
        result = self.replicas[0].run_command(
            ["ipa", "dnsrecord-find", zone_name]
        )
        assert result.returncode == 0
        # Zone should have records (e.g. NS, SOA, or record list)
        assert (
            "NS record" in result.stdout_text
            or "SOA record" in result.stdout_text
            or "Record name" in result.stdout_text
        )

    def test_dns_record_a_migrated(self):
        """
        Verify that the A record added in prepare_ipa_server is
        migrated to the local server.
        """
        zone_name = "example.test"
        record_name = "migratetest"
        record_value = "192.0.2.100"
        result = self.replicas[0].run_command(
            ["ipa", "dnsrecord-show", zone_name, record_name]
        )
        assert record_name in result.stdout_text
        assert record_value in result.stdout_text


class TestIPAMigrationWithADtrust(IntegrationTest):
    """
    Test for ipa-migrate tool with IPA Master having trust setup
    with Windows AD.
    """
    topology = "line"
    num_ad_domains = 1
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            cls.master, setup_dns=True, extra_args=['--no-dnssec-validation']
        )
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

    def test_install_local_server(self):
        """
        This test installs local IPA Server() i.e new IPA server with
        the same realm and domain name that will receive the migration data.
        """
        tasks.install_master(
            self.replicas[0], setup_dns=True,
            extra_args=['--no-dnssec-validation', '--allow-zone-overlap']
        )
        tasks.install_adtrust(self.replicas[0])

    def test_check_ad_attributes_migrate_prod_mode(self):
        """
        This test checks that IPA-AD trust related attributes
        are migrated to local server.
        """
        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=['-n']
        )
        assert result.returncode == 0
        trust1 = self.master.run_command(
            ['ipa', 'trust-show', self.ad_domain]
        ).stdout_text
        trust2 = self.replicas[0].run_command(
            ['ipa', 'trust-show', self.ad_domain]).stdout_text
        assert trust1 == trust2

    def test_check_domain_sid_is_migrated(self):
        """
        This testcase checks that domain sid is
        migrated from a remote server having trust with AD
        to local server and is displayed in the
        ipa trustconfig-show command
        """
        regexp = (r'Security Identifier: (.*)$')
        cmd1 = self.master.run_command(["ipa", "trustconfig-show"])
        sid1 = re.findall(regexp, cmd1.stdout_text, re.MULTILINE)
        cmd2 = self.replicas[0].run_command(
            ["ipa", "trustconfig-show"]
        )
        sid2 = re.findall(regexp, cmd2.stdout_text, re.MULTILINE)
        assert sid1 == sid2

    def test_check_ad_idrange_is_migrated(self):
        """
        This testcase checks AD idrange is migrated
        from remote IPA server having trust with AD
        to local IPA server
        """
        ad_domain_name = self.ad.domain.name.upper()
        cmd1 = self.master.run_command(
            ["ipa", "idrange-show", ad_domain_name + "_id_range"]
        )
        cmd2 = self.replicas[0].run_command(
            ["ipa", "idrange-show", ad_domain_name + "_id_range"]
        )
        assert cmd1.stdout_text == cmd2.stdout_text


class TestIPAMigratewithBackupRestore(IntegrationTest):
    """
    Test for ipa-migrate tool with backup files.
    The master and replicas[1] are used to create the data source.
    The replicas[0] is used as new server, retrieving data from the source.
    replicas[1] is needed to make sure that the source LDIF
    file contains replication attributes with
    options (for instance objectClass;vucsn-67f7b3de000300030000).
    """
    num_replicas = 2
    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        prepare_ipa_server(cls.master)
        tasks.install_master(cls.replicas[0], setup_dns=True, setup_kra=True,
                             extra_args=['--allow-zone-overlap'])
        tasks.install_replica(cls.master, cls.replicas[1],
                              setup_dns=True, setup_kra=True)

    @pytest.fixture
    def create_delete_user(self):
        """
        This fixtures creates a ldapuser using the
        ldif file and then delete the users
        """
        self.master.run_command(['ipa', 'user-add', 'testuser',
                                 '--first', 'test',
                                 '--last', 'user'])
        self.master.run_command(['ipa', 'user-del', 'testuser'])
        yield

    def test_ipa_migrate_stage_mode(self, create_delete_user):
        """
        This test checks ipa-migrate with LDIF file
        from backup of remote server is successful.
        """
        ERR_MSG = (
            "error: change collided with another change"
        )
        dashed_domain_name = self.master.domain.realm.replace(
            ".", '-'
        )
        DB_LDIF_FILE = '{}-userRoot.ldif'.format(
            dashed_domain_name
        )
        SCHEMA_LDIF_FILE = "{}/config_files/schema/99user.ldif".format(
            dashed_domain_name)
        CONFIG_LDIF_FILE = "{}/config_files/dse.ldif".format(
            dashed_domain_name)
        param = [
            '-n', '-g', CONFIG_LDIF_FILE, '-m', SCHEMA_LDIF_FILE,
            '-f', DB_LDIF_FILE
        ]
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        backup_path = tasks.get_backup_dir(self.master)
        remote_ipa_tar_file = backup_path + '/ipa-full.tar'
        ipa_tar_file = self.master.get_file_contents(
            remote_ipa_tar_file
        )
        replica_file_name = "/tmp/ipa-full.tar"
        self.replicas[0].put_file_contents(
            replica_file_name, ipa_tar_file
        )
        self.replicas[0].run_command(
            ['/usr/bin/tar', '-xvf', replica_file_name]
        )
        result = run_migrate(
            self.replicas[0],
            "stage-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=param,
        )
        assert result.returncode == 0
        assert ERR_MSG not in result.stderr_text


class TestIPAMigrationMixedOnlineOffline(MigrationTest):
    """
    Tests for IPA-to-IPA migration with mixed online and offline method:
    config and schema migrated online, database from remote backup LDIF.
    """
    num_replicas = 1
    num_clients = 0
    topology = "line"

    def test_ipa_migrate_mixed_online_offline(self):
        """
        Run mixed migration (config/schema online, DB from LDIF) and verify
        success, log phases, and that migrated data is present on local.
        """
        dashed_domain_name = (
            self.master.domain.realm.replace(".", "-")
        )
        DB_LDIF_FILE = "{}-userRoot.ldif".format(dashed_domain_name)
        known_user = "testuser1"

        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])

        backup_path = tasks.get_backup_dir(self.master)
        remote_ipa_tar_file = backup_path + "/ipa-full.tar"
        ipa_tar_file = self.master.get_file_contents(
            remote_ipa_tar_file
        )
        replica_file_name = "/tmp/ipa-full.tar"
        self.replicas[0].put_file_contents(
            replica_file_name, ipa_tar_file
        )
        self.replicas[0].run_command(
            ["/usr/bin/tar", "-xvf", replica_file_name]
        )

        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=["-f", DB_LDIF_FILE, "-n"],
        )
        assert result.returncode == 0

        install_msg = self.replicas[0].get_file_contents(
            paths.IPA_MIGRATE_LOG, encoding="utf-8"
        )
        assert "--db-ldif={}".format(DB_LDIF_FILE) in install_msg
        assert "Migrating schema" in install_msg
        assert "Migrating configuration" in install_msg

        show_result = self.replicas[0].run_command(
            ["ipa", "user-show", known_user]
        )
        assert "User login: {}".format(known_user) in (
            show_result.stdout_text)


class TestIPAMigrationPluginsMigrated(MigrationTest):
    """
    Tests that ipa-migrate carries cn=config attributes listed for the
    Extdom extop plugin.

    Before migration the replica's ``nsslapd-basedn`` on
    ``cn=ipa_extdom_extop,cn=plugins,cn=config`` is set to a bogus DN; the
    source keeps the real IPA suffix. After prod-mode migration the replica
    must match the source for that attribute.
    """
    num_replicas = 1
    num_clients = 0
    topology = "line"

    @pytest.fixture(scope="class", autouse=True)
    def run_prod_mode_migration(self, mh):
        """Diverge extdom nsslapd-basedn on replica.
        """
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        ldif_template = (
            "dn: {dn}\n"
            "changetype: modify\n"
            "replace: {attr}\n"
            "{attr}: {value}\n"
        )
        tasks.ldapmodify_dm(
            self.replicas[0],
            ldif_template.format(
                dn=EXTDOM_EXTOP_PLUGIN_DN,
                attr=EXTDOM_EXTOP_BASEDN_ATTR,
                value=EXTDOM_EXTOP_REPLICA_BOGUS_BASEDN,
            ),
        )
        result = run_migrate(
            self.replicas[0],
            "prod-mode",
            self.master.hostname,
            "cn=Directory Manager",
            self.master.config.admin_password,
            extra_args=["-n"],
        )
        assert result.returncode == 0, (
            "ipa-migrate failed (returncode={}): {}"
            .format(result.returncode,
                    result.stderr_text or result.stdout_text)
        )

    def test_plugin_config_migrated(self):
        """
        Replica extdom `nsslapd-basedn` matches source
        after migration.
        """
        expected = str(self.master.domain.basedn)
        result = tasks.ldapsearch_dm(
            self.replicas[0],
            EXTDOM_EXTOP_PLUGIN_DN,
            [EXTDOM_EXTOP_BASEDN_ATTR],
            scope="base",
            raiseonerr=False,
        )
        assert re.search(
            r"^{}:\s*{}$".format(
                re.escape(EXTDOM_EXTOP_BASEDN_ATTR),
                re.escape(expected),
            ),
            result.stdout_text,
            re.IGNORECASE | re.MULTILINE,
        ), (
            "Expected {}={} on replica after migration; got:\n{}"
            .format(EXTDOM_EXTOP_BASEDN_ATTR, expected, result.stdout_text)
        )
