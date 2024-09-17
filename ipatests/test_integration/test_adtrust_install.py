#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for ipa-adtrust-install utility"""

import re
import os
import textwrap
import subprocess

from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from pkg_resources import parse_version

import pytest

class TestIpaAdTrustInstall(IntegrationTest):
    topology = 'line'
    num_replicas = 1

    def unconfigure_replica_as_agent(self, host):
        """ Remove a replica from the list of agents.

        cn=adtrust agents,cn=sysaccounts,cn=etc,$BASEDN contains a list
        of members representing the agents. Remove the replica principal
        from this list.
        This is a hack allowing to run multiple times
        ipa-adtrust-install --add-agents
        (otherwise if the replica is in the list of agents, it won't be seen
        as a possible agent to be added).
        """
        remove_agent_ldif = textwrap.dedent("""
             dn: cn=adtrust agents,cn=sysaccounts,cn=etc,{base_dn}
             changetype: modify
             delete: member
             member: fqdn={hostname},cn=computers,cn=accounts,{base_dn}
             """.format(base_dn=host.domain.basedn, hostname=host.hostname))
        # ok_returncode =16 if the attribute is not present
        tasks.ldapmodify_dm(self.master, remove_agent_ldif,
                            ok_returncode=[0, 16])

    def test_samba_config_file(self):
        """Check that ipa-adtrust-install generates sane smb.conf
        This is regression test for issue
        https://pagure.io/freeipa/issue/6951
        """
        self.master.run_command(
            ['ipa-adtrust-install', '-a', self.master.config.admin_password,
             '--add-sids', '-U'])
        res = self.master.run_command(['testparm', '-s'])
        assert 'ERROR' not in (res.stdout_text + res.stderr_text)

    def test_add_agent_not_allowed(self):
        """Check that add-agents can be run only by Admins."""
        user = "nonadmin"
        passwd = "Secret123"
        host = self.replicas[0].hostname
        data_fmt = '{{"method":"trust_enable_agent","params":[["{}"],{{}}]}}'

        try:
            # Create a nonadmin user that will be used by curl.
            # First, display SSSD kdcinfo:
            # https://bugzilla.redhat.com/show_bug.cgi?id=1850445#c1
            self.master.run_command([
                "cat",
                "/var/lib/sss/pubconf/kdcinfo.%s" % self.master.domain.realm
            ], raiseonerr=False)
            # Set krb5_trace to True: https://pagure.io/freeipa/issue/8353
            tasks.create_active_user(
                self.master, user, passwd, first=user, last=user,
                krb5_trace=True
            )
            tasks.kinit_as_user(self.master, user, passwd, krb5_trace=True)

            # curl --negotiate -u : is using GSS-API i.e. nonadmin user
            cmd_args = [
                paths.BIN_CURL,
                '-H', 'referer:https://{}/ipa'.format(host),
                '-H', 'Content-Type:application/json',
                '-H', 'Accept:applicaton/json',
                '--negotiate', '-u', ':',
                '--cacert', paths.IPA_CA_CRT,
                '-d', data_fmt.format(host),
                '-X', 'POST', 'https://{}/ipa/json'.format(host)]
            res = self.master.run_command(cmd_args)
            expected = 'Insufficient access: not allowed to remotely add agent'
            assert expected in res.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    def test_add_agent_on_stopped_replica(self):
        """ Check ipa-adtrust-install --add-agents when the replica is stopped.

        Scenario: stop a replica
        Call ipa-adtrust-install --add-agents and configure the stopped replica
        as a new agent.
        The tool must detect that the replica is stopped and warn that
        a part of the configuration failed.

        Test for https://pagure.io/freeipa/issue/8148
        """
        self.unconfigure_replica_as_agent(self.replicas[0])
        self.replicas[0].run_command(['ipactl', 'stop'])

        try:
            cmd = ['ipa-adtrust-install', '--add-agents']
            with self.master.spawn_expect(cmd) as e:
                e.expect('admin password:')
                e.sendline(self.master.config.admin_password)
                # WARNING: The smb.conf already exists.
                # Running ipa-adtrust-install
                # will break your existing samba configuration.
                # Do you wish to continue? [no]:
                e.expect([
                    'smb\\.conf detected.+Overwrite smb\\.conf\\?',
                    'smb\\.conf already exists.+Do you wish to continue\\?'])
                e.sendline('yes')
                e.expect_exact('Enable trusted domains support in slapi-nis?')
                e.sendline('no')
                # WARNING: 1 IPA masters are not yet able to serve information
                # about users from trusted forests.
                # Installer can add them to the list of IPA masters allowed to
                # access information about trusts.
                # If you choose to do so, you also need to restart LDAP
                # service on
                # those masters.
                # Refer to ipa-adtrust-install(1) man page for details.
                # IPA master[replica1.testrelm.test]?[no]:
                e.expect('Installer can add them to the list of IPA masters '
                         'allowed to access information about trusts.+'
                         'IPA master \\[{}\\]'
                         .format(re.escape(self.replicas[0].hostname)),
                         timeout=120)
                e.sendline('yes')
                e.expect('"ipactl restart".+"systemctl restart sssd".+'
                         + re.escape(self.replicas[0].hostname),
                         timeout=60)
                e.expect_exit(ignore_remaining_output=True)
        finally:
            self.replicas[0].run_command(['ipactl', 'start'])

    def test_add_agent_on_running_replica_without_compat(self):
        """ Check ipa-adtrust-install --add-agents when the replica is running

        Scenario: replica up and running
        Call ipa-adtrust-install --add-agents and configure the replica as
        a new agent.
        The Schema Compat plugin must be automatically configured on the
        replica.
        """
        self.unconfigure_replica_as_agent(self.replicas[0])
        cmd = ['ipa-adtrust-install', '--add-agents']
        with self.master.spawn_expect(cmd) as e:
            e.expect_exact('admin password:')
            e.sendline(self.master.config.admin_password)
            # WARNING: The smb.conf already exists.
            # Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            e.expect([
                'smb\\.conf detected.+Overwrite smb\\.conf\\?',
                'smb\\.conf already exists.+Do you wish to continue\\?'])
            e.sendline('yes')
            e.expect_exact('Enable trusted domains support in slapi-nis?')
            e.sendline('no')
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            e.expect('Installer can add them to the list of IPA masters '
                     'allowed to access information about trusts.+'
                     'IPA master \\[{}\\]'
                     .format(re.escape(self.replicas[0].hostname)),
                     timeout=120)
            e.sendline('yes')
            e.expect_exit(ignore_remaining_output=True, timeout=60)
            output = e.get_last_output()
        assert 'Setup complete' in output
        # The replica must have been restarted automatically, no msg required
        assert 'ipactl restart' not in output

    def test_add_agent_on_running_replica_with_compat(self):
        """ Check ipa-addtrust-install --add-agents when the replica is running

        Scenario: replica up and running
        Call ipa-adtrust-install --add-agents --enable-compat and configure
        the replica as a new agent.
        The Schema Compat plugin must be automatically configured on the
        replica.
        """
        self.unconfigure_replica_as_agent(self.replicas[0])

        cmd = ['ipa-adtrust-install', '--add-agents', '--enable-compat']
        with self.master.spawn_expect(cmd) as e:
            e.expect_exact('admin password:')
            e.sendline(self.master.config.admin_password)
            # WARNING: The smb.conf already exists.
            # Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            e.expect([
                'smb\\.conf detected.+Overwrite smb\\.conf\\?',
                'smb\\.conf already exists.+Do you wish to continue\\?'])
            e.sendline('yes')
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            e.expect('Installer can add them to the list of IPA masters '
                     'allowed to access information about trusts.+'
                     'IPA master \\[{}\\]'
                     .format(re.escape(self.replicas[0].hostname)),
                     timeout=120)
            e.sendline('yes')
            e.expect_exit(ignore_remaining_output=True, timeout=60)
            output = e.get_last_output()
        assert 'Setup complete' in output
        # The replica must have been restarted automatically, no msg required
        assert 'ipactl restart' not in output

        # Ensure that the schema compat plugin is configured:
        conn = self.replicas[0].ldap_connect()
        entry = conn.get_entry(DN(
            "cn=users,cn=Schema Compatibility,cn=plugins,cn=config"))
        assert entry.single_value['schema-compat-lookup-nsswitch'] == "user"
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))
        assert entry.single_value['schema-compat-lookup-nsswitch'] == "group"

    def test_schema_compat_attribute(self):
        """Test if schema-compat-entry-attribute is set

        This is to ensure if said entry is set after installation with AD.

        related: https://pagure.io/freeipa/issue/8193
        """
        conn = self.replicas[0].ldap_connect()
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))
        entry_list = list(entry['schema-compat-entry-attribute'])
        value = (r'ipaexternalmember=%deref_r('
                 '"member","ipaexternalmember")')
        assert value in entry_list

    def test_ipa_user_pac(self):
        """Test that a user can request a service ticket with PAC"""
        user = 'testpacuser'
        user_princ = '@'.join([user, self.master.domain.realm])
        passwd = 'Secret123'
        # Create a user with a password
        tasks.create_active_user(
            self.master, user, passwd,
            extra_args=["--homedir", "/home/{}".format(user)],
            krb5_trace=True
        )
        try:
            # Defaults: host/... principal for service
            # keytab in /etc/krb5.keytab
            self.master.run_command(["kinit", '-k'])
            # Don't use enterprise principal here because it doesn't work
            # bug in krb5: src/lib/gssapi/krb5/acquire_cred.c:scan_cache()
            # where enterprise principals aren't taken into account
            result = self.master.run_command(
                [os.path.join(paths.LIBEXEC_IPA_DIR, "ipa-print-pac"),
                 "ticket", user_princ],
                stdin_text=(passwd + '\n'), raiseonerr=False
            )
            assert "PAC_DATA" in result.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    def test_ipa_user_s4u2self_pac(self):
        """Test that a service can request S4U2Self ticket with PAC"""
        user = 'tests4u2selfuser'
        user_princ = '@'.join([user, self.master.domain.realm])
        passwd = 'Secret123'
        # Create a user with a password
        tasks.create_active_user(
            self.master, user, passwd,
            extra_args=["--homedir", "/home/{}".format(user)],
            krb5_trace=True
        )
        try:
            # Defaults: host/... principal for service
            # keytab in /etc/krb5.keytab
            self.master.run_command(["kinit", '-k'])
            result = self.master.run_command(
                [os.path.join(paths.LIBEXEC_IPA_DIR, "ipa-print-pac"),
                 "-E", "impersonate", user_princ],
                raiseonerr=False
            )
            assert "PAC_DATA" in result.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    @pytest.mark.parametrize('netbios_name', ['testrelm', '.TESTRELM',
                                              'Te!5@relm', 'TEST.REALM'])
    def test_adtrust_install_with_incorrect_netbios_name(self, netbios_name):
        """
        Test that ipa-adtrust-install returns an
        error when an incorrect netbios name is provided
        """
        msg = (
            "ipaserver.install.adtrust: ERROR    \n"
            "Illegal NetBIOS name [{}].\n\n"
            "ipaserver.install.adtrust: ERROR    "
            "Up to 15 characters and only uppercase "
            "ASCII letters, digits and dashes are allowed."
            " Empty string is not allowed.\n"
            "Aborting installation.\n"
        ).format(netbios_name)
        result = self.master.run_command(
            [
                "ipa-adtrust-install",
                "-a",
                self.master.config.admin_password,
                "--netbios-name",
                netbios_name,
                "-U",
            ],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert msg in result.stderr_text

    def test_adtrust_install_with_numerical_netbios_name(self):
        """
        Test that ipa-adtrust-install works with numerical
        netbios name
        """
        netbios_name = '1234567'
        msg = (
            'NetBIOS domain name will be changed to 1234567'
        )
        result = self.master.run_command(
            [
                "ipa-adtrust-install",
                "-a",
                self.master.config.admin_password,
                "--netbios-name",
                netbios_name,
                "-U",
            ],
            raiseonerr=False,
        )
        assert msg in result.stdout_text
        assert result.returncode == 0

    def test_adtrust_install_with_non_ipa_user(self):
        """
        Test that ipa-adtrust-install command returns
        an error when kinit is done as alias
        i.e root which is not an ipa user.
        """
        msg = (
            'Unrecognized error during check of admin rights: '
            'root: user not found'
        )
        user = 'root'
        self.master.run_command(
            ["kinit", "-E", user],
            stdin_text=self.master.config.admin_password
        )
        result = self.master.run_command(
            ["ipa-adtrust-install", "-A", user,
             "-a", self.master.config.admin_password,
             "-U"], raiseonerr=False
        )
        assert result.returncode != 0
        assert msg in result.stderr_text

    def test_adtrust_install_as_regular_ipa_user(self):
        """
        This testcase checks that when regular ipa user
        does kinit and runs the ipa-adtrust-install
        command, the command is not run and message
        is displayed on the console.
        """
        user = "ipauser1"
        passwd = "Secret123"
        try:
            tasks.create_active_user(
                self.master,
                user,
                password=passwd,
                first=user,
                last=user,
            )
            tasks.kinit_as_user(self.master, user, passwd)
            self.master.run_command(["klist", "-l"])
            result = self.master.run_command(
                ["ipa-adtrust-install", "-A", user,
                 "-a", passwd, "-U"], raiseonerr=False
            )
            msg = "Must have administrative privileges to " \
                  "setup AD trusts on server\n"
            assert msg in result.stderr_text
            assert result.returncode != 0
        finally:
            self.master.run_command(["kdestroy", "-A"])
            tasks.kinit_admin(self.master)

    def test_adtrust_install_as_non_root_user(self):
        """
        This testcase checks that when regular
        ipa user logins and then runs ipa-adtrust-install
        command, the command fails to run
        """
        user = "ipauser2"
        pwd = "Secret123"
        cmd = ["ipa-adtrust-install"]
        msg = (
            "Must be root to setup AD trusts on server"
        )
        try:
            tasks.create_active_user(self.master, user, pwd)
            tasks.run_command_as_user(
                self.master, user, cmd
            )
        except subprocess.CalledProcessError as e:
            assert msg in e.stderr
            assert e.returncode != 0
        else:
            pytest.fail(
                "Run ipa-adtrust-install as non "
                "root user did not return error"
            )

    def test_adtrust_install_as_admins_group_user(self):
        """
        Test to check that ipa-adtrust-install is successfull
        when a regular ipa user is part of the admins group
        """
        user = "testuser1"
        pwd = "Secret123"
        tasks.create_active_user(self.master, user, pwd)
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "group-add-member", "admins", "--users={}".format(user)]
        )
        self.master.run_command(["kdestroy", "-A"])
        self.master.run_command(
            ["ipa-adtrust-install", "-A", user,
             "-a", pwd, "-U"]
        )

    def test_adtrust_install_with_incorrect_admin_password(self):
        """
        Test to check ipa-adtrust-install with incorrect admin
        password
        """
        password = "wrong_pwd"
        expected_substring = (
            "Must have Kerberos credentials to setup AD trusts on server:"
        )
        self.master.run_command(["kdestroy", "-A"])
        result = self.master.run_command(
            ["ipa-adtrust-install", "-A", "admin", "-a",
             password, "-U"], raiseonerr=False
        )
        assert expected_substring in result.stderr_text
        assert result.returncode != 0

    def test_adtrust_install_with_invalid_rid_base_value(self):
        """
        Test to check adtrust install with invalid rid-base
        value
        """
        rid_base_value = "103.2"
        msg = (
            "ipa-adtrust-install: error: option " "--rid-base: "
            "invalid integer value: '{}'"
        ).format(rid_base_value)
        result = self.master.run_command(
            [
                "ipa-adtrust-install",
                "-A",
                "admin",
                "-a",
                self.master.config.admin_password,
                "--rid-base",
                rid_base_value,
                "-U",
            ],
            raiseonerr=False,
        )
        assert msg in result.stderr_text
        assert result.returncode != 0

    def test_adtrust_install_with_invalid_secondary_rid_base(self):
        """
        Test to check adtrust install with invalid secondary rid-base
        value
        """
        sec_rid_base_value = "103.2"
        msg = (
            "ipa-adtrust-install: error: option "
            "--secondary-rid-base: invalid integer value: '{}'"
        ).format(sec_rid_base_value)
        result = self.master.run_command(
            [
                "ipa-adtrust-install",
                "-A",
                "admin",
                "-a",
                self.master.config.admin_password,
                "--secondary-rid-base",
                sec_rid_base_value,
                "-U",
            ],
            raiseonerr=False,
        )
        assert msg in result.stderr_text
        assert result.returncode != 0

    def test_adtrust_reinstall_updates_ipaNTFlatName_attribute(self):
        """
        Test checks that reinstalling ipa-adtrust-install with
        new netbios name reflects changes in ipaNTFlatName attribute
        and ipa trustconfig-show also reflects the same.
        """
        netbios_name = "TEST8REALM"
        cmd = self.master.run_command(
            [
                "ipa-adtrust-install",
                "-a",
                self.master.config.admin_password,
                "--netbios-name",
                netbios_name,
                "-U",
            ]
        )
        trust_dn = "cn={},cn=ad,cn=etc,{}".format(
            self.master.domain.name, self.master.domain.basedn
        )
        cmd_args = ["ldapsearch", "-Y", "GSSAPI", "(ipaNTFlatName=*)",
                    "-s", "base", "-b", trust_dn]
        cmd = self.master.run_command(cmd_args)
        cmd1 = self.master.run_command(["ipa", "trustconfig-show"])
        assert "ipaNTFlatName: {}".format(netbios_name) in cmd.stdout_text
        assert "NetBIOS name: {}".format(netbios_name) in cmd1.stdout_text

    def test_smb_not_starting_post_adtrust_install(self):
        """
        Test checks that winbindd crash doesn't occur
        and smb service is running post ipa-adtrust-install.
        https://bugzilla.redhat.com/show_bug.cgi?id=991251
        """
        samba_msg = (
            'Unit smb.service entered failed state'
        )
        core_dump_msg = (
            'dumping core in /var/log/samba/cores/winbindd'
        )
        smb_cmd = self.master.run_command(
            ['systemctl', 'status', 'smb']
        )
        assert smb_cmd.returncode == 0
        assert samba_msg not in smb_cmd.stdout_text
        winbind_cmd = self.master.run_command(
            ['systemctl', 'status', 'winbind']
        )
        assert winbind_cmd.returncode == 0
        assert core_dump_msg not in winbind_cmd.stdout_text

    def test_samba_credential_cache_is_removed_post_uninstall(self):
        """
        Test checks that samba credential cache is removed after
        ipa-server is uninstalled.
        https://pagure.io/freeipa/issue/3479
        """
        self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password, "-U"]
        )
        assert self.master.transport.file_exists(paths.KRB5CC_SAMBA)
        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.uninstall_master(self.master)
        assert not self.master.transport.file_exists(paths.KRB5CC_SAMBA)

    def test_adtrust_install_without_ipa_installed(self):
        """
        Tests checks that ipa-adrust-install warns when
        ipa is not installed on the system
        """
        msg = (
            "IPA is not configured on this system."
        )
        result = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password, "-U"], raiseonerr=False)
        assert msg in result.stderr_text
        assert result.returncode != 0

    def test_adtrust_install_without_integrated_dns(self):
        """
        Test checks ipa-adtrust-install displays the necessary
        service records to be added on a IPA server
        without integrated dns setup.
        """
        realm = self.master.domain.realm.lower()
        hostname = self.master.hostname
        msg = (
            "Done configuring CIFS.\n"
            "DNS management was not enabled at install time.\n"
            "Add the following service records to your DNS server "
            "for DNS zone {0}: \n"
            "_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.{0}. "
            "3600 IN SRV 0 100 389 {1}.\n"
            "_ldap._tcp.dc._msdcs.{0}. 3600 IN SRV 0 100 389 {1}.\n"
            "_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs.{0}. "
            "3600 IN SRV 0 100 88 {1}.\n"
            "_kerberos._udp.Default-First-Site-Name._sites.dc._msdcs.{0}. "
            "3600 IN SRV 0 100 88 {1}.\n"
            "_kerberos._tcp.dc._msdcs.{0}. 3600 IN SRV 0 100 88 {1}.\n"
            "_kerberos._udp.dc._msdcs.{0}. 3600 IN SRV 0 100 88 {1}.\n\n"
            "================================================================"
            "=============\n"
            "Setup complete\n\n"
        ).format(realm, hostname)
        result = tasks.install_master(self.master, setup_dns=False)
        assert result.returncode == 0
        cmd = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password, "-U"]
        )
        assert msg in cmd.stdout_text

    def test_adtrust_install_with_debug_option(self):
        """
        Test checks that ipa-adtrust-install runs with debug option
        without any error.
        """
        self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password, "-U", "-d"]
        )

    def test_adtrust_install_cli_without_smbpasswd_file(self):
        """
        Test checks that ipa-adtrust-install works fine even
        without smbpasswd file
        https://pagure.io/freeipa/issue/3181
        """
        error_msg = (
            "< type 'file' > was not found on this system "
            "Please install the 'samba' packages and start "
            "the installation again Aborting installation"
        )
        self.master.run_command(
            ["mv", "/usr/bin/smbpasswd", "/usr/bin/smbpasswd.old"]
        )
        cmd = ["ipa-adtrust-install"]
        with self.master.spawn_expect(cmd) as e:
            e.expect_exact("admin password:")
            e.sendline(self.master.config.admin_password)
            # WARNING: The smb.conf already exists.
            # Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            e.expect(
                [
                    "smb\\.conf detected.+Overwrite smb\\.conf\\?",
                    "smb\\.conf already exists.+Do you wish to continue\\?",
                ]
            )
            e.sendline("yes")
            e.expect(["Enable trusted domains support in slapi-nis\\?"])
            e.sendline("no")
            e.expect_exit(ignore_remaining_output=True, timeout=60)
            output = e.get_last_output()
        assert "Setup complete" in output
        assert error_msg not in output
        # Rename the smbpasswd file to original
        self.master.run_command(
            ["mv", "/usr/bin/smbpasswd.old", "/usr/bin/smbpasswd"]
        )

    def test_adtrust_install_enable_compat(self):
        """
        Test adtrust_install with enable compat option
        """
        self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "--enable-compat", "-U"]
        )
        conn = self.master.ldap_connect()
        entry = conn.get_entry(
            DN("cn=users,cn=Schema Compatibility,cn=plugins,cn=config")
        )
        assert entry.single_value["schema-compat-lookup-nsswitch"] == "user"

    def test_adtrust_install_invalid_ipaddress_option(self):
        """
        Test ipa-adtrust-install with invalid --ip-address
        option
        """
        msg = (
            'ipa-adtrust-install: error: no such option: --ip-address'
        )
        result = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "--ip-address", "-U"], raiseonerr=False
        )
        assert msg in result.stderr_text
        assert result.returncode != 0

    def test_syntax_error_in_ipachangeconf(self):
        """
        Test checks that ipa-adtrust-install doesn't fail
        with 'Syntax Error' when dns_lookup_kdc is set to False
        in /etc/krb5.conf
        https://pagure.io/freeipa/issue/3132
        """
        error_msg = (
            'The ipa-adtrust-install command failed, exception: '
            'SyntaxError: Syntax Error: Unknown line format'
        )
        tasks.FileBackup(self.master, paths.KRB5_CONF)
        krb5_cfg = self.master.get_file_contents(paths.KRB5_CONF,
                                                 encoding='utf-8')
        new_krb5_cfg = krb5_cfg.replace(
            'dns_lookup_kdc = true', 'dns_lookup_kdc = false'
        )
        self.master.put_file_contents(paths.KRB5_CONF, new_krb5_cfg)
        result = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "-U"], raiseonerr=False
        )
        assert error_msg not in result.stderr_text

    def test_unattended_adtrust_install_uses_default_netbios_name(self):
        """
        ipa-adtrust-install unattended install should use default
        netbios name rather than prompting for it.
        https://fedorahosted.org/freeipa/ticket/3497
        """
        msg = (
            'Enter the NetBIOS name for the IPA domain'
            'Only up to 15 uppercase ASCII letters and '
            'digits are allowed.'
        )
        result = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "-U"]
        )
        assert result.returncode == 0
        assert msg not in result.stdout_text

    def test_adtrust_install_with_def_rid_base_values(self):
        """
        Test that ipa-adtrust-install install is successful
        with default rid and secondary values
        """
        rid_base = '1000'
        sec_rid_base = '100000000'
        self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "--rid-base", rid_base,
             "--secondary-rid-base", sec_rid_base,
             "-U"]
        )

    def test_ipa_adtrust_install_with_add_agents_option(self):
        """
        This testcase checks that ipa-adtrust-install
        with --add-agents works without any error
        on IPA server
        """
        result = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "--add-agents",
             "-U"]
        )
        assert result.returncode == 0

    def test_ipa_adtrust_install_with_add_sids_option(self):
        """
        This testcase checks that ipa-adtrust-install
        with --add-sids option works without any error
        """
        msg = (
            'adding SIDs to existing users and groups\n'
            'This step may take considerable amount of time, please wait..'
        )
        result = self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "--add-sids",
             "-U"]
        )
        assert msg in result.stdout_text

    def test_cldap_responder_doesnot_hang_for_domain_discovery(self):
        """
        This testcase checks that cldap responder doesnot hang
        for domain discovery.
        https://pagure.io/freeipa/issue/3639
        """
        version = tasks.get_openldap_client_version(self.master)
        if parse_version(version) >= parse_version('2.6'):
            pytest.skip('bz2167328')
        base_dn = ""
        srch_filter = "(&(DnsDomain={})(NtVer=\\06\\00\\00\\00)" \
                      "(AAC=\\00\\00\\00\\00))".format(self.master.domain.name)
        self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "-U"]
        )
        result = self.master.run_command(
            ["ldapsearch", "-LL", "-H",
             "cldap://{}".format(self.master.hostname),
             "-b", base_dn, "-s", "base", srch_filter]
        )
        assert result.returncode == 0
        assert 'dn:\nnetlogon::' in result.stdout_text

    def test_user_connects_smb_share_if_locked_specific_group(self):
        """
        Test scenario:
        Create a share in the samba server
        Access the share as admin, should work
        set valid users = admins to limit the share access to
        members of the "admins" group
        Access the share as admin, should work

        https://pagure.io/freeipa/issue/4234
        """
        msg = "tree connect failed: NT_STATUS_ACCESS_DENIED"
        self.master.run_command(
            ["ipa-adtrust-install", "-a",
             self.master.config.admin_password,
             "-U"]
        )
        # Wait for SSSD to become online before doing any other check
        tasks.wait_for_sssd_domain_status_online(self.master)
        self.master.run_command(["mkdir", "/freeipa4234"])
        self.master.run_command(
            ["chcon", "-t", "samba_share_t",
             "/freeipa4234"])
        self.master.run_command(
            ["setfacl", "-m", "g:admins:rwx",
             "/freeipa4234"])
        self.master.run_command(
            ["net", "conf", "setparm", "share",
             "comment", "Test Share"])
        self.master.run_command(
            ["net", "conf", "setparm", "share",
             "read only", "no"])
        self.master.run_command(
            ["net", "conf", "setparm", "share",
             "path", "/freeipa4234"])
        self.master.run_command(["touch", "before"])
        self.master.run_command(["touch", "after"])
        # Find cache for the admin user
        cache_args = []
        cache = tasks.get_credential_cache(self.master)
        if cache:
            cache_args = ["--use-krb5-ccache", cache]

        cmd_args = ["smbclient", "--use-kerberos=desired"]
        cmd_args.extend(cache_args)
        cmd_args.extend([
            "-c=put before", "//{}/share".format(self.master.hostname)
        ])
        self.master.run_command(cmd_args)
        self.master.run_command(
            ["net", "conf", "setparm", "share",
             "valid users", "@admins"])
        cmd_args = ["smbclient", "--use-kerberos=desired"]
        cmd_args.extend(cache_args)
        cmd_args.extend([
            "-c=put after", "//{}/share".format(self.master.hostname)
        ])
        result = self.master.run_command(cmd_args)
        assert msg not in result.stdout_text
