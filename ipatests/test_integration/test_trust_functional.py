# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import time
import textwrap
from contextlib import contextmanager
import pytest
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_trust import BaseTestTrust


class TestTrustFunctionalHbac(BaseTestTrust):
    topology = 'line'
    num_ad_treedomains = 0

    def _add_hbacrule_with_service(self, rule_name, service_name):
        self.master.run_command(
            ["ipa", "hbacrule-add", rule_name, "--hostcat=all"]
        )
        self.master.run_command(
            [
                "ipa",
                "hbacrule-add-service",
                rule_name,
                f"--hbacsvcs={service_name}",
            ]
        )

    def _disable_allow_all_and_wait(self):
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        tasks.wait_for_sssd_domain_status_online(self.master)
        tasks.wait_for_sssd_domain_status_online(self.clients[0])

    def _cleanup_hrule_allow_all_and_wait(self, hrule):
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-del", hrule])
        self.master.run_command(["ipa", "hbacrule-enable", "allow_all"])
        tasks.wait_for_sssd_domain_status_online(self.master)
        tasks.wait_for_sssd_domain_status_online(self.clients[0])

    def _ssh_with_password(
        self,
        login,
        host,
        password,
        success_expected=False
    ):
        result = self.clients[0].run_command(
            ['sshpass', '-p', password,
             'ssh', '-v', '-o', 'StrictHostKeyChecking=no',
             '-l', login, host, "id"],
            raiseonerr=success_expected
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        return output

    def _get_log_tail(self, host, log_path, start_offset):
        return host.get_file_contents(log_path)[start_offset:]

    def test_setup(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        tasks.group_add(
            self.master,
            groupname="hbacgroup_external",
            extra_args=["--external"],
        )
        tasks.group_add(self.master, groupname="hbacgroup")
        tasks.group_add_member(
            self.master,
            groupname="hbacgroup",
            extra_args=['--groups=hbacgroup_external'],
        )
        self.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            self.aduser, 'hbacgroup_external',
        ])
        self.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            self.subaduser, 'hbacgroup_external',
        ])

    def test_ipa_trust_func_hbac_0001(self):
        """
        Test that adding AD users/groups without the external group to
        HBAC rules fails.

        This test verifies that when attempting to add AD users or
        groups directly to HABC rules, the operation fails with
        a "no such entry" error.
        """
        hrule = "hbacrule_hbac_0001"
        tasks.kinit_admin(self.master)
        try:
            self._add_hbacrule_with_service(hrule, 'sudo')
            for arg in [
                f"--users={self.aduser}", f"--users={self.subaduser}",
                f"--groups={self.ad_group}", f"--groups={self.ad_sub_group}"
            ]:
                result = self.master.run_command(
                    ["ipa", "hbacrule-add-user", hrule, arg],
                    raiseonerr=False
                )
                output = f"{result.stdout_text}{result.stderr_text}"
                assert result.returncode != 0
                assert "no such entry" in output
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)

    def test_ipa_trust_func_hbac_0002(self):
        """
        Test HBAC rule denies SSH access for AD users.

        This test creates an HBAC rule that allows SSH access only for admin
        users/groups, then verifies that AD users from the trusted domain are
        denied access. The test confirms that the denial is logged with
        "Access denied by HBAC rules" message.
        """
        hrule = "hbacrule_hbac_0002"
        tasks.kinit_admin(self.master)
        log_file = '{0}/sssd_{1}.log'.format(
            paths.VAR_LOG_SSSD_DIR, self.master.domain.name)
        try:
            self._add_hbacrule_with_service(hrule, 'sshd')
            self.master.run_command(
                ['ipa', 'hbacrule-add-user', hrule,
                 '--users=admin', '--groups=admins'
                 ]
            )
            self._disable_allow_all_and_wait()
            for user in [self.aduser, self.subaduser]:
                logsize = tasks.get_logsize(
                    self.clients[0], log_file
                )
                self._ssh_with_password(
                    user,
                    self.clients[0].hostname,
                    'Secret123',
                    success_expected=False,
                )
                sssd_logs = self._get_log_tail(
                    self.clients[0], log_file, logsize
                )
                assert b"Access denied by HBAC rules" in sssd_logs
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)

    def test_ipa_trust_func_hbac_0005(self):
        """
        Test HBAC rule allows SSH access for AD users in external group.

        This test creates an HBAC rule that allows SSH access for members of
        the hbacgroup (which includes AD users via external group membership).
        It verifies that AD users who are members can successfully SSH, while
        AD users who are not members are denied access.
        """
        hrule = "hbacrule_hbac_0005"
        tasks.kinit_admin(self.master)
        try:
            self._add_hbacrule_with_service(hrule, 'sshd')
            self.master.run_command(
                [
                    "ipa",
                    "hbacrule-add-user",
                    hrule,
                    "--groups=hbacgroup",
                ]
            )
            self._disable_allow_all_and_wait()
            tasks.kinit_admin(self.clients[0])
            for user in [self.aduser, self.subaduser]:
                tasks.kinit_admin(self.clients[0])
                self.clients[0].run_command(
                    ["ipa", "hbactest", f"--user={user}", "--service=sshd",
                     f"--host={self.clients[0].hostname}",
                     ]
                )
                tasks.kdestroy_all(self.clients[0])
                output = self._ssh_with_password(
                    user,
                    self.clients[0].hostname,
                    'Secret123',
                    success_expected=True,
                )
                assert "domain users" in output

            for user2 in [self.aduser2, self.subaduser2]:
                self._ssh_with_password(
                    user2,
                    self.clients[0].hostname,
                    'Secret123',
                    success_expected=False,
                )
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)

    def test_ipa_trust_func_hbac_0008(self):
        """
        Test HBAC rule denies sudo access for AD users when rule doesn't
        include them.

        This test creates an HBAC rule for sudo service that only allows
        admin users, and a sudo rule that allows admin users to run all
        commands. It then verifies that AD users are denied sudo access
        due to HBAC restrictions, with the denial being logged as
        "user NOT authorized on host".
        """
        hrule = "hbacrule_hbac_0008"
        srule = "sudorule_hbac_0008"
        tasks.kinit_admin(self.master)
        try:
            self._add_hbacrule_with_service(hrule, 'sudo')
            self.master.run_command(
                ["ipa", "hbacrule-add-user", hrule, "--users=admin",
                 "--groups=admins"]
            )
            self.master.run_command(
                [
                    "ipa",
                    "sudorule-add",
                    srule,
                    "--hostcat=all",
                    "--cmdcat=all",
                ]
            )
            self.master.run_command(
                [
                    "ipa",
                    "sudorule-add-user",
                    srule,
                    "--users=admin",
                    "--groups=admins"
                ]
            )
            tasks.clear_sssd_cache(self.clients[0])
            self._disable_allow_all_and_wait()
            tasks.kdestroy_all(self.clients[0])

            for user in [self.aduser, self.subaduser]:
                test_sudo = "su {0} -c 'sudo -S id'".format(user)
                result = self.clients[0].run_command(
                    test_sudo,
                    stdin_text='Secret123',
                    raiseonerr=False
                )
                output = f"{result.stdout_text}{result.stderr_text}"
                assert (
                    "sudo: PAM account management error: Permission denied"
                    in output
                )
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)
            self.master.run_command(["ipa", "sudorule-del", srule])

    def test_ipa_trust_func_hbac_0011(self):
        """
        Test HBAC rule allows sudo access for AD users in external group.

        This test creates an HBAC rule for sudo service that allows members of
        the hbacgroup (which includes AD users via external group membership),
        and a sudo rule that allows hbacgroup members to run all commands.
        It verifies that AD users who are members of the external group can
        successfully use sudo and gain root privileges.
        """
        hrule = "ipa_trust_func_hbac_0011"
        srule = "ipa_trust_func_hbac_0011"
        tasks.clear_sssd_cache(self.master)
        tasks.kinit_admin(self.master)
        try:
            self._add_hbacrule_with_service(hrule, 'sudo')

            self.master.run_command(
                ["ipa", "hbacrule-add-user", hrule, "--groups=hbacgroup"]
            )
            self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
            self.master.run_command(
                ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
            )
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=hbacgroup"]
            )
            tasks.clear_sssd_cache(self.master)
            tasks.clear_sssd_cache(self.clients[0])
            tasks.wait_for_sssd_domain_status_online(self.master)
            test_sudo = "su {user} -c 'sudo -S id'"
            for user in [self.aduser, self.subaduser]:
                with self.clients[0].spawn_expect(
                        test_sudo.format(user=user)) as e:
                    e.sendline('Secret123')
                    e.sendline('exit')
                    e.expect_exit(
                        ignore_remaining_output=True, raiseonerr=False)
                    output = e.get_last_output()
                    assert 'uid=0(root)' in output
            for user in [self.aduser2, self.subaduser2]:
                test_sudo = "su {0} -c 'sudo -S id'".format(user)
                result = self.clients[0].run_command(
                    test_sudo,
                    stdin_text='Secret123',
                    raiseonerr=False
                )
                assert result.returncode != 0
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)
            self.master.run_command(["ipa", "sudorule-del", srule])


class TestTrustFunctionalSudo(BaseTestTrust):
    topology = 'line'
    num_ad_treedomains = 0

    def cache_reset(self):
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        tasks.wait_for_sssd_domain_status_online(self.master)
        tasks.wait_for_sssd_domain_status_online(self.clients[0])
        # give time to SSSD to retrieve new records
        time.sleep(30)

    def _cleanup_srule(self, srule):
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "sudorule-del", srule])
        self.cache_reset()

    def _run_sudo_command(self, host, command, username, password='Secret123',
                          expected_output=None, raiseonerr=True, timeout=60):
        """
        Run a sudo command using spawn_expect with proper error handling.

        Args:
            host: Host to run the command on
            command: Command to execute
            username: Username for password prompt
            password: Password to send
            expected_output: Expected string in output (for assertion)
            raiseonerr: Whether to raise on error
            timeout: Timeout for expect_exit

        Returns:
            Output from the command
        """
        with host.spawn_expect(command) as e:
            e.expect(r'(?i).*Password for {}.*:'.format(username))
            e.sendline(password)
            e.expect_exit(ignore_remaining_output=True,
                          raiseonerr=raiseonerr, timeout=timeout)
            output = e.get_last_output()

            if expected_output:
                assert expected_output in output, (
                    f"Expected '{expected_output}' in output, got: {output}"
                )

            return output

    def test_ipa_trust_func_sudo_setup(self):
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kinit_admin(self.master)

        for i in range(1, 3):
            external_group = f"sudogroup_external{i}"
            internal_group = f"sudogroup{i}"
            tasks.group_add(self.master,
                            groupname=external_group,
                            extra_args=["--external"]
                            )
            tasks.group_add(self.master,
                            groupname=internal_group
                            )
            tasks.group_add_member(self.master,
                                   groupname=internal_group,
                                   extra_args=[f"--groups={external_group}"]
                                   )

        group_members = {
            "sudogroup_external1": [self.aduser, self.subaduser],
            "sudogroup_external2": [self.aduser2, self.subaduser2],
        }

        for group, members in group_members.items():
            for member in members:
                self.master.run_command([
                    'ipa', '-n', 'group-add-member', '--external',
                    member, group,
                ])
        for user in ['sudouser1', 'sudouser2', 'ipauser1']:
            tasks.create_active_user(
                self.master, user, password='Secret123'
            )

    def test_ipa_trust_func_sudo_0001(self):
        """
        Test sudo rule allow AD user in external group to run commands as root.

        This test creates a sudo rule that allows members of sudogroup1 (which
        includes AD users via external group membership) to run all commands as
        root. It verifies that AD users who are members of the external group
        can successfully use sudo to gain root privileges.
        """
        srule = "sudorule_01"
        cmd = ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
        try:
            tasks.kinit_admin(self.master)
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=sudogroup1"]
            )
            self.cache_reset()
            for user in [self.aduser, self.subaduser]:
                test_sudo = f"su {user} -c 'sudo -S id'"
                self._run_sudo_command(
                    self.clients[0], test_sudo, user,
                    expected_output='uid=0(root)'
                )
        finally:
            self._cleanup_srule(srule)

    def test_ipa_trust_func_sudo_0002(self):
        """
        Test sudo rule allows AD users to run commands as other AD users.

        This test creates a sudo rule that allows members of sudogroup1 to run
        commands as members of sudogroup2. It verifies that AD users can
        successfully use sudo to switch to other AD user accounts when they
        have the appropriate sudo permissions.
        """
        srule = "sudorule_02"
        cmd = ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
        try:
            tasks.kinit_admin(self.master)
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=sudogroup1"]
            )
            self.master.run_command(
                ["ipa", "sudorule-add-runasuser", srule, "--groups=sudogroup2"]
            )
            self.cache_reset()
            test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                self.aduser, self.aduser2
            )
            self._run_sudo_command(self.clients[0], test_sudo, self.aduser,
                                   expected_output=self.aduser2
                                   )

            test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                self.subaduser, self.subaduser2
            )
            self._run_sudo_command(self.clients[0], test_sudo, self.subaduser,
                                   expected_output=self.subaduser2
                                   )
        finally:
            self._cleanup_srule(srule)

    def test_ipa_trust_func_sudo_0004(self):
        """
        Test sudo rule allows IPA users to run commands as AD users.

        This test creates a sudo rule that allows IPA users to run commands
        as AD users who are members of external groups. It verifies that
        IPA users can successfully use sudo to switch to AD user accounts
        when they have the appropriate sudo permissions.
        """
        srule = "sudorule_04"
        cmd = ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
        try:
            tasks.kinit_admin(self.master)
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--users=ipauser1"]
            )
            self.master.run_command(
                ["ipa", "sudorule-add-runasuser", srule, "--groups=sudogroup1"]
            )
            self.cache_reset()
            self.master.run_command(
                ["ipa", "sudorule-show", srule, "--all"]
            )
            self.master.run_command(['ipa', 'group-show', 'sudogroup1'])
            self.master.run_command(
                ['ipa', 'group-show', 'sudogroup_external1']
            )
            for user in [self.aduser, self.subaduser]:
                tasks.clear_sssd_cache(self.master)
                test_sudo = f"su ipauser1 -c 'sudo -S -u {user} id'"
                self._run_sudo_command(self.master, test_sudo, 'ipauser1',
                                       expected_output=user)

            for user in [self.aduser2, self.subaduser2]:
                tasks.clear_sssd_cache(self.master)
                test_sudo = f"su ipauser1 -c 'sudo -S -u {user} id'"
                self._run_sudo_command(self.master, test_sudo, 'ipauser1',
                                       expected_output="not allowed to",
                                       raiseonerr=False)
        finally:
            self._cleanup_srule(srule)

    def test_ipa_trust_func_sudo_0005(self):
        """
        Test sudo rule disable/enable functionality for AD users.

        Test creates a sudo rule that allows AD users to run commands as root,
        then tests the disable/enable functionality. It verifies that:
        1. AD users can sudo as root when the rule is enabled
        2. AD users are denied sudo access when the rule is disabled
        3. AD users can sudo as root again when the rule is re-enabled
        """
        srule = "sudorule_05"
        cmd = ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
        try:
            tasks.kinit_admin(self.master)
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=sudogroup1"]
            )
            self.cache_reset()
            for aduser in [self.aduser, self.subaduser]:
                # First check that user can sudo as root
                sudo_cmd = f"su - {aduser} -c 'sudo -S id'"
                self._run_sudo_command(self.clients[0], sudo_cmd, aduser,
                                       expected_output='uid=0(root)')

                # disable sudorule
                self.master.run_command(["ipa", "sudorule-disable", srule])
                self.cache_reset()

                # now make sure user cannot sudo as root
                sudo_cmd = f"su - {aduser} -c 'sudo -S id'"
                self._run_sudo_command(self.clients[0], sudo_cmd, aduser,
                                       expected_output="is not allowed to",
                                       raiseonerr=False)

                # now reenable rule
                self.master.run_command(["ipa", "sudorule-enable", srule])
                self.cache_reset()
                sudo_cmd = f"su - {aduser} -c 'sudo -S id'"
                self._run_sudo_command(self.clients[0], sudo_cmd, aduser,
                                       expected_output='uid=0(root)')
        finally:
            self._cleanup_srule(srule)

    def test_ipa_trust_func_sudo_0007(self):
        """
        Test sudo rule with allow/deny command restrictions for AD users.

        Test creates a sudo rule that allows AD users to run commands as root,
        but with specific command restrictions. It verifies that:
        1. AD users are denied access to commands in the deny list
        2. AD users are allowed access to commands in the allow list

        The test uses /usr/bin/id as a denied command and /usr/bin/whoami as an
        allowed command to demonstrate the allow/deny functionality.
        """
        srule = "sudorule_07"
        try:
            tasks.kinit_admin(self.master)
            cmd = ["ipa", "sudorule-add", srule, "--hostcat=all"]
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=sudogroup1"]
            )
            self.master.run_command(['ipa', 'sudocmd-add', '/usr/bin/id'])
            self.master.run_command(['ipa', 'sudocmd-add', '/usr/bin/whoami'])
            self.master.run_command(['ipa', 'sudorule-add-deny-command', srule,
                                     '--sudocmds', '/usr/bin/id']
                                    )
            self.master.run_command(
                ['ipa', 'sudorule-add-allow-command', srule,
                 '--sudocmds', '/usr/bin/whoami']
            )
            self.cache_reset()
            for aduser in [self.aduser, self.subaduser]:
                sudo_cmd = f"su - {aduser} -c 'sudo -S id'"
                self._run_sudo_command(self.clients[0], sudo_cmd, aduser,
                                       expected_output="is not allowed to",
                                       raiseonerr=False)
            for aduser in [self.aduser, self.subaduser]:
                sudo_cmd = f"su - {aduser} -c 'sudo -S whoami'"
                self._run_sudo_command(self.clients[0], sudo_cmd, aduser,
                                       expected_output='root')
        finally:
            self._cleanup_srule(srule)
            self.master.run_command(['ipa', 'sudocmd-del', '/usr/bin/id'])
            self.master.run_command(['ipa', 'sudocmd-del', '/usr/bin/whoami'])

    def test_ipa_trust_func_sudo_0009(self):
        """
        Test sudo rule denies AD users access when they are not in the rule.

        This test creates a sudo rule that only allows members of sudogroup2
        to run commands as other members of sudogroup2. It verifies that
        AD users who are not members of the allowed group are denied access
        when attempting to use sudo to switch to other user accounts.
        """
        srule = "sudorule_09"
        cmd = ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
        try:
            tasks.kinit_admin(self.master)
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--groups=sudogroup2"]
            )
            self.master.run_command(
                ["ipa", "sudorule-add-runasuser", srule, "--groups=sudogroup2"]
            )
            self.cache_reset()
            test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                self.aduser, self.aduser2
            )
            self._run_sudo_command(self.clients[0], test_sudo, self.aduser,
                                   expected_output='not allowed to run sudo',
                                   raiseonerr=False)

            test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                self.subaduser, self.subaduser2
            )
            self._run_sudo_command(self.clients[0], test_sudo, self.subaduser,
                                   expected_output='not allowed to run sudo',
                                   raiseonerr=False)
        finally:
            self._cleanup_srule(srule)

    def test_ipa_trust_func_sudo_0010(self):
        """
        Test sudo rule denies IPA users access to AD users not in the rule.

        This test creates a sudo rule that allows IPA users to run commands as
        members of sudogroup2 (which includes aduser2/subaduser2), but not as
        members of sudogroup1 (which includes aduser1/subaduser1). It verifies
        that IPA users are denied access when attempting to use sudo to switch
        to AD user accounts that are not in the allowed runasuser group.
        """
        srule = "sudorule_10"
        cmd = ["ipa", "sudorule-add", srule, "--hostcat=all", "--cmdcat=all"]
        try:
            tasks.kinit_admin(self.master)
            self.master.run_command(cmd)
            self.master.run_command(
                ["ipa", "sudorule-add-user", srule, "--users=ipauser1"]
            )
            self.master.run_command(
                ["ipa", "sudorule-add-runasuser", srule, "--groups=sudogroup2"]
            )
            self.cache_reset()

            for aduser in [self.aduser, self.subaduser]:
                sudo_cmd = f"su - {aduser} -c 'sudo -S id'"
                self._run_sudo_command(self.clients[0], sudo_cmd, aduser,
                                       expected_output="is not allowed to",
                                       raiseonerr=False)
        finally:
            self._cleanup_srule(srule)


class TestTrustFunctionalHttp(BaseTestTrust):
    topology = 'line'
    num_ad_treedomains = 0

    ad_user_password = 'Secret123'

    # Apache configuration for GSSAPI-protected webapp. The /mywebapp
    # location requires Kerberos authentication and restricts access by
    # domain: IPA users (@IPA_REALM) or AD users (@AD_DOMAIN).
    apache_conf = textwrap.dedent('''
    Alias /mywebapp "/var/www/html/mywebapp"
    <Directory "/var/www/html/mywebapp">
        Allow from all
    </Directory>
    <Location "/mywebapp">
        LogLevel debug
        AuthType GSSAPI
        AuthName "IPA Kerberos authentication"
        GssapiNegotiateOnce on
        GssapiBasicAuthMech krb5
        GssapiCredStore keytab:{keytab_path}
        <RequireAll>
            Require valid-user
            # Require expr: restrict access by domain. REMOTE_USER is set by
            # mod_auth_gssapi after GSSAPI authentication. Allow users whose
            # principal ends with the domain (IPA realm or AD domain).
            Require expr %{{REMOTE_USER}} =~ /{allowed_domain_regex}$/
        </RequireAll>
    </Location>
    ''')

    def _configure_webapp(self, allowed_domain):
        """Write the GSSAPI vhost config and restart httpd on the client.

        allowed_domain: realm/domain for access control (e.g. IPA.TEST for
        IPA users, AD.DOMAIN for AD users). Users whose principal ends with
        @allowed_domain are granted access.
        """
        # Escape dots for regex (e.g. IPA.TEST -> IPA\\.TEST)
        escaped = re.escape(allowed_domain)
        allowed_domain_regex = '.*@' + escaped
        keytab_path = f"/etc/httpd/conf/{self.clients[0].hostname}.keytab"
        self.clients[0].put_file_contents(
            '/etc/httpd/conf.d/mywebapp.conf',
            self.apache_conf.format(
                keytab_path=keytab_path,
                allowed_domain_regex=allowed_domain_regex,
            )
        )
        self.clients[0].run_command(['systemctl', 'restart', 'httpd'])

    def _assert_curl_ok(self, msg=None):
        """Run curl with GSSAPI negotiate and assert the webapp responds."""
        url = f"http://{self.clients[0].hostname}/mywebapp/index.html"
        result = self.clients[0].run_command([
            paths.BIN_CURL, '-v', '--negotiate', '-u:', url
        ])
        assert "TEST_MY_WEB_APP" in result.stdout_text, (
            msg or f"Expected webapp content at {url}"
        )

    def _assert_curl_GSSAPI_access_denied(self, msg=None):
        """Run curl with GSSAPI negotiate and assert a 401 is returned."""
        url = f"http://{self.clients[0].hostname}/mywebapp/index.html"
        result = self.clients[0].run_command([
            paths.BIN_CURL, '-v', '--negotiate', '-u:', url
        ], raiseonerr=False)
        output = f"{result.stdout_text}{result.stderr_text}"
        assert ("401" in output
                or "Unauthorized" in output
                or "Authorization Required" in output), (
            msg or f"Expected 401/Unauthorized at {url}, got: {output[:200]}"
        )

    @classmethod
    def install(cls, mh):
        """Extend base install to configure Apache/GSSAPI for HTTP tests.

        Runs once before any test in this class.  Sets up the AD trust,
        creates the HTTP service principal and IPA test user, installs
        mod_auth_gssapi, retrieves the service keytab, and provisions the
        static webapp content used by all HTTP tests.
        """
        super().install(mh)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

        # Create HTTP service principal on master
        service_principal = f"HTTP/{cls.clients[0].hostname}"
        cls.master.run_command(
            ["ipa", "service-add", service_principal]
        )

        # Create IPA user for HTTP tests
        tasks.create_active_user(
            cls.master, "ipahttpuser1", password="Passw0rd1",
            first="f", last="l"
        )

        # Clear SSSD cache on master
        tasks.clear_sssd_cache(cls.master)
        tasks.wait_for_sssd_domain_status_online(cls.master)

        # Install Apache and the GSSAPI module on the IPA client
        tasks.install_packages(
            cls.clients[0], ['mod_auth_gssapi', 'httpd']
        )

        # Retrieve and protect the HTTP service keytab
        keytab_path = f"/etc/httpd/conf/{cls.clients[0].hostname}.keytab"
        cls.clients[0].run_command([
            'ipa-getkeytab', '-s', cls.master.hostname,
            '-k', keytab_path,
            '-p', service_principal
        ])
        cls.clients[0].run_command(
            ['chown', 'apache:apache', keytab_path]
        )

        # Create webapp directory and static content
        cls.clients[0].run_command(
            ['mkdir', '-p', '/var/www/html/mywebapp']
        )
        cls.clients[0].put_file_contents(
            '/var/www/html/mywebapp/index.html',
            'TEST_MY_WEB_APP\n'
        )

    def test_ipa_trust_func_http_krb_ipauser(self):
        """
        Test IPA User access http with kerberos ticket via valid user.

        This test verifies that an IPA user with a valid Kerberos ticket
        can successfully access an HTTP resource protected by GSSAPI
        authentication and restricted to IPA users.
        """
        ipa_realm = self.clients[0].domain.realm
        self._configure_webapp(ipa_realm)

        tasks.kdestroy_all(self.clients[0])
        tasks.kinit_as_user(
            self.clients[0], f'ipahttpuser1@{ipa_realm}', "Passw0rd1"
        )

        self._assert_curl_ok()

        users = [
            (self.aduser, self.ad_domain),
            (self.subaduser, self.ad_subdomain),
        ]
        for aduser, domain in users:
            tasks.kdestroy_all(self.clients[0])
            # pylint: disable=use-maxsplit-arg
            principal = f"{aduser.split('@')[0]}@{domain.upper()}"
            tasks.kinit_as_user(
                self.clients[0], principal, self.ad_user_password
            )
            self._assert_curl_GSSAPI_access_denied(
                msg=f"Expected 401 for AD user {aduser}"
            )

    def test_ipa_trust_func_http_krb_aduser(self):
        """
        Test AD root and subdomain users access http with kerberos ticket.

        This test verifies that both a root AD domain user and a child
        subdomain user with valid Kerberos tickets can successfully access
        an HTTP resource protected by GSSAPI authentication and restricted
        to AD domain / AD subdomain users.
        """
        users = [
            (self.aduser, self.ad_domain),
            (self.subaduser, self.ad_subdomain),
        ]
        for aduser, domain in users:
            tasks.kdestroy_all(self.clients[0])
            # pylint: disable=use-maxsplit-arg
            principal = f"{aduser.split('@')[0]}@{domain.upper()}"
            self._configure_webapp(domain.upper())
            tasks.kinit_as_user(
                self.clients[0], principal, self.ad_user_password
            )
            self._assert_curl_ok(
                msg=f"Expected webapp content for AD user {aduser}"
            )
            tasks.kdestroy_all(self.clients[0])
            tasks.kinit_as_user(self.clients[0], "ipahttpuser1", "Passw0rd1")
            self._assert_curl_GSSAPI_access_denied(
                msg=f"Expected 401 for IPA user after AD user {aduser}"
            )

    def test_ipa_trust_func_http_krb_nouser(self):
        """
        Test User cannot access http without kerberos ticket via valid user.

        This test verifies that an user without a valid Kerberos ticket
        is denied access to an HTTP resource protected by GSSAPI
        authentication, receiving a 401 Unauthorized error.
        """
        tasks.kdestroy_all(self.clients[0])

        self._assert_curl_GSSAPI_access_denied()


class TestTrustFunctionalSelinuxUsermap(BaseTestTrust):
    """Trusted AD users, IPA SELinux user maps, and HBAC (Beaker).

    Beaker suite: ``ipa-trust-functional``.

    Forest scenarios match ``t.ipa_trust_func_selinuxusermap.sh``; each
    numbered test also runs the subdomain variant from
    ``t.ipa_trust_func_selinuxusermap_sub.sh``.
    Every ``test_ipa_trust_func_selinuxusermap_*`` docstring states **what**
    is verified (SSH success, ``id -Z`` context strings, or expected denial).
    """

    topology = 'line'
    num_clients = 2
    num_ad_treedomains = 0

    ADPASS = 'Secret123'
    SELINUX_STAFF = 'staff_u:s0-s0:c0.c1023'
    SELINUX_USER_U = 'user_u:s0'
    SELINUX_XGUEST = 'xguest_u:s0'
    SELINUX_GUEST = 'guest_u:s0'
    SELINUX_UNCONFINED_DEFAULT = 'unconfined_u:s0-s0:c0.c1023'
    G1_EXT = 'ad_testgrp1_ext'
    G1 = 'ad_testgrp1'
    G2_EXT = 'ad_testgrp2_ext'
    G2 = 'ad_testgrp2'
    SG1_EXT = 'ad_subtestgrp1_ext'
    SG1 = 'ad_subtestgrp1'
    SG2_EXT = 'ad_subtestgrp2_ext'
    SG2 = 'ad_subtestgrp2'

    @classmethod
    def install(cls, mh):
        """Prepare trust, AD groups, and SSSD for SELinux user map tests.

        Configures DNS and establishes a one-way trust to AD, creates four
        external+posix group pairs (forest ``G1``/``G2`` and subdomain
        ``SG1``/``SG2``) with the usual test AD principals as external
        members, then clears SSSD
        caches on the master and both clients so group membership is visible
        before any test runs.
        """
        super().install(mh)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kinit_admin(cls.master)
        cls._add_pair(cls.G1_EXT, cls.G1, cls.testuser1)
        cls._add_pair(cls.G2_EXT, cls.G2, cls.testuser2)
        cls._add_pair(cls.SG1_EXT, cls.SG1, cls.subaduser)
        cls._add_pair(cls.SG2_EXT, cls.SG2, cls.subdomaintestuser2)
        for host in (cls.master, *cls.clients):
            tasks.clear_sssd_cache(host)
            tasks.wait_for_sssd_domain_status_online(host)

    def _require_selinux_clients(self):
        """Skip the class unless every client has SELinux enforcing.

        The suite relies on ``id -Z`` over SSH; without SELinux on clients the
        checks are meaningless, so we abort early with ``pytest.skip``.
        """
        for client_host in self.clients:
            if not tasks.is_selinux_enabled(client_host):
                pytest.skip(
                    'SELinux must be enabled on all clients for id -Z tests'
                )

    def _sssd_clear_all(self):
        """Invalidate SSSD caches on master and all clients; wait until online.

        Call after IPA objects that affect identity or SELinux mapping change
        so ``id -Z`` reflects the current server state.
        """
        for host in (self.master, *self.clients):
            tasks.clear_sssd_cache(host)
            tasks.wait_for_sssd_domain_status_online(host)

    def _sssd_prime_trusted_users(self, users, hosts):
        """Warm SSSD after a cache clear (``id`` on each *user* / *host* pair).

        Matches the pattern in ``test_hbac_functional`` before password SSH
        when ``allow_all`` is off: cold caches can yield sshpass exit 5 even
        when HBAC allows access.
        """
        for host in hosts:
            for user in users:
                host.run_command(['id', user], raiseonerr=False)

    def _ssh_id_z(self, runner, user, target, password=ADPASS):
        """Run ``id -Z`` on *target* by SSH from *runner*, as trusted *user*.

        Uses ``sshpass`` with *password* (default ``ADPASS``).  *runner* is a
        multihost host that executes the SSH client; *target* may be a host
        object (``hostname`` used) or a bare hostname string.  Does not raise
        on SSH failure—inspect the returned exit code.

        :param runner: Host running ``ssh`` (typically a client).
        :param user: Remote login (trusted AD user principal).
        :param target: Destination host or hostname.
        :param password: Password for ``sshpass``.
        :return: ``(combined_stdout_stderr, exit_code)``.
        """
        run_result = runner.run_command(
            [
                'sshpass', '-p', password,
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'PasswordAuthentication=yes',
                '-o', 'PubkeyAuthentication=no',
                '-o', 'GSSAPIAuthentication=no',
                '-l', user, target.hostname, 'id', '-Z',
            ],
            raiseonerr=False,
        )
        combined_output = (
            f'{run_result.stdout_text}{run_result.stderr_text}')
        return combined_output, run_result.returncode

    @classmethod
    def _unconfined_ctx(cls, output):
        """True if *output* looks like the default unconfined ``id -Z`` line.

        ``ipa config-mod --ipaselinuxusermapdefault`` uses the short MLS user
        string (``SELINUX_UNCONFINED_DEFAULT``), but ``id -Z`` on recent
        Fedora/RHEL prints the full context with role and type in between.
        Accept either form.
        """
        if re.search(
                re.escape(cls.SELINUX_UNCONFINED_DEFAULT),
                output,
                re.DOTALL,
        ):
            return True
        return re.search(
            r'unconfined_u:unconfined_r:unconfined_t:s0-s0:c0\.c1023',
            output,
        ) is not None

    def _ssh_id_z_assert(self, runner, user, target, role, password=ADPASS):
        """SSH ``id -Z`` and assert exit code 0 and SELinux role *role*.

        Combines ``_ssh_id_z`` with role checks.  Use when login and ``id -Z``
        must succeed (contrast ``_ssh_id_z_assert_denied``).
        """
        output, code = self._ssh_id_z(runner, user, target, password=password)
        assert code == 0, output
        has_staff = 'staff_u' in output and 's0-s0:c0.c1023' in output
        # Full contexts look like user_u:user_r:user_t:s0 (not ``user_u:s0``).
        has_user_u = (
            re.search(r'user_u:user_r:user_t:s0', output) is not None
        )
        has_guest = (
            re.search(r'guest_u:guest_r:guest_t:s0', output) is not None
        )
        # Match xguest full context; do not use bare ``:s0`` (staff has
        # ``s0-s0``).
        has_xguest = (
            re.search(r'xguest_u:xguest_r:xguest_t:s0', output) is not None
        )

        if role == 'staff':
            assert has_staff, output
        elif role == 'unconfined':
            assert self._unconfined_ctx(output), output
        elif role == 'not_staff_unconfined':
            assert (not has_staff and self._unconfined_ctx(output)), output
        elif role == 'user_u':
            assert has_user_u, output
        elif role == 'user_u_not_staff':
            assert has_user_u and not has_staff, output
        elif role == 'guest':
            assert has_guest, output
        elif role == 'not_guest_unconfined':
            assert (not has_guest and self._unconfined_ctx(output)), output
        elif role == 'xguest':
            assert has_xguest, output
        elif role == 'not_staff':
            assert not has_staff, output
        else:
            raise ValueError(f'unknown id -Z role: {role!r}')
        return output, code

    def _ssh_id_z_assert_denied(self, runner, user, target, password=ADPASS):
        """SSH ``id -Z`` and assert the session fails (non-zero exit code).

        Used when HBAC or SSH must reject access; output is not interpreted as
        a successful SELinux context.
        """
        output, code = self._ssh_id_z(runner, user, target, password=password)
        assert code != 0, output
        return output, code

    @classmethod
    def _add_pair(cls, external_group_name, posix_group_name,
                  trusted_member_account):
        """Create an external IPA group, a posix group, and link them with AD.

        Adds *trusted_member_account* to *external_group_name*, then nests the
        external group inside *posix_group_name* so trusted users resolve
        through the posix group for SELinux user map and HBAC tests.
        """
        tasks.group_add(
            cls.master, groupname=external_group_name,
            extra_args=['--external'])
        tasks.group_add(cls.master, groupname=posix_group_name)
        cls.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            trusted_member_account, external_group_name,
        ])
        tasks.group_add_member(
            cls.master, groupname=posix_group_name,
            extra_args=[f'--groups={external_group_name}'],
        )

    @contextmanager
    def _staff_selinux_user_map_context(
            self, map_name, posix_group, map_host_hostname):
        """Context: staff SELinux user map for one host and one posix group.

        On entry: ``kinit`` admin, ``ipa selinuxusermap-add`` with
        ``SELINUX_STAFF``, attach *posix_group* and *map_host_hostname*,
        refresh SSSD.  On exit: ``kinit`` admin, remove the map, refresh SSSD.

        Used by tests 001–002 to share setup/teardown without duplicated
        ``try``/``finally`` blocks.

        :param map_name: IPA selinuxusermap name (unique per scenario).
        :param posix_group: IPA posix group whose members get the map.
        :param map_host_hostname: Host where the map applies (FQDN string).
        """
        tasks.kinit_admin(self.master)
        try:
            tasks.selinuxusermap_add(
                self.master, map_name,
                extra_args=[f'--selinuxuser={self.SELINUX_STAFF}'])
            tasks.selinuxusermap_add_user(
                self.master, map_name, groups=posix_group)
            tasks.selinuxusermap_add_host(
                self.master, map_name, hosts=map_host_hostname)
            self._sssd_clear_all()
            yield
        finally:
            tasks.kinit_admin(self.master)
            tasks.selinuxusermap_del(
                self.master, map_name, raiseonerr=False)
            self._sssd_clear_all()

    @contextmanager
    def _hbac_staff_selinux_map_context(
            self, hbac_rule_name, staff_map_name, posix_group,
            hbac_host_hostname):
        """Context: HBAC (sshd) on one host plus staff SELinux map tied to it.

        Creates an HBAC rule allowing *posix_group* to *hbac_host_hostname*
        for ``sshd``, then a selinuxusermap with ``SELINUX_STAFF`` referencing
        that HBAC rule.  On exit: remove the map, delete the HBAC rule,
        refresh SSSD.

        :param hbac_rule_name: IPA hbacrule name.
        :param staff_map_name: IPA selinuxusermap name.
        :param posix_group: Group allowed by HBAC and used on the map.
        :param hbac_host_hostname: Client FQDN attached to the HBAC rule.
        """
        tasks.kinit_admin(self.master)
        try:
            tasks.hbacrule_add(self.master, hbac_rule_name)
            tasks.hbacrule_add_user(
                self.master, hbac_rule_name, groups=posix_group)
            tasks.hbacrule_add_host(
                self.master, hbac_rule_name, hosts=hbac_host_hostname)
            tasks.hbacrule_add_service(
                self.master, hbac_rule_name, services='sshd')
            tasks.selinuxusermap_add(
                self.master, staff_map_name,
                extra_args=[
                    f'--selinuxuser={self.SELINUX_STAFF}',
                    f'--hbacrule={hbac_rule_name}',
                ])
            self._sssd_clear_all()
            yield
        finally:
            tasks.kinit_admin(self.master)
            tasks.selinuxusermap_del(
                self.master, staff_map_name, raiseonerr=False)
            self.master.run_command(
                ['ipa', 'hbacrule-del', hbac_rule_name], raiseonerr=False)
            self._sssd_clear_all()

    def _run_id_z_case_rows(self, case_rows):
        """Execute a table of SSH ``id -Z`` checks.

        *case_rows* is an iterable of ``(ssh_runner_host, login_user,
        target_host, role)`` tuples passed to ``_ssh_id_z_assert`` in order.
        """
        for ssh_client, user, target, role in case_rows:
            self._ssh_id_z_assert(ssh_client, user, target, role)

    def test_ipa_trust_func_selinuxusermap_001(self):
        """SELinux user map restricted to one client host (001 / sub_001).

        **Verifies (forest, map on client 0 for ``G1`` + ``SELINUX_STAFF``):**

        - From client 0 or 1, ``aduser`` SSH to client 0 → ``id -Z`` shows
          staff MLS (``staff_u`` + ``s0-s0:c0.c1023``); SSH succeeds.
        - ``aduser2`` from client 0 to client 0 → not staff, default
          unconfined.
        - ``aduser`` from client 0 to client 1 → unconfined (no staff map on
          client 1).
        - ``aduser`` from client 1 to client 1 → not staff and unconfined
          (self-login on unmapped host).

        **Verifies (subdomain, ``SG1`` / ``subaduser`` / ``subaduser2``):**

        - ``subaduser`` → client 0: staff; → client 1: unconfined only.
        - ``subaduser2`` → client 0: not staff + unconfined.
        - From client 1, ``subaduser`` → client 0: staff; → client 1: not
          staff + unconfined.

        Password SSH; exit code 0 wherever a context is read.
        """
        self._require_selinux_clients()
        first_client, second_client = self.clients[0], self.clients[1]
        with self._staff_selinux_user_map_context(
                'selinux_umap_001_ad', self.G1, first_client.hostname):
            for ssh_client in first_client, second_client:
                self._ssh_id_z_assert(
                    ssh_client, self.testuser1, first_client, 'staff')
            self._ssh_id_z_assert(
                first_client, self.testuser2, first_client,
                'not_staff_unconfined')
            self._ssh_id_z_assert(
                second_client, self.testuser1, second_client,
                'not_staff_unconfined')
            self._ssh_id_z_assert(
                first_client, self.testuser1, second_client, 'unconfined')

        with self._staff_selinux_user_map_context(
                'selinux_umap_001_sub', self.SG1, first_client.hostname):
            self._run_id_z_case_rows([
                (first_client, self.subaduser, first_client, 'staff'),
                (first_client, self.subaduser, second_client, 'unconfined'),
                (first_client, self.subdomaintestuser2, first_client,
                 'not_staff_unconfined'),
                (second_client, self.subaduser, first_client, 'staff'),
                (second_client, self.subaduser, second_client,
                 'not_staff_unconfined'),
            ])

    def test_ipa_trust_func_selinuxusermap_002(self):
        """SELinux user map on the IPA master host only (002 / sub_002).

        **Verifies (forest, map host = master, group ``G1``):**

        - From client 0, ``aduser`` SSH to master → ``id -Z`` is staff.
        - From client 0, ``aduser`` SSH to client 0 → not staff, unconfined
          (map does not apply to the client).
        - From client 0, ``aduser2`` SSH to master → not staff, unconfined
          (not in mapped group).

        **Verifies (subdomain, map host = master, group ``SG1``):**

        - Same three cases for ``subaduser`` / ``subaduser2`` on master vs
          client 0.

        The map **host** limits where staff applies, not where SSH starts.
        """
        self._require_selinux_clients()
        first_client = self.clients[0]
        with self._staff_selinux_user_map_context(
                'selinux_umap_002_ad', self.G1, self.master.hostname):
            self._run_id_z_case_rows([
                (first_client, self.testuser1, self.master, 'staff'),
                (first_client, self.testuser1, first_client,
                 'not_staff_unconfined'),
                (first_client, self.testuser2, self.master,
                 'not_staff_unconfined'),
            ])

        with self._staff_selinux_user_map_context(
                'selinux_umap_002_sub', self.SG1, self.master.hostname):
            self._run_id_z_case_rows([
                (first_client, self.subaduser, self.master, 'staff'),
                (first_client, self.subaduser, first_client,
                 'not_staff_unconfined'),
                (first_client, self.subdomaintestuser2, self.master,
                 'not_staff_unconfined'),
            ])

    def test_ipa_trust_func_selinuxusermap_003(self):
        """Staff SELinux user map conditioned on an HBAC rule (003 / sub_003).

        HBAC rule allows ``sshd`` to one client for members of the posix
        group; selinuxusermap uses ``--hbacrule=`` so staff applies only when
        that HBAC allows access.

        **Verifies (forest, ``hbacrule3_1_ad``, map on client 0, ``G1``):**

        - From client 0, ``aduser`` SSH to client 0 → ``id -Z`` is staff.
        - From client 0, ``aduser2`` SSH to client 0 → not staff, unconfined.

        **Verifies (subdomain, ``hbacrule3_1_sub``, group ``SG1``):**

        - Same for ``subaduser`` / ``subaduser2`` on the first client.

        So membership in the HBAC rule and the map’s user list must align for
        staff; others keep the default unconfined mapping.
        """
        self._require_selinux_clients()
        first_client = self.clients[0]
        with self._hbac_staff_selinux_map_context(
                'hbacrule3_1_ad', 'selinux_umap3_1_ad', self.G1,
                first_client.hostname):
            self._run_id_z_case_rows([
                (first_client, self.testuser1, first_client, 'staff'),
                (first_client, self.testuser2, first_client,
                 'not_staff_unconfined'),
            ])

        with self._hbac_staff_selinux_map_context(
                'hbacrule3_1_sub', 'selinux_umap3_1_sub', self.SG1,
                first_client.hostname):
            self._run_id_z_case_rows([
                (first_client, self.subaduser, first_client, 'staff'),
                (first_client, self.subdomaintestuser2, first_client,
                 'not_staff_unconfined'),
            ])

    def _chain_004_cleanup(self, suffix):
        """Remove HBAC/selinux objects from :meth:`_chain_004` (best-effort).

        Called from test ``finally`` so a failed chain does not leave
        ``allow_all`` disabled, stale maps, or HBAC rules that break later
        tests (e.g. SSH exit failures or wrong ``id -Z`` in 008/009).
        """
        admin_allow_all_rule = f'admin_allow_all_{suffix}'
        hbac_user_u_rule = f'hbacrule4_1_{suffix}'
        hbac_staff_ssh_rule = f'hbacrule4_2_{suffix}'
        selinux_map_xguest_allow_all = f'selinux_umap4_0_{suffix}'
        selinux_map_user_u = f'selinux_umap4_1_{suffix}'
        selinux_map_staff = f'selinux_umap4_2_{suffix}'
        tasks.kinit_admin(self.master)
        for map_name in (
                selinux_map_staff,
                selinux_map_user_u,
                selinux_map_xguest_allow_all):
            tasks.selinuxusermap_del(
                self.master, map_name, raiseonerr=False)
        tasks.hbacrule_del(
            self.master, hbac_staff_ssh_rule, raiseonerr=False)
        tasks.hbacrule_del(self.master, hbac_user_u_rule, raiseonerr=False)
        tasks.hbacrule_enable(self.master, 'allow_all')
        tasks.hbacrule_del(
            self.master, admin_allow_all_rule, raiseonerr=False)
        tasks.hbacrule_enable(self.master, 'allow_all')

    def _chain_004(self, suffix, mapped_posix_group,
                   trusted_user_primary, trusted_user_secondary):
        """Long sequence: allow_all off, layered maps, then restore.

        Steps: admin ``allow_all``-style HBAC; disable global ``allow_all``;
        xguest map tied to ``allow_all``; per-user_u HBAC + map; staff map on
        first client with sshd HBAC.  Asserts staff vs user_u on different
        targets, removes maps/rules in order, re-enables ``allow_all``, checks
        xguest then unconfined for both trusted users, deletes admin rule.

        *suffix* disambiguates object names (``ad`` vs ``sub``).
        *mapped_posix_group* is ``G1`` or ``SG1``; *trusted_user_primary* /
        *trusted_user_secondary* are used for xguest/unconfined checks.
        """
        first_client, second_client = self.clients[0], self.clients[1]
        admin_allow_all_rule = f'admin_allow_all_{suffix}'
        hbac_user_u_rule = f'hbacrule4_1_{suffix}'
        hbac_staff_ssh_rule = f'hbacrule4_2_{suffix}'
        selinux_map_xguest_allow_all = f'selinux_umap4_0_{suffix}'
        selinux_map_user_u = f'selinux_umap4_1_{suffix}'
        selinux_map_staff = f'selinux_umap4_2_{suffix}'
        tasks.kinit_admin(self.master)
        self.master.run_command([
            'ipa', 'hbacrule-add', admin_allow_all_rule,
            '--hostcat=all', '--servicecat=all'])
        tasks.hbacrule_add_user(
            self.master, admin_allow_all_rule, groups='admins')
        tasks.hbacrule_disable(self.master, 'allow_all')
        tasks.selinuxusermap_add(
            self.master, selinux_map_xguest_allow_all,
            extra_args=[f'--selinuxuser={self.SELINUX_XGUEST}'])
        tasks.selinuxusermap_mod(
            self.master, selinux_map_xguest_allow_all,
            extra_args=['--hbacrule=allow_all'])
        # Explicit ``sshd`` + enrolled hosts (cf. test_hbac_functional): broad
        # ``--hostcat=all --servicecat=all`` can leave trusted users denied
        # when ``allow_all`` is off, which shows up as sshpass exit 5.
        tasks.hbacrule_add(self.master, hbac_user_u_rule)
        tasks.hbacrule_add_user(
            self.master, hbac_user_u_rule, groups=mapped_posix_group)
        for hb_host in (first_client, second_client, self.master):
            tasks.hbacrule_add_host(
                self.master, hbac_user_u_rule, hosts=hb_host.hostname)
        tasks.hbacrule_add_service(
            self.master, hbac_user_u_rule, services='sshd')
        tasks.selinuxusermap_add(
            self.master, selinux_map_user_u,
            extra_args=[f'--selinuxuser={self.SELINUX_USER_U}'])
        tasks.selinuxusermap_mod(
            self.master, selinux_map_user_u,
            extra_args=[f'--hbacrule={hbac_user_u_rule}'])
        tasks.hbacrule_add(self.master, hbac_staff_ssh_rule)
        tasks.hbacrule_add_user(
            self.master, hbac_staff_ssh_rule, groups=mapped_posix_group)
        tasks.hbacrule_add_host(
            self.master, hbac_staff_ssh_rule, hosts=first_client.hostname)
        tasks.hbacrule_add_service(
            self.master, hbac_staff_ssh_rule, services='sshd')
        tasks.selinuxusermap_add(
            self.master, selinux_map_staff,
            extra_args=[
                f'--selinuxuser={self.SELINUX_STAFF}',
                f'--hbacrule={hbac_staff_ssh_rule}',
            ])
        self._sssd_clear_all()
        self._sssd_prime_trusted_users(
            (trusted_user_primary, trusted_user_secondary),
            (self.master, first_client, second_client),
        )
        for target, role in (
                (first_client, 'staff'),
                (self.master, 'user_u_not_staff'),
                (second_client, 'user_u_not_staff')):
            self._ssh_id_z_assert(
                first_client, trusted_user_primary, target, role)
        tasks.selinuxusermap_del(self.master, selinux_map_staff)
        tasks.hbacrule_del(self.master, hbac_staff_ssh_rule)
        self._sssd_clear_all()

        self._ssh_id_z_assert(
            first_client, trusted_user_primary, first_client,
            'user_u_not_staff')

        tasks.selinuxusermap_del(self.master, selinux_map_user_u)
        tasks.hbacrule_del(self.master, hbac_user_u_rule)
        tasks.hbacrule_enable(self.master, 'allow_all')
        self._sssd_clear_all()

        self._ssh_id_z_assert(
            first_client, trusted_user_primary, first_client, 'xguest')
        self._ssh_id_z_assert(
            first_client, trusted_user_secondary, first_client, 'xguest')

        tasks.selinuxusermap_del(self.master, selinux_map_xguest_allow_all)
        self._sssd_clear_all()

        self._ssh_id_z_assert(
            first_client, trusted_user_primary, first_client, 'unconfined')
        self._ssh_id_z_assert(
            first_client, trusted_user_secondary, first_client, 'unconfined')

        tasks.hbacrule_del(self.master, admin_allow_all_rule)
        tasks.hbacrule_enable(self.master, 'allow_all')

    def test_ipa_trust_func_selinuxusermap_004(self):
        """Layered HBAC + selinuxusermap; ``allow_all`` toggled (004* / sub).

        Runs :meth:`_chain_004` twice (``suffix`` ``ad`` then ``sub``).  See
        that method for object names.  **End-to-end checks:**

        **While staff map + user_u HBAC + disabled global ``allow_all``:**

        - Primary user, SSH client 0 → client 0 → staff.
        - Same user to master or client 1 → ``user_u``, not staff.

        **After removing staff + user_u maps and re-enabling ``allow_all``:**

        - Primary on client 0 → xguest (map tied to ``allow_all``).
        - Secondary on client 0 → xguest.

        **After removing the xguest / ``allow_all`` map:**

        - Both users on client 0 → default unconfined.

        **Cleanup:** admin allow-all HBAC rule removed; ``allow_all`` on.

        Each run uses ``G1``/``aduser``/``aduser2`` or ``SG1``/subdomain;
        ``finally`` re-kinit admin and clears SSSD so a failed chain does not
        poison the next suffix.
        """
        self._require_selinux_clients()
        for suffix, mapped_group, user_primary, user_secondary in (
                ('ad', self.G1, self.testuser1, self.testuser2),
                ('sub', self.SG1, self.subaduser, self.subdomaintestuser2)):
            try:
                self._chain_004(
                    suffix, mapped_group, user_primary, user_secondary)
            finally:
                self._chain_004_cleanup(suffix)
                tasks.kinit_admin(self.master)
                self._sssd_clear_all()

    def _chain_005(self, suffix, mapped_posix_group,
                   trusted_user_primary, trusted_user_secondary):
        """Guest map on hostgroup containing only the second client (005*).

        Members of *mapped_posix_group* (``G2`` or ``SG2``) get ``guest_u``
        when SSHing to the second client via a map that references a hostgroup.
        Removing users from the map or deleting the hostgroup drops guest
        context back to unconfined for the secondary trusted user.
        """
        first_client, second_client = self.clients[0], self.clients[1]
        second_client_hostgroup = f'hostgrp_selinux_005_{suffix}'
        selinux_map_name = f'test_user_specific_hostgroup_{suffix}'
        tasks.kinit_admin(self.master)
        try:
            tasks.hostgroup_add(self.master, second_client_hostgroup)
            tasks.hostgroup_add_member(
                self.master, second_client_hostgroup,
                hosts=second_client.hostname)
            tasks.selinuxusermap_add(
                self.master, selinux_map_name,
                extra_args=[f'--selinuxuser={self.SELINUX_GUEST}'])
            tasks.selinuxusermap_add_host(
                self.master, selinux_map_name,
                extra_args=[f'--hostgroups={second_client_hostgroup}'])
            tasks.selinuxusermap_add_user(
                self.master, selinux_map_name, groups=mapped_posix_group)
            self._sssd_clear_all()

            self._ssh_id_z_assert(
                first_client, trusted_user_secondary, second_client, 'guest')
            self._ssh_id_z_assert(
                first_client, trusted_user_primary, second_client,
                'not_guest_unconfined')

            tasks.selinuxusermap_remove_user(
                self.master, selinux_map_name, groups=mapped_posix_group)
            self._sssd_clear_all()

            self._ssh_id_z_assert(
                first_client, trusted_user_secondary, second_client,
                'not_guest_unconfined')
        finally:
            tasks.kinit_admin(self.master)
            tasks.selinuxusermap_del(
                self.master, selinux_map_name, raiseonerr=False)
            tasks.hostgroup_del(
                self.master, second_client_hostgroup, raiseonerr=False)

    def test_ipa_trust_func_selinuxusermap_005(self):
        """Hostgroup map (client 1 only) with guest SELinux user (005*).

        **Verifies (forest ``G2`` / subdomain ``SG2``, :meth:`_chain_005`):**

        - Map uses ``SELINUX_GUEST`` and ``--hostgroups`` (hostgroup is only
          client 1).  User **not** on map: from client 0,
          ``trusted_user_primary`` → client 1 → not guest, unconfined.
        - ``trusted_user_secondary`` (in mapped posix group) → client 1 →
          ``guest_u``.
        - After ``selinuxusermap-remove-user`` drops the group from the map,
          ``trusted_user_secondary`` → client 1 → not guest, unconfined.

        Hostgroup targeting and map membership drive guest vs unconfined.
        """
        self._require_selinux_clients()
        for suffix, mapped_group, user_primary, user_secondary in (
                ('ad', self.G2, self.testuser1, self.testuser2),
                ('sub', self.SG2, self.subaduser, self.subdomaintestuser2)):
            try:
                self._chain_005(
                    suffix, mapped_group, user_primary, user_secondary)
            finally:
                tasks.kinit_admin(self.master)
                tasks.hbacrule_enable(self.master, 'allow_all')
                self._sssd_clear_all()

    def _chain_006(self, suffix, mapped_posix_group,
                   trusted_user_primary, trusted_user_secondary):
        """HBAC (sshd) to client 1 via hostgroup; staff map linked (006*).

        With ``allow_all`` disabled, only users in *mapped_posix_group* may SSH
        to the second client; staff SELinux map is tied to that HBAC rule.
        After removing users from the HBAC rule, both trusted users lose access
        (assert SSH denial).  Cleans up hostgroup, map, rule, re-enables
        ``allow_all``.
        """
        first_client = self.clients[0]
        second_client = self.clients[1]
        hostgroup_second_client = f'hostgrp_selinux_006_{suffix}'
        selinux_map_name = f'test_u_hostgroup_hbac_{suffix}'
        hbac_rule_name = f'rule6_{suffix}'
        tasks.kinit_admin(self.master)
        try:
            tasks.hbacrule_disable(self.master, 'allow_all')
            tasks.hostgroup_add(self.master, hostgroup_second_client)
            tasks.hostgroup_add_member(
                self.master, hostgroup_second_client,
                hosts=second_client.hostname)
            tasks.hbacrule_add(self.master, hbac_rule_name)
            tasks.hbacrule_add_service(
                self.master, hbac_rule_name, services='sshd')
            tasks.hbacrule_add_user(
                self.master, hbac_rule_name, groups=mapped_posix_group)
            self.master.run_command([
                'ipa', 'hbacrule-add-host', hbac_rule_name,
                f'--hostgroups={hostgroup_second_client}',
            ])
            tasks.selinuxusermap_add(
                self.master, selinux_map_name,
                extra_args=[
                    f'--selinuxuser={self.SELINUX_STAFF}',
                    f'--hbacrule={hbac_rule_name}',
                ])
            self._sssd_clear_all()
            self._sssd_prime_trusted_users(
                (trusted_user_primary, trusted_user_secondary),
                (first_client, second_client),
            )

            self._ssh_id_z_assert(
                first_client, trusted_user_secondary, second_client, 'staff')
            self._ssh_id_z_assert_denied(
                first_client, trusted_user_primary, second_client)
            tasks.hbacrule_remove_user(
                self.master, hbac_rule_name, groups=mapped_posix_group)
            self._sssd_clear_all()

            self._ssh_id_z_assert_denied(
                first_client, trusted_user_secondary, second_client)
        finally:
            tasks.kinit_admin(self.master)
            tasks.hostgroup_del(
                self.master, hostgroup_second_client, raiseonerr=False)
            tasks.selinuxusermap_del(
                self.master, selinux_map_name, raiseonerr=False)
            tasks.hbacrule_del(self.master, hbac_rule_name, raiseonerr=False)
            tasks.hbacrule_enable(self.master, 'allow_all')

    def test_ipa_trust_func_selinuxusermap_006(self):
        """HBAC hostgroup + sshd to client 1; staff map on that rule (006*).

        **Verifies (``G2`` / ``SG2``, :meth:`_chain_006`):**

        With ``allow_all`` **disabled**, HBAC allows only members of the mapped
        posix group to reach client 1 via ``sshd`` (hostgroup contains client
        1).  Staff selinuxusermap references that HBAC rule.

        - ``trusted_user_secondary`` (in group) client 0 → client 1: SSH OK,
          ``id -Z`` staff.
        - ``trusted_user_primary`` (not in group) same path: SSH **fails**
          (non-zero exit).

        After ``hbacrule-remove-user`` removes the group from the rule:

        - ``trusted_user_secondary`` → client 1: SSH **fails**.

        **Finally:** hostgroup, map, and HBAC rule removed; ``allow_all`` on.
        The test ``finally`` kinit admin, ``hbacrule-enable allow_all``, SSSD
        clear so HBAC is not left disabled.
        """
        self._require_selinux_clients()
        for suffix, mapped_group, user_primary, user_secondary in (
                ('ad', self.G2, self.testuser1, self.testuser2),
                ('sub', self.SG2, self.subaduser, self.subdomaintestuser2)):
            try:
                self._chain_006(
                    suffix, mapped_group, user_primary, user_secondary)
            finally:
                tasks.kinit_admin(self.master)
                tasks.hbacrule_enable(self.master, 'allow_all')
                self._sssd_clear_all()

    def _chain_007(self, suffix, mapped_posix_group,
                   trusted_user_primary, trusted_user_secondary):
        """One HBAC rule, two hostgroups (one per client); staff map (007*).

        ``allow_all`` is off.  HBAC permits *mapped_posix_group* for ``sshd``
        on hosts in both hostgroups.  Primary trusted user gets staff on each
        client; secondary user is not in the group (not staff).  After
        removing the group from HBAC, primary user can no longer SSH to the
        first client.
        """
        first_client, second_client = self.clients[0], self.clients[1]
        hostgroup_first_client = f'hostgrp7_1_{suffix}'
        hostgroup_second_client = f'hostgrp7_2_{suffix}'
        hbac_rule_name = f'rule7_{suffix}'
        hbac_ssh_secondary_rule = f'rule7_sshonly_{suffix}'
        selinux_map_name = f'test_umap_from_hg_{suffix}'
        secondary_hbac_group = self.G2 if suffix == 'ad' else self.SG2
        tasks.kinit_admin(self.master)
        try:
            self._sssd_clear_all()
            self._sssd_prime_trusted_users(
                (trusted_user_primary, trusted_user_secondary),
                (self.master, first_client, second_client),
            )
            tasks.hbacrule_disable(self.master, 'allow_all')
            for hostgroup_name, client_host in (
                    (hostgroup_first_client, first_client),
                    (hostgroup_second_client, second_client)):
                tasks.hostgroup_add(self.master, hostgroup_name)
                tasks.hostgroup_add_member(
                    self.master, hostgroup_name, hosts=client_host.hostname)
            tasks.hbacrule_add(self.master, hbac_rule_name)
            tasks.hbacrule_add_service(
                self.master, hbac_rule_name, services='sshd')
            tasks.hbacrule_add_user(
                self.master, hbac_rule_name, groups=mapped_posix_group)
            self.master.run_command([
                'ipa', 'hbacrule-add-host', hbac_rule_name,
                f'--hostgroups={hostgroup_first_client}',
                f'--hostgroups={hostgroup_second_client}',
            ])
            tasks.selinuxusermap_add(
                self.master, selinux_map_name,
                extra_args=[
                    f'--selinuxuser={self.SELINUX_STAFF}',
                    f'--hbacrule={hbac_rule_name}',
                ])
            # Secondary trusted user is not in *mapped_posix_group*; with
            # ``allow_all`` off they still need sshd HBAC.  No selinux map on
            # this rule so they stay unconfined (not staff).
            # ``ipa hbacrule-add-user --users=`` only accepts IPA user entries,
            # not ``user@ad.test`` principals (no such entry).  Use the
            # secondary user's posix group (``G2`` / ``SG2``) instead.
            tasks.hbacrule_add(self.master, hbac_ssh_secondary_rule)
            tasks.hbacrule_add_service(
                self.master, hbac_ssh_secondary_rule, services='sshd')
            tasks.hbacrule_add_user(
                self.master, hbac_ssh_secondary_rule,
                groups=secondary_hbac_group)
            self.master.run_command([
                'ipa', 'hbacrule-add-host', hbac_ssh_secondary_rule,
                f'--hostgroups={hostgroup_first_client}',
                f'--hostgroups={hostgroup_second_client}',
            ])
            self._sssd_clear_all()
            self._sssd_prime_trusted_users(
                (trusted_user_primary, trusted_user_secondary),
                (first_client, second_client),
            )

            for ssh_target_host in (first_client, second_client):
                self._ssh_id_z_assert(
                    first_client, trusted_user_primary, ssh_target_host,
                    'staff')
            self._ssh_id_z_assert(
                first_client, trusted_user_secondary, first_client,
                'not_staff')

            tasks.hbacrule_remove_user(
                self.master, hbac_rule_name, groups=mapped_posix_group)
            self._sssd_clear_all()

            self._ssh_id_z_assert_denied(
                first_client, trusted_user_primary, first_client)
        finally:
            tasks.kinit_admin(self.master)
            tasks.selinuxusermap_del(
                self.master, selinux_map_name, raiseonerr=False)
            tasks.hostgroup_del(
                self.master, hostgroup_first_client, raiseonerr=False)
            tasks.hostgroup_del(
                self.master, hostgroup_second_client, raiseonerr=False)
            tasks.hbacrule_del(
                self.master, hbac_ssh_secondary_rule, raiseonerr=False)
            tasks.hbacrule_del(self.master, hbac_rule_name, raiseonerr=False)
            tasks.hbacrule_enable(self.master, 'allow_all')

    def test_ipa_trust_func_selinuxusermap_007(self):
        """One HBAC rule, two hostgroups (clients 0 and 1); staff map (007*).

        **Verifies (``G1`` / ``SG1``, :meth:`_chain_007`):**

        With ``allow_all`` disabled, one HBAC rule grants ``sshd`` to both
        hostgroups for members of the posix group; staff map references that
        rule.

        - ``trusted_user_primary`` client 0 → client 0 and → client 1:
          staff.
        - ``trusted_user_secondary`` client 0 → client 0: SSH OK, ``id -Z``
          **not** staff (user outside mapped group).

        After removing the posix group from the HBAC rule:

        - ``trusted_user_primary`` client 0 → client 0: SSH **denied**.

        Cleanup: hostgroups, map, rule; ``allow_all`` on.  Test ``finally``:
        ``allow_all`` + SSSD after each suffix.
        """
        self._require_selinux_clients()
        for suffix, mapped_group, user_primary, user_secondary in (
                ('ad', self.G1, self.testuser1, self.testuser2),
                ('sub', self.SG1, self.subaduser, self.subdomaintestuser2)):
            try:
                self._chain_007(
                    suffix, mapped_group, user_primary, user_secondary)
            finally:
                tasks.kinit_admin(self.master)
                tasks.hbacrule_enable(self.master, 'allow_all')
                self._sssd_clear_all()

    def test_ipa_trust_func_selinuxusermap_008(self):
        """Empty ``ipaselinuxusermapdefault`` → unconfined for trusted users.

        **Verifies:**

        - After ``ipa config-mod --ipaselinuxusermapdefault=`` (empty) and
          SSSD refresh, from client 0 each of ``aduser``, ``aduser2``,
          ``subaduser``, ``subaduser2`` SSH to client 0; ``id -Z`` shows
          ``SELINUX_UNCONFINED_DEFAULT``.

        **``finally``:** config key restored to ``SELINUX_UNCONFINED_DEFAULT``.

        Beaker 008 (empty default selinux user).
        """
        self._require_selinux_clients()
        first_client = self.clients[0]
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(
                ['ipa', 'config-mod', '--ipaselinuxusermapdefault='])
            self._sssd_clear_all()

            trusted_users = (
                self.testuser1,
                self.testuser2,
                self.subaduser,
                self.subdomaintestuser2,
            )
            for trusted_user in trusted_users:
                self._ssh_id_z_assert(
                    first_client, trusted_user, first_client, 'unconfined')
        finally:
            tasks.kinit_admin(self.master)
            default = self.SELINUX_UNCONFINED_DEFAULT
            self.master.run_command([
                'ipa', 'config-mod',
                '--ipaselinuxusermapdefault=' + default,
            ])
            self._sssd_clear_all()

    def _chain_009(self, suffix, mapped_posix_group,
                   trusted_user_primary, _trusted_user_secondary):
        """Three overlapping maps on one host; ``user_u`` wins first (009*).

        Adds xguest, user_u, and guest maps for the same *mapped_posix_group*
        on the first client.  Expects ``user_u`` to win on that host; on the
        second client no map applies (unconfined).  Disables the user_u map and
        expects xguest to take over on the first client.  Deletes all three
        maps.  *trusted_user_secondary* is unused but kept for a uniform call
        signature with other chains.
        """
        first_client, second_client = self.clients[0], self.clients[1]
        selinux_map_xguest = f'selinux_umap9a_{suffix}'
        selinux_map_user_u = f'selinux_umap9b_{suffix}'
        selinux_map_guest = f'selinux_umap9c_{suffix}'
        tasks.kinit_admin(self.master)
        try:
            for map_name, selinux_user in (
                    (selinux_map_xguest, self.SELINUX_XGUEST),
                    (selinux_map_user_u, self.SELINUX_USER_U),
                    (selinux_map_guest, self.SELINUX_GUEST)):
                tasks.selinuxusermap_add(
                    self.master, map_name,
                    extra_args=[f'--selinuxuser={selinux_user}'])
                tasks.selinuxusermap_add_user(
                    self.master, map_name, groups=mapped_posix_group)
                tasks.selinuxusermap_add_host(
                    self.master, map_name, hosts=first_client.hostname)
            self._sssd_clear_all()

            self._ssh_id_z_assert(
                first_client, trusted_user_primary, first_client, 'user_u')
            self._ssh_id_z_assert(
                first_client, trusted_user_primary, second_client,
                'unconfined')

            tasks.selinuxusermap_disable(self.master, selinux_map_user_u)
            self._sssd_clear_all()

            self._ssh_id_z_assert(
                first_client, trusted_user_primary, first_client, 'xguest')
        finally:
            tasks.kinit_admin(self.master)
            for map_name in (
                    selinux_map_xguest,
                    selinux_map_user_u,
                    selinux_map_guest):
                tasks.selinuxusermap_del(
                    self.master, map_name, raiseonerr=False)

    def test_ipa_trust_func_selinuxusermap_009(self):
        """Overlapping selinuxusermaps on one host; precedence (009 / sub).

        **Verifies (``G1`` / ``SG1``, :meth:`_chain_009`):**

        Three maps on client 0 for the same posix group: xguest, user_u,
        guest (different IPA map names).

        - ``trusted_user_primary`` client 0 → client 0: ``id -Z`` is
          **user_u** (wins over xguest/guest).
        - Same user → client 1: **unconfined** (no map there).

        After ``selinuxusermap-disable`` on the user_u map:

        - Same user → client 0: **xguest**.

        All three maps deleted.  Test ``finally``: kinit admin, SSSD clear
        after each forest/subdomain iteration.
        """
        self._require_selinux_clients()
        for suffix, mapped_group, user_primary, user_secondary in (
                ('ad', self.G1, self.testuser1, self.testuser2),
                ('sub', self.SG1, self.subaduser, self.subdomaintestuser2)):
            try:
                self._chain_009(
                    suffix, mapped_group, user_primary, user_secondary)
            finally:
                tasks.kinit_admin(self.master)
                self._sssd_clear_all()
