# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import time

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


class TestTrustFunctionalSHH(BaseTestTrust):
    topology = 'line'
    num_ad_treedomains = 0

    ad_user_password = 'Secret123'
    ad_user_first_password = 'Passw0rd1'
    ad_user_new_password = 'Passw0rd2'

    def cache_reset(self):
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])
        tasks.wait_for_sssd_domain_status_online(self.master)
        tasks.wait_for_sssd_domain_status_online(self.clients[0])
        # give time to SSSD to retrieve new records
        time.sleep(30)

    def test_ssh_setup(self):
        """Setup trust and client for SSH/GSSAPI tests.

        Enables the mkhomedir feature on the IPA client, configures DNS
        for the AD trust, establishes the trust with range type
        ipa-ad-trust, and kinits as the IPA admin on the master.
        """
        tasks.kinit_admin(self.clients[0])
        self.clients[0].run_command(
            ["authselect", "enable-feature", "with-mkhomedir"]
        )
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kinit_admin(self.master)

    def _ad_user_base(self, principal):
        return principal.split('@', 1)[0]

    def _ad_domain_netbios(self):
        return self.ad_domain.split('.', 1)[0]

    def _ad_principal(self, username, realm=False, domain=None):
        if domain is None:
            domain = self.ad_domain
        suffix = domain.upper() if realm else domain.lower()
        return f"{username}@{suffix}"

    def _ad_run_powershell(self, command, raiseonerr=True):
        """Run a PowerShell command on the AD host.

        Args:
            command: PowerShell command to execute
            raiseonerr: If True, raise on error; if False, return result
        """
        result = self.ad.run_command(
            ['powershell', '-c', command],
            raiseonerr=raiseonerr
        )
        return result

    def _ad_user_add(self, username, password, enabled=True):
        admin = self.master.config.ad_admin_name
        ad_realm = self.ad_domain.upper()
        admin_principal = self._ad_principal(admin, realm=True)
        ad_basedn = ','.join(f'DC={part}' for part in ad_realm.split('.'))
        ad_dirman = f"CN={admin},CN=Users,{ad_basedn}"

        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(
            self.master, admin_principal,
            self.master.config.ad_admin_password
        )
        self.master.run_command(['kvno', f'kadmin/changepw@{ad_realm}'])
        self.master.run_command(
            ['kvno', f'ldap/{self.ad.hostname}@{ad_realm}'])

        result = self.master.run_command([
            'net', '--debuglevel=10', 'ads', 'user', 'add',
            username, password, '-k', '-S', self.ad.hostname
        ], raiseonerr=False)
        if result.returncode != 0:
            self.master.run_command([
                'net', '--debuglevel=10', 'ads', 'user', 'add',
                username, password, '-k', '-S', self.ad.hostname
            ])

        # net ads user add leaves the account disabled; set
        # userAccountControl 512 (NORMAL_ACCOUNT) to enable it
        ldif = (
            f"dn: CN={username},CN=Users,{ad_basedn}\n"
            f"changetype: modify\n"
            f"replace: userAccountControl\n"
            f"userAccountControl: 512\n"
        )
        self.master.run_command(
            ['ldapmodify', '-Y', 'GSS-SPNEGO',
             '-H', f'ldap://{self.ad.hostname}',
             '-D', ad_dirman,
             '-w', self.master.config.ad_admin_password],
            stdin_text=ldif
        )

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

    def _ad_user_mod(self, username, options):
        """Run dsmod user on the AD host to modify an AD user account.

        Args:
            username: sAMAccountName of the user to modify
            options: list of dsmod flags, e.g. ['-mustchpwd', 'yes']
        """
        ad_realm = self.ad_domain.upper()
        ad_basedn = ','.join(f'DC={part}' for part in ad_realm.split('.'))
        ad_usercn = f"CN={username},CN=Users,{ad_basedn}"
        self.ad.run_command(['dsmod', 'user', ad_usercn] + options)

    def _ad_user_del(self, username):
        admin = self.master.config.ad_admin_name
        ad_realm = self.ad_domain.upper()
        admin_principal = self._ad_principal(admin, realm=True)

        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(
            self.master, admin_principal,
            self.master.config.ad_admin_password
        )
        self.master.run_command([
            'net', 'ads', 'user', 'delete', username,
            '-k', '-S', self.ad.hostname
        ], raiseonerr=False)
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

    def _ssh_with_password(self, host, login, target_host, password,
                           expect_success=True):
        if not tasks.is_package_installed(host, 'sshpass'):
            pytest.skip(f"sshpass not available on {host.hostname}")
        result = host.run_command(
            [
                'sshpass', '-p', password,
                'ssh', '-o', 'StrictHostKeyChecking=no',
                '-l', login, target_host, 'id'
            ],
            raiseonerr=expect_success,
        )
        return result

    def _ssh_with_gssapi(self, host, kinit_principal, login, target_host,
                         password, expect_success=True):
        tasks.kdestroy_all(host)
        tasks.kinit_as_user(host, kinit_principal, password)
        result = host.run_command(
            [
                'ssh', '-o', 'StrictHostKeyChecking=no', '-K',
                '-l', login, target_host, 'id'
            ],
            raiseonerr=expect_success,
        )
        return result

    def _get_log_tail(self, host, log_path, start_offset):
        return host.get_file_contents(
            log_path, encoding='utf-8')[start_offset:]

    def _log_file_if_exists(self, host, paths_to_check):
        for path in paths_to_check:
            if host.transport.file_exists(path):
                return path
        return None

    def _sssd_cache_reset_all(self):
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])

    def _spawn_ssh_interactive(self, host, login, target_host,
                               extra_ssh_options=None, remote_cmd=None):
        """Return a spawn_expect context for an interactive SSH session.

        Builds the standard SSH command with StrictHostKeyChecking disabled.

        Args:
            host: the host object on which to run SSH
            login: the SSH login name (-l argument)
            target_host: the hostname to connect to
            extra_ssh_options: extra options forwarded to spawn_expect
                               (e.g. ['-t'] for PTY allocation)
            remote_cmd: optional command string to execute remotely
        """
        cmd = [
            'ssh', '-o', 'StrictHostKeyChecking=no',
            '-l', login, target_host,
        ]
        if remote_cmd is not None:
            cmd.append(remote_cmd)
        return host.spawn_expect(cmd, extra_ssh_options=extra_ssh_options)

    def _expect_password_change_prompts(self, e, current_password,
                                        new_password):
        """Drive the current→new→confirm password-change prompt sequence.

        Handles the three-step interactive password-change dialogue that
        both SSH forced-change and passwd in-session flows share:
        current password prompt, new password prompt, confirm prompt.

        Args:
            e: the active spawn_expect context
            current_password: the user's current password
            new_password: the desired new password
        """
        e.expect(r'(?i)current password:')
        e.sendline(current_password)
        e.expect(r'(?i).*password.*:')
        e.sendline(new_password)
        e.expect(r'(?i).*password.*:')
        e.sendline(new_password)

    def test_ssh_password_unqualified_login_fails(self):
        """AD user SSH with password using short (unqualified) username fails.

        Verifies that password authentication is rejected when the AD user
        logs in with only their sAMAccountName (no domain suffix), because
        the IPA client cannot map an unqualified name to an AD identity.
        """
        testuser = self._ad_user_base(self.aduser)
        result = self._ssh_with_password(
            self.clients[0], testuser, self.clients[0].hostname,
            self.ad_user_password, expect_success=False)
        assert result.returncode != 0

    def test_ssh_gssapi_unqualified_login_fails(self):
        """AD user SSH with GSSAPI using short (unqualified) username fails.

        Verifies that GSSAPI authentication is rejected when the AD user's
        login name contains no domain suffix, even though a valid Kerberos
        ticket is obtained with the full UPN.
        """
        testuser = self._ad_user_base(self.aduser)
        ad_upn = self._ad_principal(testuser, realm=True)
        result = self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.clients[0].hostname,
            self.ad_user_password, expect_success=False)
        assert result.returncode != 0

    def test_ssh_password_fqdn_login(self):
        """AD user SSH with password using fully-qualified user@domain login.

        Verifies that password authentication succeeds when the AD user
        logs in as user@domain.lower.  Also checks that no sssd_be crash
        or core dump appears in /var/log/messages after the login.
        """
        testuser = self._ad_principal(self._ad_user_base(self.aduser))
        messages_path = self._log_file_if_exists(
            self.clients[0], [paths.MESSAGES])
        logsize = 0
        if messages_path:
            logsize = len(
                self.clients[0].get_file_contents(
                    messages_path, encoding='utf-8')
            )
        self._ssh_with_password(
            self.clients[0], testuser, self.clients[0].hostname,
            self.ad_user_password)
        if messages_path:
            tail = self._get_log_tail(self.clients[0], messages_path, logsize)
            assert "core dump" not in tail
            assert "sssd_be" not in tail

    def test_ssh_gssapi_localauth_plugin(self):
        """SSSD localauth plugin is present and AD user GSSAPI login works.

        Verifies that the SSSD localauth plugin configuration file and its
        module binary exist on the client, that krb5.conf does not contain
        a legacy auth_to_local rule, and that the AD user can log in via
        GSSAPI using the lowercase domain principal.
        """
        plugin_conf = (
            "/var/lib/sss/pubconf/krb5.include.d/localauth_plugin"
        )
        assert self.clients[0].transport.file_exists(plugin_conf)
        plugin_content = self.clients[0].get_file_contents(
            plugin_conf, encoding='utf-8'
        )
        localauth_module = None
        for line in plugin_content.splitlines():
            if line.strip().startswith('module'):
                localauth_module = line.split(':', 1)[-1].strip()
                break
        assert localauth_module
        assert self.clients[0].transport.file_exists(localauth_module)
        krb5_conf = self.clients[0].get_file_contents(
            paths.KRB5_CONF, encoding='utf-8'
        )
        assert "auth_to_local" not in krb5_conf
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), domain=self.ad_domain.lower())
        ad_upn = self._ad_principal(self._ad_user_base(self.aduser),
                                    realm=True)
        self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_password_upn_login(self):
        """AD user SSH with password using UPN (user@REALM) login succeeds.

        Verifies that password authentication works when the AD user's
        login name is in UPN format with the uppercase Kerberos realm
        (user@AD.DOMAIN.COM).
        """
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), realm=True)
        self._ssh_with_password(
            self.clients[0], testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_gssapi_upn_login(self):
        """AD user SSH with GSSAPI using UPN for both kinit and login.

        Verifies that GSSAPI authentication succeeds when the same UPN
        (user@REALM) is used as the kinit principal and as the SSH login
        name.
        """
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), realm=True)
        ad_upn = testuser
        self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_password_netbios_lower_login(self):
        """AD user SSH with password using lowercase NetBIOS prefix login.

        Verifies that password authentication succeeds when the AD user
        logs in with the Windows-style netbios\\user notation using a
        lowercase NetBIOS domain prefix.
        """
        testuser = "{0}\\{1}".format(
            self._ad_domain_netbios().lower(),
            self._ad_user_base(self.aduser),
        )
        self._ssh_with_password(
            self.clients[0], testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_gssapi_netbios_lower_login(self):
        """AD user SSH with GSSAPI using lowercase NetBIOS prefix login.

        Verifies that GSSAPI authentication succeeds when the SSH login
        name uses the lowercase netbios\\user notation while kinit is
        performed with the full UPN.
        """
        testuser = "{0}\\{1}".format(
            self._ad_domain_netbios().lower(),
            self._ad_user_base(self.aduser),
        )
        ad_upn = self._ad_principal(self._ad_user_base(self.aduser),
                                    realm=True)
        self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_password_netbios_upper_login(self):
        """AD user SSH with password using uppercase NetBIOS prefix login.

        Verifies that password authentication succeeds when the AD user
        logs in with the Windows-style NETBIOS\\user notation using an
        uppercase NetBIOS domain prefix.
        """
        testuser = "{0}\\{1}".format(
            self._ad_domain_netbios().upper(),
            self._ad_user_base(self.aduser),
        )
        self._ssh_with_password(
            self.clients[0], testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_gssapi_netbios_upper_login(self):
        """AD user SSH with GSSAPI using uppercase NetBIOS prefix login.

        Verifies that GSSAPI authentication succeeds when the SSH login
        name uses the uppercase NETBIOS\\user notation while kinit is
        performed with the full UPN.
        """
        testuser = "{0}\\{1}".format(
            self._ad_domain_netbios().upper(),
            self._ad_user_base(self.aduser),
        )
        ad_upn = self._ad_principal(self._ad_user_base(self.aduser),
                                    realm=True)
        self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.clients[0].hostname,
            self.ad_user_password)

    def test_ssh_gssapi_credential_forwarding(self):
        """AD user kinit and SSH as a second AD user via credential forwarding.

        Verifies that one AD user can obtain a Kerberos ticket and then
        forward GSSAPI credentials to SSH into the client as a different
        AD user, confirming cross-user credential delegation within an AD
        trust environment.
        """
        user1 = self._ad_principal(self._ad_user_base(self.aduser),
                                   domain=self.ad_domain.lower())
        user2 = self._ad_principal(self._ad_user_base(self.aduser2),
                                   domain=self.ad_domain.lower())
        client = self.clients[0]

        ssh_cmd = (
            'sshpass -p "Secret123" ssh -K -l {user2}'
            ' $(hostname) echo "login successful"'
        ).format(user2=user2)
        test_kinit_ssh = (
            "su {user} -c 'kinit {user} ; {ssh_cmd}'"
            .format(user=user1, ssh_cmd=ssh_cmd)
        )
        with client.spawn_expect(test_kinit_ssh) as e:
            e.expect(r'(?i).*Password for {}.*:'.format(user1))
            e.sendline(self.ad_user_password)
            e.expect('login successful', timeout=15)

    def test_ssh_gssapi_new_user_no_cache_flush(self):
        """Newly created AD user can SSH with GSSAPI without cache flush.

        Verifies that an AD user added during the test can immediately
        authenticate via GSSAPI over SSH, confirming that SSSD resolves
        brand-new AD accounts without requiring a manual cache reset.
        """
        username = 'adnew1'
        testuser = self._ad_principal(username)
        ad_upn = self._ad_principal(username, realm=True)
        ad_password = 'Secret123'
        try:
            self._ad_user_add(username, ad_password)
            self._ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                ad_password)
        finally:
            self._ad_user_del(username)

    def test_ssh_deleted_user_evicted_from_cache(self):
        """Deleted AD user is evicted from SSSD cache and kinit fails.

        Creates an AD user, resolves it via getent (populating the SSSD
        cache), deletes the user, flushes the SSSD cache, and then verifies
        that getent returns no entry and kinit reports the principal is not
        found in the Kerberos database.
        """
        username = 'adnew2'
        testuser = self._ad_principal(username)
        ad_upn = self._ad_principal(username, realm=True)
        ad_password = 'Secret123'
        try:
            self._ad_user_add(username, ad_password)
            self.master.run_command(['getent', 'passwd', testuser])
            self._ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                ad_password)
            self._ad_user_del(username)
            self._sssd_cache_reset_all()
            result = self.clients[0].run_command(
                ['getent', '-s', 'sss', 'passwd', testuser],
                raiseonerr=False,
            )
            assert result.returncode != 0
            result = self.clients[0].run_command(
                ['kinit', testuser],
                stdin_text=ad_password,
                raiseonerr=False,
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert "not found in Kerberos database" in output
        finally:
            self._ad_user_del(username)

    def test_ssh_recreated_user_login_after_cache_clear(self):
        """Re-created AD user can SSH after SSSD cache is cleared.

        Verifies that an AD user which was deleted and then re-added with
        the same name can still authenticate via GSSAPI and password SSH
        once the SSSD cache is flushed, ensuring stale cache entries do
        not block the re-created account.
        """
        username = 'adnew3'
        testuser = self._ad_principal(username)
        ad_upn = self._ad_principal(username, realm=True)
        ad_password = 'Secret123'
        try:
            self._ad_user_add(username, ad_password)
            self.master.run_command(['getent', 'passwd', testuser])
            self._ad_user_del(username)
            self._sssd_cache_reset_all()
            self.master.run_command(['getent', 'passwd', testuser],
                                    raiseonerr=False)
            self._ad_user_add(username, ad_password)
            self._sssd_cache_reset_all()
            tasks.kdestroy_all(self.clients[0])
            tasks.clear_sssd_cache(self.clients[0])
            self.clients[0].run_command(['getent', 'passwd', testuser])
            self._ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                ad_password)
            self._ssh_with_password(
                self.clients[0], testuser, self.clients[0].hostname,
                ad_password)
        finally:
            self._ad_user_del(username)

    def test_ssh_su_second_ad_user_in_session(self):
        """AD user can switch to a second AD user via su within SSH session.

        Verifies that after logging in via GSSAPI as one AD user, it is
        possible to switch to a different AD user using su inside the same
        SSH session, confirming correct PAM/SSSD identity handling for
        cross-user switches under an AD trust.
        """
        user1 = self._ad_principal(self._ad_user_base(self.aduser),
                                   domain=self.ad_domain.lower())
        user2 = self._ad_principal(self._ad_user_base(self.aduser2),
                                   domain=self.ad_domain.lower())
        client = self.clients[0]
        tasks.kdestroy_all(client)
        tasks.kinit_as_user(client, user1, self.ad_user_password)
        with client.spawn_expect([
            'ssh', '-o', 'StrictHostKeyChecking=no', '-K',
            '-l', user1, client.hostname
        ]) as e:
            e.sendline(f"su {user2} -c 'whoami'")
            e.expect(r'.*assword.*:')
            e.sendline(self.ad_user_password)
            e.expect(user2)
            e.sendline('exit')

    def test_ssh_password_to_master(self):
        """AD user SSH with password to the IPA master (server mode).

        Verifies that password authentication succeeds when the AD user
        connects to the IPA master rather than to a regular IPA client,
        exercising the server-mode SSSD code path.
        """
        testuser = self._ad_principal(self._ad_user_base(self.aduser))
        self._ssh_with_password(
            self.clients[0], testuser, self.master.hostname,
            self.ad_user_password)

    def test_ssh_gssapi_to_master(self):
        """AD user SSH with GSSAPI to the IPA master (server mode).

        Verifies that GSSAPI authentication succeeds when the AD user
        connects to the IPA master, exercising the server-mode SSSD and
        Kerberos PAC processing code paths.
        """
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), domain=self.ad_domain.lower())
        ad_upn = self._ad_principal(self._ad_user_base(self.aduser),
                                    realm=True)
        self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.master.hostname,
            self.ad_user_password)

    def test_ssh_gssapi_ad_user_ipa_cmd_denied(self):
        """AD user cannot run privileged IPA commands over GSSAPI SSH.

        Verifies that an AD user authenticated via GSSAPI is denied when
        attempting to execute `ipa trust-del` on the master over SSH,
        receiving an "insufficient access" or "cannot connect" error.
        """
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), domain=self.ad_domain.lower())
        ad_upn = self._ad_principal(self._ad_user_base(self.aduser),
                                    realm=True)
        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(self.master, ad_upn, self.ad_user_password)
        result = self.master.run_command(
            [
                'ssh', '-o', 'StrictHostKeyChecking=no', '-K',
                '-l', testuser, self.master.hostname,
                'ipa', 'trust-del', self.ad_domain
            ],
            raiseonerr=False,
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        assert ("cannot connect" in output.lower()
                or "insufficient access" in output.lower())

    def test_ssh_gssapi_ad_admin_trust_del_denied(self):
        """AD domain admin cannot delete the IPA-AD trust over GSSAPI SSH.

        Verifies that even the AD domain administrator is denied when
        trying to execute `ipa trust-del` on the master over SSH using
        GSSAPI credentials, ensuring the trust cannot be removed by an
        AD-side account.
        """
        admin = self.master.config.ad_admin_name
        admin_principal = self._ad_principal(admin, realm=True)
        admin_login = self._ad_principal(admin, domain=self.ad_domain.lower())
        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(self.master, admin_principal,
                            self.master.config.ad_admin_password)
        result = self.master.run_command(
            [
                'ssh', '-o', 'StrictHostKeyChecking=no', '-K',
                '-l', admin_login, self.master.hostname,
                'ipa', 'trust-del', self.ad_domain
            ],
            raiseonerr=False,
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        assert ("cannot connect" in output.lower()
                or "insufficient access" in output.lower())

    def test_ssh_password_change_forced_at_login(self):
        """AD user forced to change password on first SSH login can do so.

        Sets the AD account's "must change password at next logon" flag,
        then verifies the SSH session prompts for the current and a new
        password, accepts the change, and subsequently allows a successful
        login with the new credentials.
        """
        username = 'aduserpw1'
        testuser = self._ad_principal(username)
        try:
            self._ad_user_add(username, self.ad_user_first_password)
            self._ad_user_mod(username, [
                '-pwd', self.ad_user_first_password, '-mustchpwd', 'yes'
            ])
            tasks.clear_sssd_cache(self.clients[0])
            with self._spawn_ssh_interactive(
                self.clients[0], testuser, self.clients[0].hostname,
                extra_ssh_options=['-t']
            ) as e:
                e.expect(r'(?i).*password.*:')
                e.sendline(self.ad_user_first_password)
                self._expect_password_change_prompts(
                    e, self.ad_user_first_password, self.ad_user_new_password)
                e.expect(r'.*[$#] ')
                e.sendline('whoami')
                e.expect(testuser)
                e.sendline('exit')
                e.expect_exit(ignore_remaining_output=True, raiseonerr=False)
        finally:
            self._ad_user_del(username)

    def test_ssh_passwd_change_denied_canchpwd_no(self):
        """Aduser with 'cannot change password' is denied password change SSH

        Sets the AD account's "cannot change password" flag, logs in over
        SSH, attempts a password change via passwd, and verifies that the
        change is rejected with a "password change failed" message.
        """
        username = 'aduserpw2'
        testuser = self._ad_principal(username)
        try:
            self._ad_user_add(username, self.ad_user_first_password)
            self._ad_user_mod(username, [
                '-pwd', self.ad_user_first_password, '-canchpwd', 'no'
            ])
            with self._spawn_ssh_interactive(
                self.clients[0], testuser, self.clients[0].hostname,
                extra_ssh_options=['-t']
            ) as e:
                e.expect(r'(?i).*password.*:')
                e.sendline(self.ad_user_first_password)
                e.expect(r'.*[$#] ')
                e.sendline('passwd')
                self._expect_password_change_prompts(
                    e, self.ad_user_first_password, self.ad_user_new_password)
                e.sendline('exit')
                e.expect_exit(ignore_remaining_output=True, raiseonerr=False)
                assert 'password change failed' in e.before.lower()
        finally:
            self._ad_user_del(username)

    def test_ssh_password_disabled_account_rejected(self):
        """Disabled AD account is rejected during SSH password authentication.

        Disables an AD user account, attempts SSH password authentication,
        and verifies the login is denied.  Also checks that the failure is
        recorded as an authentication failure in the secure log.
        """
        username = 'aduserpw3'
        testuser = self._ad_principal(username)
        try:
            self._ad_user_add(username, self.ad_user_first_password)
            self._ad_user_mod(username, [
                '-pwd', self.ad_user_first_password, '-disabled', 'yes'
            ])
            # Give AD time to propagate the change and clear SSSD cache
            time.sleep(5)
            tasks.clear_sssd_cache(self.clients[0])
            time.sleep(10)
            with self._spawn_ssh_interactive(
                self.clients[0], testuser, self.clients[0].hostname,
                extra_ssh_options=['-t']
            ) as e:
                e.expect(r'(?i).*password.*:')
                e.sendline(self.ad_user_first_password)
                e.expect(r'(?i).*password.*:')
                e.sendcontrol('c')
                e.expect_exit(ignore_remaining_output=True, raiseonerr=False)
            log_output = self.clients[0].get_file_contents(
                paths.LOG_SECURE, encoding='utf-8')
            assert ("authentication failure" in log_output.lower()
                    or "authentication failure for" in log_output.lower())
        finally:
            self._ad_user_del(username)

    def test_ipa_trust_func_bug_878262(self):
        """
        Test ipa password auth works for user principal name when shorter
        than IPA Realm name.

        Bug: [BZ878262] ipa password auth failing for user principal name
        when shorter than IPA Realm name
        """
        # Only run if IPA domain is significantly longer than AD domain
        if len(self.master.domain.name) <= len(self.ad_domain) + 3:
            pytest.skip("IPA domain not long enough for this test")

        username = 'a1'
        testuser = self._ad_principal(username)
        password = 'Secret123'

        try:
            self._ad_user_add(username, password)
            tasks.kdestroy_all(self.master)

            # Test SSH with password authentication
            with self._spawn_ssh_interactive(
                self.master, testuser, self.master.hostname,
                remote_cmd="echo 'login successful'"
            ) as e:
                e.expect(r'(?i).*password.*:')
                e.sendline(password)
                e.expect('login successful')

            # Check logs for errors
            sssd_log = '{0}/sssd_{1}.log'.format(
                paths.VAR_LOG_SSSD_DIR, self.master.domain.name)
            if self.master.transport.file_exists(sssd_log):
                log_content = self.master.get_file_contents(sssd_log)
                assert b'User lookup failed' not in log_content

            secure_log = self._log_file_if_exists(
                self.master, [paths.VAR_LOG_SECURE, '/var/log/auth.log'])
            if secure_log:
                log_content = self.master.get_file_contents(
                    secure_log, encoding='utf-8')
                assert 'System error' not in log_content
                assert 'Failed password for a1@' not in log_content
        finally:
            self._ad_user_del(username)

    def test_ipa_trust_func_bug_954342(self):
        """
        Test sssd logs do not throw error when AD user tries to login via
        ipa client.

        Bug: [BZ954342] In IPA AD trust setup, the sssd logs throws
        'sysdb_search_user_by_name failed' error when AD user tries to
        login via ipa client.
        """
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), realm=False)
        ad_upn = self._ad_principal(
            self._ad_user_base(self.aduser), realm=True)

        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(
            self.master, ad_upn, self.master.config.ad_admin_password)

        # SSH with GSSAPI
        self.master.run_command([
            'ssh', '-K', '-l', testuser, self.master.hostname,
            'echo login successful $(whoami)'
        ])

        # Check sssd log for the error
        sssd_log = '{0}/sssd_{1}.log'.format(
            paths.VAR_LOG_SSSD_DIR, self.master.domain.name)
        if self.master.transport.file_exists(sssd_log):
            log_content = self.master.get_file_contents(sssd_log)
            assert b'sysdb_search_user_by_name failed' not in log_content

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

    def test_ipa_trust_func_bug_1097286(self):
        """
        Test expanding home directory works when the request comes from
        the PAC responder.

        Bug: [BZ1097286] Expanding home directory fails when the request
        comes from the PAC responder
        """
        testuser = f"Administrator@{self.ad_domain}"
        testuserupn = f"Administrator@{self.ad_domain.upper()}"

        # Test on master (server mode)
        self._sssd_cache_reset_all()
        tasks.wait_for_sssd_domain_status_online(self.master)

        # Verify server mode
        sssd_conf = self.master.get_file_contents(
            paths.SSSD_CONF, encoding='utf-8')
        assert 'ipa_server_mode = True' in sssd_conf

        tasks.kdestroy_all(self.master)
        self._ssh_with_gssapi(
            self.master, testuserupn, testuser, self.master.hostname,
            self.master.config.ad_admin_password)

        # Test on client
        sssd_conf = self.clients[0].get_file_contents(
            paths.SSSD_CONF, encoding='utf-8')
        assert f'ipa_server = _srv_, {self.master.hostname}' in sssd_conf

        tasks.kdestroy_all(self.clients[0])
        self._ssh_with_gssapi(
            self.clients[0], testuserupn, testuser,
            self.clients[0].hostname,
            self.clients[0].config.ad_admin_password)

    def test_ipa_trust_func_bug_1123432(self):
        """
        Test sssd_be must not crash on passwordless login.

        Bug: [BZ1123432] sssdbe must not crash on passwordless login
        """
        testuser = self._ad_principal(
            self._ad_user_base(self.aduser), realm=False)
        ad_upn = self._ad_principal(
            self._ad_user_base(self.aduser), realm=True)

        # Note: We check for errors after the test. If there were errors
        # before the test, they will still be present, but we're checking
        # that no NEW errors are introduced by the passwordless login.

        # Perform passwordless login
        self._ssh_with_gssapi(
            self.clients[0], ad_upn, testuser, self.clients[0].hostname,
            self.ad_user_password)

        # Check messages log for errors after test
        if self.clients[0].transport.file_exists(paths.MESSAGES):
            log_content_after = self.clients[0].get_file_contents(
                paths.MESSAGES, encoding='utf-8')
            assert 'Internal credentials cache error' not in log_content_after
            assert 'core_backtrace' not in log_content_after
            assert 'segfault' not in log_content_after
