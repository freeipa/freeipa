# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import time

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


class TestTrustFunctionalSelinuxusermap(BaseTestTrust):
    """
    SELinux user mapping tests for AD users in trust environment.

    Ported from Beaker t.ipa_trust_func_selinuxusermap.sh
    """
    topology = 'line'
    num_ad_treedomains = 0
    num_ad_subdomains = 0
    num_clients = 2

    # SELinux user constants (from Beaker t.ipa_trust_func_selinuxusermap.sh)
    DEFAULT_SELINUXUSER = "unconfined_u:s0-s0:c0.c1023"
    DEFAULT_SELINUXUSER_VERIF = r"unconfined_u:.*s0-s0:c0\.c1023"
    T1_SELINUXUSER = "staff_u:s0-s0:c0.c1023"
    T1_SELINUXUSER_VERIF = r"staff_u:.*s0-s0:c0\.c1023"
    T2_SELINUXUSER = "user_u:s0"
    T2_SELINUXUSER_VERIF = r"user_u:.*s0"
    T3_SELINUXUSER = "xguest_u:s0"
    T3_SELINUXUSER_VERIF = r"xguest_u:.*s0"
    T4_SELINUXUSER = "guest_u:s0"
    T4_SELINUXUSER_VERIF = r"guest_u:.*s0"

    AD_PASSWORD = 'Secret123'

    def _clear_sssd_cache(self):
        """Clear SSSD cache on all hosts."""
        for host in [self.master] + list(self.clients):
            tasks.clear_sssd_cache(host)
            tasks.wait_for_sssd_domain_status_online(host)

    def _verify_ssh_selinuxuser_success_krb(
        self, from_host, user_principal, target_host, selinuxuser_pattern
    ):
        """SSH with Kerberos credentials, verify id -Z matches pattern."""
        tasks.kdestroy_all(from_host)
        from_host.run_command(
            ['kinit', user_principal],
            stdin_text=f'{self.AD_PASSWORD}\n',
            raiseonerr=True
        )
        result = from_host.run_command(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-l', user_principal,
             target_host.hostname, 'id', '-Z'],
            raiseonerr=True
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        assert re.search(selinuxuser_pattern, output), (
            f"Expected SELinux context matching {selinuxuser_pattern}, "
            f"got: {output}"
        )

    def _verify_ssh_selinuxuser_failure_krb(
        self, from_host, user_principal, target_host, selinuxuser_pattern
    ):
        """SSH with Kerberos, verify id -Z does NOT match pattern."""
        tasks.kdestroy_all(from_host)
        from_host.run_command(
            ['kinit', user_principal],
            stdin_text=f'{self.AD_PASSWORD}\n',
            raiseonerr=True
        )
        result = from_host.run_command(
            ['ssh', '-o', 'StrictHostKeyChecking=no', '-l', user_principal,
             target_host.hostname, 'id', '-Z'],
            raiseonerr=True
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        assert not re.search(selinuxuser_pattern, output), (
            f"Expected SELinux context NOT matching {selinuxuser_pattern}, "
            f"got: {output}"
        )

    def _verify_ssh_auth_success_selinuxuser(
        self, from_host, user, password, target_host, selinuxuser_pattern
    ):
        """SSH with password auth, verify id -Z matches pattern."""
        result = from_host.run_command(
            ['sshpass', '-p', password, 'ssh',
             '-o', 'StrictHostKeyChecking=no', '-o', 'PubkeyAuthentication=no',
             '-o', 'GSSAPIAuthentication=no',
             '-l', user, target_host.hostname, 'id', '-Z'],
            raiseonerr=True
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        assert re.search(selinuxuser_pattern, output), (
            f"Expected SELinux context matching {selinuxuser_pattern}, "
            f"got: {output}"
        )

    def _verify_ssh_auth_failure_selinuxuser(
        self, from_host, user, password, target_host, selinuxuser_pattern
    ):
        """SSH with password auth, verify id -Z does NOT match pattern."""
        result = from_host.run_command(
            ['sshpass', '-p', password, 'ssh',
             '-o', 'StrictHostKeyChecking=no', '-o', 'PubkeyAuthentication=no',
             '-o', 'GSSAPIAuthentication=no',
             '-l', user, target_host.hostname, 'id', '-Z'],
            raiseonerr=True
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        assert not re.search(selinuxuser_pattern, output), (
            f"Expected SELinux context NOT matching {selinuxuser_pattern}, "
            f"got: {output}"
        )

    def _ad_user_pairs(self):
        """Yield (mapped_user, other_user) for ad_testgrp1."""
        yield (self.aduser, self.aduser2)

    def _ad_user_pairs_grp2(self):
        """Yield (mapped_user, other_user) for ad_testgrp2."""
        yield (self.aduser2, self.aduser)

    @classmethod
    def install(cls, mh):
        super().install(mh)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kdestroy_all(cls.master)
        tasks.kinit_admin(cls.master)

        # Create external and internal groups for aduser
        tasks.group_add(
            cls.master, groupname="ad_testgrp1_ext",
            extra_args=["--external"]
        )
        tasks.group_add(cls.master, groupname="ad_testgrp1")
        cls.master.run_command([
            'ipa', '-n', 'group-add-member', 'ad_testgrp1_ext',
            '--external', cls.aduser
        ])
        cls.master.run_command([
            'ipa', 'group-add-member', 'ad_testgrp1',
            '--groups=ad_testgrp1_ext'
        ])

        # Create external and internal groups for aduser2
        tasks.group_add(
            cls.master, groupname="ad_testgrp2_ext",
            extra_args=["--external"]
        )
        tasks.group_add(cls.master, groupname="ad_testgrp2")
        cls.master.run_command([
            'ipa', '-n', 'group-add-member', 'ad_testgrp2_ext',
            '--external', cls.aduser2
        ])
        cls.master.run_command([
            'ipa', 'group-add-member', 'ad_testgrp2',
            '--groups=ad_testgrp2_ext'
        ])

        for host in [cls.master] + list(cls.clients):
            tasks.clear_sssd_cache(host)

        for user in [cls.aduser, cls.aduser2]:
            cls.master.run_command(['getent', 'passwd', user])

    def test_selinuxusermap_on_specific_host(self):
        """
        Verify SELinux user mapping applies only when target host matches.

        Creates selinuxusermap for ad_testgrp1 (staff_u) on CLIENT1 only.
        Verifies: ad_testgrp1 users get staff_u when SSHing to CLIENT1,
        unconfined_u on CLIENT2 and Master. ad_testgrp2 users get default
        on all hosts. Tests both Kerberos and password auth from master
        and both clients.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule1',
                f'--selinuxuser={self.T1_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule1',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule1',
                f'--hosts={self.clients[0].hostname}'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'selinuxusermaprule1']
            )

    def test_selinuxusermap_on_master_only(self):
        """
        Verify SELinux user mapping applies only when target host is Master.

        Creates selinuxusermap for ad_testgrp1 (staff_u) restricted to Master.
        Verifies: ad_testgrp1 users get staff_u when SSHing to Master,
        unconfined_u on CLIENT1 and CLIENT2. ad_testgrp2 users get default
        everywhere. Tests Kerberos and password auth from all hosts.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule2',
                f'--selinuxuser={self.T1_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule2',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule2',
                f'--hosts={self.master.hostname}'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.master,
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.master, self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.master, self.T1_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'selinuxusermaprule2']
            )

    def test_selinuxusermap_with_hbac_rule(self):
        """
        Verify HBAC rule and selinuxusermap together control access and
        context.

        Creates HBAC rule allowing ad_testgrp1 to access CLIENT1 via sshd,
        with selinuxusermap assigning staff_u. Verifies: ad_testgrp1 users
        get staff_u on CLIENT1 and default elsewhere; ad_testgrp2 users get
        default on all hosts. Tests Kerberos and password auth.
        """
        tasks.kinit_admin(self.master)
        try:
            self._clear_sssd_cache()
            self.master.run_command(['ipa', 'hbacrule-add', 'hbacrule3_1'])
            self.master.run_command([
                'ipa', 'hbacrule-add-user', 'hbacrule3_1',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'hbacrule3_1',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-service', 'hbacrule3_1',
                '--hbacsvcs=sshd'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermap3_1',
                f'--selinuxuser={self.T1_SELINUXUSER}',
                '--hbacrule=hbacrule3_1'
            ])

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'selinuxusermap3_1']
            )
            self.master.run_command(['ipa', 'hbacrule-del', 'hbacrule3_1'])

    def _setup_precedence_chain_004(self):
        """Setup selinuxusermap precedence chain (4_0, 4_1, 4_2)."""
        tasks.kinit_admin(self.master)
        self.master.run_command([
            'ipa', 'hbacrule-add', 'admin_allow_all',
            '--hostcat=all', '--servicecat=all'
        ])
        self.master.run_command([
            'ipa', 'hbacrule-add-user', 'admin_allow_all',
            '--groups=admins'
        ])
        self.master.run_command(['ipa', 'hbacrule-disable', 'allow_all'])
        self.master.run_command([
            'ipa', 'selinuxusermap-add', 'selinuxusermap4_0',
            f'--selinuxuser={self.T3_SELINUXUSER}'
        ])
        self.master.run_command([
            'ipa', 'selinuxusermap-mod', 'selinuxusermap4_0',
            '--hbacrule=allow_all'
        ])
        self.master.run_command([
            'ipa', 'hbacrule-add', 'hbacrule4_1',
            '--servicecat=all', '--hostcat=all'
        ])
        self.master.run_command([
            'ipa', 'hbacrule-add-user', 'hbacrule4_1',
            '--groups=ad_testgrp1'
        ])
        self.master.run_command([
            'ipa', 'selinuxusermap-add', 'selinuxusermap4_1',
            f'--selinuxuser={self.T2_SELINUXUSER}'
        ])
        self.master.run_command([
            'ipa', 'selinuxusermap-mod', 'selinuxusermap4_1',
            '--hbacrule=hbacrule4_1'
        ])
        self.master.run_command(['ipa', 'hbacrule-add', 'hbacrule4_2'])
        self.master.run_command([
            'ipa', 'hbacrule-add-user', 'hbacrule4_2',
            '--groups=ad_testgrp1'
        ])
        self.master.run_command([
            'ipa', 'hbacrule-add-host', 'hbacrule4_2',
            f'--hosts={self.clients[0].hostname}'
        ])
        self.master.run_command([
            'ipa', 'hbacrule-add-service', 'hbacrule4_2',
            '--hbacsvcs=sshd'
        ])
        self.master.run_command([
            'ipa', 'selinuxusermap-add', 'selinuxusermap4_2',
            f'--selinuxuser={self.T1_SELINUXUSER}',
            '--hbacrule=hbacrule4_2'
        ])

    def test_selinuxusermap_rule_precedence(self):
        """
        Verify host-specific selinuxusermap overrides general when both match.

        Creates precedence chain: general map (user_u), host-specific map
        (staff_u on CLIENT1). Verifies: on CLIENT1, staff_u takes precedence;
        on CLIENT2 and Master, user_u applies. Tests from master and clients.
        """
        tasks.kinit_admin(self.master)
        try:
            self._clear_sssd_cache()
            self._setup_precedence_chain_004()

            for mapped_user, _other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.master,
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T2_SELINUXUSER_VERIF
                )

            for mapped_user, _other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T2_SELINUXUSER_VERIF
                )

            for mapped_user, _other_user in self._ad_user_pairs():
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T2_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)

    def test_selinuxusermap_rule_precedence_after_removing_specific(self):
        """
        Verify fallback to general map when host-specific map is removed.

        Deletes host-specific selinuxusermap (staff_u on CLIENT1).
        Verifies: ad_testgrp1 users now get user_u from general map on all
        hosts. Continues from test_selinuxusermap_rule_precedence.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'selinuxusermap4_2']
            )
            self.master.run_command(['ipa', 'hbacrule-del', 'hbacrule4_2'])

            self._clear_sssd_cache()
            for mapped_user, _other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T2_SELINUXUSER_VERIF
                )

            for mapped_user, _other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T2_SELINUXUSER_VERIF
                )

            for mapped_user, _other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T2_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            # State left for test_selinuxusermap_004_3

    def test_selinuxusermap_rule_precedence_after_removing_general(self):
        """
        Verify fallback to default map when general map is removed.

        Deletes general selinuxusermap (user_u), re-enables allow_all.
        Verifies: ad_testgrp1 and ad_testgrp2 users get xguest_u from
        default map on all hosts. Continues from
        precedence_after_removing_specific.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'selinuxusermap4_1']
            )
            self.master.run_command(['ipa', 'hbacrule-del', 'hbacrule4_1'])
            self.master.run_command(['ipa', 'hbacrule-enable', 'allow_all'])

            self._clear_sssd_cache()
            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.master,
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[1],
                    self.T3_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.master, self.T3_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[1], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.master, self.T3_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)

    def test_selinuxusermap_rule_precedence_after_removing_default(self):
        """
        Verify fallback to IPA default when default map is removed.

        Deletes default selinuxusermap (xguest_u).
        Verifies: all AD users get unconfined_u (IPA default) on all hosts.
        Continues from precedence_after_removing_general.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'selinuxusermap4_0']
            )
            self.master.run_command(['ipa', 'hbacrule-del', 'admin_allow_all'])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)

    def test_selinuxusermap_with_hostgroup(self):
        """
        Verify selinuxusermap --hostgroup restricts mapping to hostgroup hosts.

        Creates hostgroup containing CLIENT2, selinuxusermap for ad_testgrp2
        (guest_u) on that hostgroup. Verifies: ad_testgrp2 users get guest_u
        on CLIENT2 only; on CLIENT1 and Master they get default unconfined_u.
        ad_testgrp1 users get default everywhere.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp1', '--desc=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp1',
                f'--hosts={self.clients[1].hostname}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'test_user_specific_hostgroup',
                f'--selinuxuser={self.T4_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host',
                'test_user_specific_hostgroup', '--hostgroups=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user',
                'test_user_specific_hostgroup', '--groups=ad_testgrp2'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[1],
                    self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[1], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp1'])
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'test_user_specific_hostgroup']
            )

    def test_selinuxusermap_with_hostgroup_after_removing_user(self):
        """
        Verify users get default when removed from selinuxusermap.

        Removes ad_testgrp2 from hostgroup selinuxusermap.
        Verifies: ad_testgrp2 users now get default unconfined_u on all hosts.
        ad_testgrp1 users continue to get default everywhere.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp1', '--desc=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp1',
                f'--hosts={self.clients[1].hostname}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'test_user_specific_hostgroup',
                f'--selinuxuser={self.T4_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host',
                'test_user_specific_hostgroup', '--hostgroups=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user',
                'test_user_specific_hostgroup', '--groups=ad_testgrp2'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-remove-user',
                'test_user_specific_hostgroup', '--groups=ad_testgrp2'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[1],
                    self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_auth_failure_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T4_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp1'])
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'test_user_specific_hostgroup']
            )

    def test_selinuxusermap_with_hbac_rule_and_hostgroup(self):
        """
        Verify HBAC rule + selinuxusermap + hostgroup work together.

        Creates rule6 allowing ad_testgrp2 to access hostgroup (CLIENT2) via
        sshd, selinuxusermap assigns staff_u. Verifies: ad_testgrp2 users can
        SSH to CLIENT2 with staff_u; access to CLIENT1 and Master denied by
        HBAC.
        ad_testgrp1 users denied everywhere by rule6.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(['ipa', 'hbacrule-disable', 'allow_all'])
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp1', '--desc=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp1',
                f'--hosts={self.clients[1].hostname}'
            ])
            self.master.run_command(['ipa', 'hbacrule-add', 'rule6'])
            self.master.run_command([
                'ipa', 'hbacrule-add-service', 'rule6', '--hbacsvcs=sshd'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-user', 'rule6', '--groups=ad_testgrp2'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'rule6', '--hostgroups=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'test_user_specific_hostgroup',
                f'--selinuxuser={self.T1_SELINUXUSER}', '--hbacrule=rule6'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )
                self.master.run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.clients[1].hostname, 'id'],
                    raiseonerr=True
                )
                result = self.master.run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.clients[1].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.master.run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T1_SELINUXUSER_VERIF
                )
                result = self.clients[0].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[0].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.clients[1].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T1_SELINUXUSER_VERIF
                )
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.clients[0].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.clients[0].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.clients[1].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp1'])
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'test_user_specific_hostgroup']
            )
            self.master.run_command(['ipa', 'hbacrule-del', 'rule6'])
            self.master.run_command(['ipa', 'hbacrule-enable', 'allow_all'])

    def test_selinuxusermap_with_hbac_rule_after_removing_user(self):
        """
        Verify access denied when user group removed from HBAC rule.

        Removes ad_testgrp2 from rule6. Verifies: ad_testgrp2 users are now
        denied SSH access to all hosts (HBAC blocks before selinuxusermap).
        ad_testgrp1 users also denied (not in rule6).
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(['ipa', 'hbacrule-disable', 'allow_all'])
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp1', '--desc=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp1',
                f'--hosts={self.clients[1].hostname}'
            ])
            self.master.run_command(['ipa', 'hbacrule-add', 'rule6'])
            self.master.run_command([
                'ipa', 'hbacrule-add-service', 'rule6', '--hbacsvcs=sshd'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-user', 'rule6', '--groups=ad_testgrp2'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'rule6', '--hostgroups=hostgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'test_user_specific_hostgroup',
                f'--selinuxuser={self.T1_SELINUXUSER}', '--hbacrule=rule6'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-remove-user', 'rule6', '--groups=ad_testgrp2'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                for host in [self.master, self.clients[0], self.clients[1]]:
                    result = self.master.run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', mapped_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
                    result = self.master.run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', other_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                for host in [self.master, self.clients[0], self.clients[1]]:
                    result = self.clients[0].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', mapped_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
                    result = self.clients[0].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', other_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs_grp2():
                for host in [self.master, self.clients[0], self.clients[1]]:
                    result = self.clients[1].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', mapped_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
                    result = self.clients[1].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', other_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp1'])
            self.master.run_command(
                ['ipa', 'selinuxusermap-del', 'test_user_specific_hostgroup']
            )
            self.master.run_command(['ipa', 'hbacrule-del', 'rule6'])
            self.master.run_command(['ipa', 'hbacrule-enable', 'allow_all'])

    def test_selinuxusermap_with_hbac_rule_two_hostgroups(self):
        """
        Verify selinuxusermap across multiple hostgroups in one HBAC rule.

        Creates rule7 allowing ad_testgrp1 to access hostgrp7-1 (CLIENT1) and
        hostgrp7-2 (CLIENT2). Verifies: ad_testgrp1 users get staff_u on both
        clients; access to Master denied by HBAC. ad_testgrp2 denied
        everywhere.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(['ipa', 'hbacrule-disable', 'allow_all'])
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp7-1', '--desc=hostgrp7-1'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp7-1',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp7-2', '--desc=hostgrp7-2'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp7-2',
                f'--hosts={self.clients[1].hostname}'
            ])
            self.master.run_command(['ipa', 'hbacrule-add', 'rule7'])
            self.master.run_command([
                'ipa', 'hbacrule-add-service', 'rule7', '--hbacsvcs=sshd'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-user', 'rule7', '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'rule7',
                '--hostgroups=hostgrp7-1'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'rule7',
                '--hostgroups=hostgrp7-2'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add',
                'test_user_specific_hostgroup_from_hostgroup',
                f'--selinuxuser={self.T1_SELINUXUSER}', '--hbacrule=rule7'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.master,
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[0],
                    self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[1],
                    self.T1_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T1_SELINUXUSER_VERIF
                )
                result = self.clients[0].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[0].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.clients[1].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[0].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T1_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.T1_SELINUXUSER_VERIF
                )
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', mapped_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.clients[0].hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
                result = self.clients[1].run_command(
                    ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PubkeyAuthentication=no',
                     '-o', 'GSSAPIAuthentication=no',
                     '-l', other_user, self.master.hostname, 'id'],
                    raiseonerr=False
                )
                assert result.returncode != 0
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp7-1'])
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp7-2'])
            self.master.run_command([
                'ipa', 'selinuxusermap-del',
                'test_user_specific_hostgroup_from_hostgroup'
            ])
            self.master.run_command(['ipa', 'hbacrule-del', 'rule7'])
            self.master.run_command(['ipa', 'hbacrule-enable', 'allow_all'])

    def test_selinuxusermap_with_hbac_rule_two_hostgroups_after_removing_user(
            self):
        """
        Verify access denied when user group removed from multi-hostgroup rule.

        Removes ad_testgrp1 from rule7. Verifies: ad_testgrp1 users are now
        denied SSH access to all hosts. ad_testgrp2 users also denied.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(['ipa', 'hbacrule-disable', 'allow_all'])
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp7-1', '--desc=hostgrp7-1'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp7-1',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add', 'hostgrp7-2', '--desc=hostgrp7-2'
            ])
            self.master.run_command([
                'ipa', 'hostgroup-add-member', 'hostgrp7-2',
                f'--hosts={self.clients[1].hostname}'
            ])
            self.master.run_command(['ipa', 'hbacrule-add', 'rule7'])
            self.master.run_command([
                'ipa', 'hbacrule-add-service', 'rule7', '--hbacsvcs=sshd'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-user', 'rule7', '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'rule7',
                '--hostgroups=hostgrp7-1'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-add-host', 'rule7',
                '--hostgroups=hostgrp7-2'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add',
                'test_user_specific_hostgroup_from_hostgroup',
                f'--selinuxuser={self.T1_SELINUXUSER}', '--hbacrule=rule7'
            ])
            self.master.run_command([
                'ipa', 'hbacrule-remove-user', 'rule7', '--groups=ad_testgrp1'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                for host in [self.master, self.clients[0], self.clients[1]]:
                    result = self.master.run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', mapped_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
                    result = self.master.run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', other_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs():
                for host in [self.master, self.clients[0], self.clients[1]]:
                    result = self.clients[0].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', mapped_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
                    result = self.clients[0].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', other_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0

            for mapped_user, other_user in self._ad_user_pairs():
                for host in [self.master, self.clients[0], self.clients[1]]:
                    result = self.clients[1].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', mapped_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
                    result = self.clients[1].run_command(
                        ['sshpass', '-p', self.AD_PASSWORD, 'ssh',
                         '-o', 'StrictHostKeyChecking=no',
                         '-o', 'PubkeyAuthentication=no',
                         '-o', 'GSSAPIAuthentication=no',
                         '-l', other_user, host.hostname, 'id'],
                        raiseonerr=False
                    )
                    assert result.returncode != 0
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp7-1'])
            self.master.run_command(['ipa', 'hostgroup-del', 'hostgrp7-2'])
            self.master.run_command([
                'ipa', 'selinuxusermap-del',
                'test_user_specific_hostgroup_from_hostgroup'
            ])
            self.master.run_command(['ipa', 'hbacrule-del', 'rule7'])
            self.master.run_command(['ipa', 'hbacrule-enable', 'allow_all'])

    def test_selinuxusermap_with_empty_default(self):
        """
        Verify AD users get system default when IPA selinuxusermap default
        empty.

        Clears ipaselinuxusermapdefault. Verifies: AD users get unconfined_u
        (system default) on all hosts when IPA default is not set.
        Restores default in cleanup.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command(
                ['ipa', 'config-mod', '--ipaselinuxusermapdefault=']
            )
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'config-mod',
                '--ipaselinuxusermapdefault=unconfined_u:s0-s0:c0.c1023'
            ])

    def test_selinuxusermap_precedence_multiple_maps(self):
        """
        Verify precedence when multiple selinuxusermaps match same user/host.

        Creates three maps on CLIENT1 for ad_testgrp1: xguest_u, user_u,
        guest_u.
        Verifies: user_u (second in order) takes precedence. ad_testgrp2 users
        get default. Tests from master and both clients.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule1',
                f'--selinuxuser={self.T3_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule1',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule1',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule2',
                f'--selinuxuser={self.T2_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule2',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule2',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule3',
                f'--selinuxuser={self.T4_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule3',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule3',
                f'--hosts={self.clients[0].hostname}'
            ])
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'selinuxusermap-del',
                'selinuxusermaprule1', 'selinuxusermaprule2',
                'selinuxusermaprule3'
            ])

    def test_selinuxusermap_precedence_after_disabling_map(self):
        """
        Verify next map applies when leading map is disabled.

        Creates three maps on CLIENT1, then disables the one (user_u) that
        was taking precedence. Verifies: ad_testgrp1 users now get xguest_u
        from next matching map on CLIENT1; ad_testgrp2 users get default.
        """
        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule1',
                f'--selinuxuser={self.T3_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule1',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule1',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule2',
                f'--selinuxuser={self.T2_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule2',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule2',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add', 'selinuxusermaprule3',
                f'--selinuxuser={self.T4_SELINUXUSER}'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-user', 'selinuxusermaprule3',
                '--groups=ad_testgrp1'
            ])
            self.master.run_command([
                'ipa', 'selinuxusermap-add-host', 'selinuxusermaprule3',
                f'--hosts={self.clients[0].hostname}'
            ])
            self.master.run_command(
                ['ipa', 'selinuxusermap-disable', 'selinuxusermaprule2']
            )
            self._clear_sssd_cache()

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T2_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[0],
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.clients[1],
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, mapped_user, self.master,
                    self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_failure_krb(
                    self.master, other_user, self.clients[0],
                    self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_selinuxuser_success_krb(
                    self.master, other_user, self.clients[0],
                    self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[0], other_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )

            for mapped_user, other_user in self._ad_user_pairs():
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[0], self.T3_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.clients[1], self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], mapped_user, self.AD_PASSWORD,
                    self.master, self.DEFAULT_SELINUXUSER_VERIF
                )
                self._verify_ssh_auth_success_selinuxuser(
                    self.clients[1], other_user, self.AD_PASSWORD,
                    self.clients[0], self.DEFAULT_SELINUXUSER_VERIF
                )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'selinuxusermap-del',
                'selinuxusermaprule1', 'selinuxusermaprule2',
                'selinuxusermaprule3'
            ])
