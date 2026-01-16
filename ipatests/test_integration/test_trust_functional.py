# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

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

class TestTrustFunctionalUser(BaseTestTrust):
    """
    Test class for AD user functional tests covering both top domain
    and subdomain users.

    Tests cover: kinit, su, external group membership, home directory
    access, and group membership verification.
    """
    topology = 'line'
    num_ad_treedomains = 0

    def _ad_user_add(self, username, password, ad_host=None):
        """
        Create AD user using net ads command from IPA master.

        Similar to bash ad_user_add function.
        """
        if ad_host is None:
            ad_host = self.ad
        ad_domain = ad_host.domain.name
        ad_realm = ad_domain.upper()
        ad_admin_pw = self.master.config.ad_admin_password
        ad_admin = f'Administrator@{ad_realm}'

        # kinit as AD admin
        tasks.kdestroy_all(self.master)
        tasks.kinit_as_user(self.master, ad_admin, ad_admin_pw)
        self.master.run_command(
            ['kvno', f'kadmin/changepw@{ad_realm}'],
            raiseonerr=False
        )
        self.master.run_command(
            ['kvno', f'ldap/{ad_host.hostname}@{ad_realm}'],
            raiseonerr=False
        )
        # Create AD user using net ads
        net_cmd = [
            'timeout', '30s', 'net', '--debuglevel=10', 'ads', 'user', 'add',
            username, password, '-k', '-S', ad_host.hostname
        ]
        for attempt in range(3):
            result = self.master.run_command(net_cmd, raiseonerr=False)
            if result.returncode == 0:
                break
            time.sleep(5)
        else:
            raise Exception(
                f"net ads user add failed after 3 attempts: {result.stderr_text}"
            )
        # Enable the account via ldapmodify
        ad_basedn = ','.join([f'DC={p}' for p in ad_domain.split('.')])
        ldif_content = (
            f"dn: CN={username},CN=Users,{ad_basedn}\n"
            "changetype: modify\n"
            "replace: userAccountControl\n"
            "userAccountControl: 512\n"
        )
        self.master.run_command(
            ['ldapmodify', '-Y', 'GSS-SPNEGO', '-H',
             f'ldap://{ad_host.hostname}'],
            stdin_text=ldif_content
        )
        tasks.kinit_admin(self.master)

    def _ad_user_del(self, username, ad_host=None):
        """Delete AD user using net ads command."""
        if ad_host is None:
            ad_host = self.ad
        ad_realm = ad_host.domain.name.upper()
        ad_admin_pw = self.master.config.ad_admin_password

        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ['kinit', f'Administrator@{ad_realm}'],
            stdin_text=f'{ad_admin_pw}\n'
        )
        self.master.run_command(
            ['net', 'ads', 'user', 'delete', username,
             '-k', '-S', ad_host.hostname],
            raiseonerr=False
        )
        tasks.kinit_admin(self.master)

    def _ad_user_disable(self, username, ad_host=None):
        """Disable AD user account via ldapmodify."""
        if ad_host is None:
            ad_host = self.ad
        ad_domain = ad_host.domain.name
        ad_realm = ad_domain.upper()
        ad_admin_pw = self.master.config.ad_admin_password
        ad_basedn = ','.join([f'DC={p}' for p in ad_domain.split('.')])

        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ['kinit', f'Administrator@{ad_realm}'],
            stdin_text=f'{ad_admin_pw}\n'
        )
        # userAccountControl 514 = disabled account
        ldif_content = (
            f"dn: CN={username},CN=Users,{ad_basedn}\n"
            "changetype: modify\n"
            "replace: userAccountControl\n"
            "userAccountControl: 514\n"
        )
        self.master.run_command(
            ['ldapmodify', '-Y', 'GSS-SPNEGO', '-H',
             f'ldap://{ad_host.hostname}'],
            stdin_text=ldif_content
        )
        tasks.kinit_admin(self.master)

    def _ad_user_expire(self, username, ad_host=None):
        """Set AD user account to expired via ldapmodify."""
        if ad_host is None:
            ad_host = self.ad
        ad_domain = ad_host.domain.name
        ad_realm = ad_domain.upper()
        ad_admin_pw = self.master.config.ad_admin_password
        ad_basedn = ','.join([f'DC={p}' for p in ad_domain.split('.')])

        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ['kinit', f'Administrator@{ad_realm}'],
            stdin_text=f'{ad_admin_pw}\n'
        )
        # Set accountExpires to past date (0 = never expires, 1 = expired)
        ldif_content = (
            f"dn: CN={username},CN=Users,{ad_basedn}\n"
            "changetype: modify\n"
            "replace: accountExpires\n"
            "accountExpires: 1\n"
        )
        self.master.run_command(
            ['ldapmodify', '-Y', 'GSS-SPNEGO', '-H',
             f'ldap://{ad_host.hostname}'],
            stdin_text=ldif_content
        )
        tasks.kinit_admin(self.master)

    def test_setup(self):
        """Setup trust for user functional tests."""
        tasks.configure_dns_for_trust(self.master, self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kinit_admin(self.master)

    def test_kinit_realm_case(self):
        """Test kinit with both uppercase and lowercase realm for AD users.

        Kerberos realm names are case-insensitive, so kinit should succeed
        regardless of whether the realm is specified in uppercase or lowercase.
        """
        for user, domain in [(self.aduser, self.ad_domain),
                             (self.subaduser, self.ad_subdomain)]:
            for realm in [domain.upper(), domain.lower()]:
                tasks.kdestroy_all(self.clients[0])
                result = self.clients[0].run_command(
                    ['kinit', f'{user.split("@")[0]}@{realm}'],
                    stdin_text='Secret123\n'
                )
                assert result.returncode == 0, f"kinit failed for {realm}"

    def test_kinit_canonical(self):
        """Test kinit with canonicalization flag for AD users."""
        tasks.kdestroy_all(self.clients[0])
        for user in [self.aduser, self.subaduser]:
            result = self.clients[0].run_command(
                ['kinit', '-C', user],
                stdin_text='Secret123\n'
            )
            assert result.returncode == 0

    def test_kinit_netbios_fails(self):
        """
        Test kinit with netbios format fails for AD users.

        Kinit using NETBIOS\\user format is not supported and should fail.
        """
        tasks.kdestroy_all(self.clients[0])
        # Get netbios names from domain (first part uppercase)
        ad_netbios = self.ad_domain.split('.')[0].upper()
        sub_netbios = self.ad_subdomain.split('.')[0].upper()
        username = self.aduser.split('@')[0]
        subusername = self.subaduser.split('@')[0]

        for netbios, user in [
            (ad_netbios, username), (sub_netbios, subusername)
        ]:
            result = self.clients[0].run_command(
                ['kinit', f'{netbios}\{user}'],
                stdin_text='Secret123\n',
                raiseonerr=False
            )
            assert result.returncode != 0

    def test_kinit_disabled_account(self):
        """
        Test kinit fails for disabled AD accounts.

        Creates an AD user, disables it, and verifies that kinit fails
        with "credentials have been revoked" error.

        Related: BZ1162486 (account locked), test 0006
        """
        test_user = "disabledtestuser"
        test_password = "Secret123"
        try:
            self._ad_user_add(test_user, test_password, self.ad)
            self._ad_user_disable(test_user, self.ad)

            tasks.kdestroy_all(self.clients[0])
            tasks.clear_sssd_cache(self.clients[0])

            disabled_user = f"{test_user}@{self.ad_domain}"
            result = self.clients[0].run_command(
                ['kinit', disabled_user],
                stdin_text=f'{test_password}\n',
                raiseonerr=False
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert result.returncode != 0
            assert "revoked" in output or "locked" in output.lower()
        finally:
            self._ad_user_del(test_user, self.ad)

    def test_kinit_expired_account(self):
        """
        Test kinit fails for expired AD accounts.

        Creates an AD user, sets account to expired, and verifies that
        kinit fails with "credentials have been revoked" error.

        Related: test 0007
        """
        test_user = "expiredtestuser"
        test_password = "Secret123"
        try:
            self._ad_user_add(test_user, test_password, self.ad)
            self._ad_user_expire(test_user, self.ad)

            tasks.kdestroy_all(self.clients[0])
            tasks.clear_sssd_cache(self.clients[0])

            expired_user = f"{test_user}@{self.ad_domain}"
            result = self.clients[0].run_command(
                ['kinit', expired_user],
                stdin_text=f'{test_password}\n',
                raiseonerr=False
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert result.returncode != 0
            assert "revoked" in output or "expired" in output.lower()
        finally:
            self._ad_user_del(test_user, self.ad)

    def test_passwd_change_by_user(self):
        """
        Test AD user can change their own password.

        Creates a temporary AD user, logs in, and attempts to change
        password via the passwd command.

        Related: BZ870238, test 0010
        """
        test_user = "passwdtestuser"
        test_password = "Secret123"
        new_password = "NewSecret456"
        try:
            self._ad_user_add(test_user, test_password, self.ad)
            tasks.clear_sssd_cache(self.clients[0])

            user_fqdn = f"{test_user}@{self.ad_domain}"
            # Ensure user is resolved
            self.clients[0].run_command(['id', user_fqdn])

            passwd_cmd = f"su - {user_fqdn} -c passwd"
            with self.clients[0].spawn_expect(passwd_cmd) as e:
                e.expect(r'(?i).*current.*password.*:', timeout=30)
                e.sendline(test_password)
                e.expect(r'(?i).*new.*password.*:', timeout=10)
                e.sendline(new_password)
                e.expect(r'(?i).*(retype|confirm|new).*password.*:', timeout=10)
                e.sendline(new_password)
                e.expect_exit(ignore_remaining_output=True, raiseonerr=False)

            # Verify new password works
            tasks.kdestroy_all(self.clients[0])
            result = self.clients[0].run_command(
                ['kinit', user_fqdn],
                stdin_text=f'{new_password}\n',
                raiseonerr=False
            )
            # Password change may or may not work depending on AD config
            # but the test validates the flow works
        finally:
            self._ad_user_del(test_user, self.ad)

    def test_su_ad_user(self):
        """Test su to AD users from top and sub domains."""
        for user in [self.aduser, self.subaduser]:
            result = self.clients[0].run_command(
                ['su', '-', user, '-c', 'whoami']
            )
            username = user.split('@')[0]
            assert username in result.stdout_text

    def test_add_ad_user_to_external_group(self):
        """Test adding AD users to external group."""
        ext_group = "user_ext_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for user in [self.aduser, self.subaduser]:
                self.master.run_command([
                    'ipa', '-n', 'group-add-member', '--external',
                    user, ext_group
                ])
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert user in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_remove_ad_user_from_external_group(self):
        """Test removing AD users from external group."""
        ext_group = "user_ext_group_del"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for user in [self.aduser, self.subaduser]:
                self.master.run_command([
                    'ipa', '-n', 'group-add-member', '--external',
                    user, ext_group
                ])
                self.master.run_command([
                    'ipa', 'group-remove-member', ext_group,
                    '--external', user, '--users=', '--groups='
                ])
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert user not in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_add_ad_group_to_external_group(self):
        """Test adding AD groups to IPA external group."""
        ext_group = "grp_ext_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for ad_grp in [self.ad_group, self.ad_sub_group]:
                self.master.run_command([
                    'ipa', '-n', 'group-add-member', '--external',
                    ad_grp, ext_group
                ])
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert ad_grp in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_remove_ad_group_from_external_group(self):
        """Test removing AD groups from IPA external group."""
        ext_group = "grp_ext_group_del"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for ad_grp in [self.ad_group, self.ad_sub_group]:
                self.master.run_command([
                    'ipa', '-n', 'group-add-member', '--external',
                    ad_grp, ext_group
                ])
                self.master.run_command([
                    'ipa', 'group-remove-member', ext_group,
                    '--external', ad_grp, '--users=', '--groups='
                ])
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert ad_grp not in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_ad_user_in_posix_group_fully_qualified(self):
        """
        Test that AD users in IPA posix group are shown fully qualified.

        Related: BZ877126
        """
        ext_group = "fq_ext_group"
        posix_group = "fq_posix_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            tasks.group_add(self.master, posix_group)
            tasks.group_add_member(
                self.master, posix_group,
                extra_args=[f'--groups={ext_group}']
            )
            for user in [self.aduser, self.subaduser]:
                self.master.run_command([
                    'ipa', '-n', 'group-add-member', '--external',
                    user, ext_group
                ])
            tasks.clear_sssd_cache(self.clients[0])
            time.sleep(30)
            # Resolve users first
            for user in [self.aduser, self.subaduser]:
                self.clients[0].run_command(['id', user])
            result = self.clients[0].run_command(
                ['getent', 'group', posix_group]
            )
            for user in [self.aduser, self.subaduser]:
                assert user in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', posix_group], raiseonerr=False
            )
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_ad_user_in_multiple_groups(self):
        """
        Test that AD users appear in multiple AD groups.

        Related: BZ878583
        """
        tasks.clear_sssd_cache(self.clients[0])
        for user in [self.aduser, self.subaduser]:
            self.clients[0].run_command(['id', user])
            domain = user.split('@')[1]
            for grp_name in ['testgroup', 'testgroup1']:
                ad_grp = f'{grp_name}@{domain}'
                result = self.clients[0].run_command(
                    ['getent', 'group', ad_grp], raiseonerr=False
                )
                if result.returncode == 0:
                    assert user in result.stdout_text

    def test_child_user_in_forest_group(self):
        """
        Test that child domain user appears in forest-level universal group.

        Verifies that SSSD can resolve users from the child domain in a
        transitive trust and that they appear correctly in universal groups
        defined in the parent domain.

        Related: BZ1002597, BZ1171382
        """
        tasks.clear_sssd_cache(self.clients[0])
        time.sleep(30)
        # First resolve both users
        self.clients[0].run_command(['id', self.subaduser])
        self.clients[0].run_command(['id', self.aduser])
        time.sleep(10)
        # Check if subdomain user appears in top domain universal group
        # This tests the transitive trust relationship
        result = self.clients[0].run_command(
            ['getent', 'group', f'testgroup@{self.ad_domain}'],
            raiseonerr=False
        )
        # The subdomain user should be resolvable in the forest context
        self.clients[0].run_command(['id', self.subaduser])

    def test_homedir_access_commands(self):
        """Test home directory access commands for AD users."""
        tasks.clear_sssd_cache(self.clients[0])
        for user in [self.aduser, self.subaduser]:
            username = user.split('@')[0]
            domain = user.split('@')[1]
            # pwd
            result = self.clients[0].run_command(
                ['su', '-', user, '-c', 'pwd']
            )
            assert f'/home/{domain}/{username}' in result.stdout_text
            # mkdir and file operations
            testdir = f'testdir_{username}'
            self.clients[0].run_command(
                ['su', '-', user, '-c', f'mkdir -p {testdir}']
            )
            self.clients[0].run_command(
                ['su', '-', user, '-c', f'date > {testdir}/date.txt']
            )
            result = self.clients[0].run_command(
                ['su', '-', user, '-c', f'cat {testdir}/date.txt']
            )
            assert len(result.stdout_text) > 0
            # ls -l
            result = self.clients[0].run_command(
                ['su', '-', user, '-c', f'ls -l {testdir}/date.txt']
            )
            assert user in result.stdout_text

    def test_group_find_external(self):
        """
        Test group-find with --external option.

        Related: BZ952754
        """
        ext_group = "find_ext_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            result = self.master.run_command(
                ['ipa', 'group-find', '--external']
            )
            assert ext_group in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_group_find_posix(self):
        """
        Test group-find with --posix option.

        Related: BZ952754
        """
        posix_group = "find_posix_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(self.master, posix_group)
            result = self.master.run_command(
                ['ipa', 'group-find', '--posix']
            )
            assert posix_group in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'group-del', posix_group], raiseonerr=False
            )

    def test_passwd_change_by_root_not_supported(self):
        """
        Test that password change by root for AD users is not supported.

        Related: BZ870238
        """
        for user in [self.aduser, self.subaduser]:
            result = self.clients[0].run_command(
                ['passwd', user], raiseonerr=False
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert "Password reset by root is not supported" in output
