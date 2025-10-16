# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

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
                    e.expect(r'.*assword for {}.*:'.format(user))
                    e.sendline('Secret123')
                    e.expect_exit(ignore_remaining_output=True, timeout=60)
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
