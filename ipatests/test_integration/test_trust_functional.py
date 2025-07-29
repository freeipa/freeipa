# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import time
import pytest
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration import skip_if_fips


class TestTrustFunctional(IntegrationTest):
    topology = 'line'
    num_clients = 1
    num_ad_domains = 1
    num_ad_subdomains = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_client(cls.master, cls.clients[0])
        cls.ad = cls.ads[0]
        cls.child_ad = cls.ad_subdomains[0]
        cls.aduser = f'nonposixuser@{cls.ad.domain.name}'
        cls.aduser2 = f'nonposixuser1@{cls.ad.domain.name}'

        cls.subaduser = f'subdomaintestuser@{cls.child_ad.domain.name}'
        cls.subaduser2 = f'subdomaindisabledadu@{cls.child_ad.domain.name}'
        cls.ad_group = f'testgroup@{cls.ad.domain.name}'
        cls.ad_sub_group = f'subdomaintestgroup@{cls.child_ad.domain.name}'
        cls.log_file = '{0}/sssd_{1}.log'.format(
            paths.VAR_LOG_SSSD_DIR, cls.master.domain.name)

        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.configure_windows_dns_for_trust(cls.ad, cls.master)
        if cls.master.is_fips_mode:
            pytest.skip("RHEL-12154")
        tasks.establish_trust_with_ad(
            cls.master,
            cls.ad.domain.name,
            extra_args=['--range-type=ipa-ad-trust', '--two-way=true']
        )
        tasks.kdestroy_all(cls.master)
        tasks.kinit_admin(cls.master)
        tasks.group_add(
            cls.master,
            groupname="hbacgroup_external",
            extra_args=["--external"],
        )
        tasks.group_add(cls.master, groupname="hbacgroup")
        tasks.group_add_member(
            cls.master,
            groupname="hbacgroup",
            extra_args=['--groups=hbacgroup_external'],
        )
        cls.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            cls.aduser, 'hbacgroup_external',
        ])
        cls.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            cls.subaduser, 'hbacgroup_external',
        ])

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
             'ssh', '-l', login, host, "id"],
            raiseonerr=success_expected
        )
        output = f"{result.stdout_text}{result.stderr_text}"
        return output

    def _get_log_tail(self, host, log_path, start_offset):
        return host.get_file_contents(log_path)[start_offset:]

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['user', 'group', 'subuser', 'subgroup'])
    def test_ipa_trust_func_hbac_0001(self, arg):
        """
        Test that adding non-existent AD users/groups to HBAC rules fails.

        This test verifies that when attempting to add AD users or groups that
        don't exist in the trust relationship to HBAC rules for both SSH and
        sudo services, the operation fails with a "no such entry" error.

        """
        hrule = "hbacrule_hbac_0001"
        tasks.kinit_admin(self.master)
        try:
            for service in ['sshd', 'sudo']:
                self.master.run_command(["ipa", "hbacrule-del", hrule],
                                        raiseonerr=False
                                        )
                self._add_hbacrule_with_service(hrule, service)
                if arg == 'user':
                    cmd = f"--users={self.aduser}"
                elif arg == 'group':
                    cmd = f"--groups={self.ad_group}"
                elif arg == 'subuser':
                    cmd = f"--users={self.subaduser}"
                elif arg == 'subgroup':
                    cmd = f"--groups={self.ad_sub_group}"
                result = self.master.run_command(
                    ["ipa", "hbacrule-add-user", hrule, cmd],
                    raiseonerr=False
                )
                output = f"{result.stdout_text}{result.stderr_text}"
                assert result.returncode != 0
                assert "no such entry" in output
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['--users=admin', '--groups=admins'])
    def test_ipa_trust_func_hbac_0002(self, arg):
        """
        Test HBAC rule denies SSH access for AD users.

        This test creates an HBAC rule that allows SSH access only for admin
        users/groups, then verifies that AD users from the trusted domain are
        denied access. The test confirms that the denial is logged with
        "Access denied by HBAC rules" message.
        """
        logsize = tasks.get_logsize(
            self.clients[0], self.log_file
        )
        hrule = "hbacrule_hbac_0002"
        tasks.kinit_admin(self.master)
        try:
            self._add_hbacrule_with_service(hrule, 'sshd')
            self.master.run_command(
                ["ipa", "hbacrule-add-user", hrule, arg]
            )
            self._disable_allow_all_and_wait()
            for user in [self.aduser, self.subaduser]:
                self._ssh_with_password(
                    user,
                    self.clients[0].hostname,
                    'Secret123',
                    success_expected=False,
                )
                sssd_logs = self._get_log_tail(
                    self.clients[0], self.log_file, logsize
                )
                assert b"Access denied by HBAC rules" in sssd_logs
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['user', 'subuser'])
    def test_ipa_trust_func_hbac_0005(self, arg):
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
            if arg == 'user':
                user = self.aduser
            elif arg == 'subuser':
                user = self.subaduser

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

            for user2 in [self.aduser2, self.subaduser]:
                self._ssh_with_password(
                    user2,
                    self.clients[0].hostname,
                    'Secret123',
                    success_expected=False,
                )
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['user', 'subuser'])
    def test_ipa_trust_func_hbac_0008(self, arg):
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
            start_time = time.strftime('%Y-%m-%d %H:%M:%S')
            self._add_hbacrule_with_service(hrule, 'sudo')
            self.master.run_command(
                ["ipa", "hbacrule-add-user", hrule, "--users=admin"]
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
                ]
            )
            tasks.clear_sssd_cache(self.clients[0])
            self._disable_allow_all_and_wait()
            tasks.kdestroy_all(self.clients[0])
            if arg == 'user':
                user = self.aduser
            elif arg == 'subuser':
                user = self.subaduser

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
            cmd = ["journalctl", f"--since={start_time}"]
            result = self.clients[0].run_command(cmd)
            assert (
                f"{user} : user NOT authorized on host" in result.stdout_text
            )
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)
            self.master.run_command(["ipa", "sudorule-del", srule])

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['user', 'subuser'])
    def test_ipa_trust_func_hbac_0010(self, arg):
        """
        Test HBAC rule denies sudo access for AD users not in allowed groups.

        This test creates an HBAC rule for sudo service that only allows
        admin users, and a sudo rule that allows admins group members to
        run all commands. It verifies that AD users are denied sudo access
        due to HBAC restrictions, with the denial being logged as
        "user NOT authorized on host".
        """
        hrule = "ipa_trust_func_hbac_0010"
        srule = "ipa_trust_func_hbac_0010"
        tasks.kinit_admin(self.master)
        try:
            start_time = time.strftime('%Y-%m-%d %H:%M:%S')
            self._add_hbacrule_with_service(hrule, 'sudo')
            self.master.run_command(
                ["ipa", "hbacrule-add-user", hrule, "--users=admin"]
            )
            tasks.clear_sssd_cache(self.clients[0])
            self._disable_allow_all_and_wait()
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
                    "--groups=admins",
                ]
            )
            tasks.kdestroy_all(self.clients[0])
            if arg == 'user':
                user = self.aduser2
            elif arg == 'subuser':
                user = self.subaduser

            test_sudo = "su {0} -c 'sudo -S id'".format(user)
            self.clients[0].run_command(
                test_sudo,
                stdin_text='Secret123',
                raiseonerr=False
            )
            time.sleep(30)
            cmd = ["journalctl", f"--since={start_time}"]
            result = self.clients[0].run_command(cmd)
            assert (
                f"{user} : user NOT authorized on host" in result.stdout_text
            )
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)
            self.master.run_command(["ipa", "sudorule-del", srule])

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['user', 'subuser'])
    def test_ipa_trust_func_hbac_0011(self, arg):
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
            if arg == 'user':
                user = self.aduser
            elif arg == 'subuser':
                user = self.subaduser

            test_sudo = "su {0} -c 'sudo -S id'".format(user)
            with self.clients[0].spawn_expect(test_sudo) as e:
                e.sendline('Secret123')
                e.expect_exit(ignore_remaining_output=True, timeout=60)
                output = e.get_last_output()
            assert 'uid=0(root)' in output
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)
            self.master.run_command(["ipa", "sudorule-del", srule])

    @skip_if_fips()
    @pytest.mark.parametrize('arg', ['user', 'subuser'])
    def test_ipa_trust_func_hbac_0012(self, arg):
        """
        Test HBAC rule denies sudo access for AD users not in allowed external
        group.

        This test creates an HBAC rule for sudo service that allows members of
        the hbacgroup, and a sudo rule that allows hbacgroup members to run
        all commands. It then verifies that AD users who are NOT members of the
        external group (specifically aduser2/subaduser) are denied sudo access
        due to HBAC restrictions, with the denial being logged as
        "user NOT authorized on host".
        """
        hrule = "ipa_trust_func_hbac_0012"
        srule = "ipa_trust_func_hbac_0012"
        tasks.kinit_admin(self.master)
        try:
            start_time = time.strftime('%Y-%m-%d %H:%M:%S')
            self._add_hbacrule_with_service(hrule, 'sudo')
            self.master.run_command(
                [
                    "ipa",
                    "hbacrule-add-user",
                    hrule,
                    "--groups=hbacgroup",
                ]
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
                    "--groups=hbacgroup",
                ]
            )
            tasks.clear_sssd_cache(self.clients[0])
            self._disable_allow_all_and_wait()
            tasks.kdestroy_all(self.clients[0])
            if arg == 'user':
                user = self.aduser2
            elif arg == 'subuser':
                user = self.subaduser2

            test_sudo = "su {0} -c 'sudo -S id'".format(user)
            self.clients[0].run_command(
                test_sudo,
                stdin_text='Secret123',
                raiseonerr=False
            )
            cmd = ["journalctl", f"--since={start_time}"]
            result = self.clients[0].run_command(cmd)
            assert (
                f"{user} : user NOT authorized on host" in result.stdout_text
            )
        finally:
            self._cleanup_hrule_allow_all_and_wait(hrule)
            self.master.run_command(["ipa", "sudorule-del", srule])
