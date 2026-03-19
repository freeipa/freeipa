# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import textwrap
import time

import pytest
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_trust import BaseTestTrust

AD_PASSWORD = 'Secret123'

AUTOMOUNT_LOCATION = 'trust_location'
AUTOMOUNT_INDIRECT_MAP = 'auto.share'
AUTOMOUNT_INDIRECT_MOUNTPOINT = '/automnt.d'
EXPORT_RW_DIR = '/export'

WAIT_AFTER_AUTOMOUNT_LOCATION = 5


def run_as_ad_user(host, user, domain, command, **kwargs):
    """Run a shell command on host as user@domain via su -l."""
    return tasks.run_command_as_user(
        host, f'{user}@{domain}', command, **kwargs
    )


def kinit_ad_user(host, user, domain, realm, password=AD_PASSWORD):
    """Obtain a Kerberos ticket for an AD user via su -l."""
    run_as_ad_user(
        host, user, domain,
        f'echo {password} | kinit {user}@{realm}'
    )


def umount_and_restart_autofs(host, mountpoint):
    """Unmount a stale NFS mount and restart autofs."""
    host.run_command(['umount', mountpoint], raiseonerr=False)
    host.run_command(['systemctl', 'restart', 'autofs'])


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


class TestTrustFunctionalAutomount(BaseTestTrust):
    """Tests for NFS automount access by AD trusted users.

    Verifies that AD trusted users (from both a top-level AD domain
    and a child subdomain) can access Kerberized NFS mounts configured
    via IPA automount. Covers allow/deny scenarios for read-only and
    read-write NFS exports and ownership-based access control.

    NFS is set up once in install() for all domains. Each test method
    iterates over both root and subdomain users.
    """

    topology = 'line'
    num_ad_treedomains = 0

    @classmethod
    def install(cls, mh):
        super(TestTrustFunctionalAutomount, cls).install(mh)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.clear_sssd_cache(cls.master)

        cls.nfs_configs = [
            (cls.ad_domain, cls.ad_domain.upper(),
             'testuser', 'nonposixuser'),
        ]
        if cls.num_ad_subdomains > 0:
            cls.nfs_configs.append(
                (cls.ad_subdomain, cls.ad_subdomain.upper(),
                 'subdomaintestuser', 'subdomaintestuser'))

        cls._setup_nfs_automount()

    @classmethod
    def uninstall(cls, mh):
        tasks.kinit_admin(cls.master, raiseonerr=False)
        cls.master.run_command(
            ['ipa', 'automountlocation-del', AUTOMOUNT_LOCATION],
            raiseonerr=False)
        cls.master.run_command(
            ['rm', '-rf', EXPORT_RW_DIR, '/export2'],
            raiseonerr=False)
        cls.clients[0].run_command(
            ['ipa-client-automount', '--uninstall', '-U'],
            raiseonerr=False)
        cls.master.run_command(
            ['systemctl', 'stop', 'nfs-server'], raiseonerr=False)
        cls.master.run_command(
            ['systemctl', 'stop', 'rpc-gssd.service'],
            raiseonerr=False)
        cls.master.run_command(
            ['systemctl', 'restart', 'gssproxy'], raiseonerr=False)
        tasks.clear_sssd_cache(cls.master)
        tasks.unconfigure_dns_for_trust(cls.master, cls.ad)
        super(TestTrustFunctionalAutomount, cls).uninstall(mh)

    @classmethod
    def _setup_nfs_automount(cls):
        """Set up NFS server and automount for all configured domains."""
        master = cls.master
        client = cls.clients[0]

        tasks.install_packages(master, ['gssproxy'])
        tasks.kinit_admin(master)

        nfs_principal = f'nfs/{master.hostname}'
        result = master.run_command(
            ['ipa', 'service-show', nfs_principal], raiseonerr=False)
        if result.returncode != 0:
            master.run_command(['ipa', 'service-add', nfs_principal])

        result = master.run_command(
            ['klist', '-ket', '/etc/krb5.keytab'], raiseonerr=False)
        if nfs_principal not in result.stdout_text:
            master.run_command([
                'ipa-getkeytab', '-k', '/etc/krb5.keytab',
                '-s', master.hostname, '-p', nfs_principal
            ])

        nfs_sysconfig = '/etc/sysconfig/nfs'
        try:
            content = master.get_file_contents(
                nfs_sysconfig, encoding='utf-8')
        except Exception:
            content = ''
        master.put_file_contents(
            nfs_sysconfig, content + 'SECURE_NFS="yes"\n')

        exports_content = '/export  *(rw,sec=krb5:krb5i:krb5p)\n'

        for domain, _realm, user1, user2 in cls.nfs_configs:
            ad_user1 = f'{user1}@{domain}'
            ad_user2 = f'{user2}@{domain}'
            export_ro_dir = f'/export2/{user2}'

            # RW export directory for user1
            master.run_command(
                ['mkdir', '-p', f'/export/{user1}'])
            master.run_command(
                ['chmod', '770', f'/export/{user1}'])
            master.run_command(
                ['chown', f'{ad_user1}:{ad_user1}',
                 f'/export/{user1}'])
            master.put_file_contents(
                f'/export/{user1}/rw_test', 'Read-Write-Test\n')
            master.run_command(
                ['chown', f'{ad_user1}:{ad_user1}',
                 f'/export/{user1}/rw_test'])
            master.run_command(
                ['chmod', '664', f'/export/{user1}/rw_test'])

            # RO export directory for user2
            master.run_command(['mkdir', '-p', export_ro_dir])
            master.run_command(['chmod', '770', export_ro_dir])
            master.run_command(
                ['chown', f'{ad_user2}:{ad_user2}', export_ro_dir])
            master.put_file_contents(
                f'{export_ro_dir}/ro_test', 'Read-Only-Test\n')
            master.run_command(
                ['chown', f'{ad_user2}:{ad_user2}',
                 f'{export_ro_dir}/ro_test'])
            master.run_command(
                ['chmod', '664', f'{export_ro_dir}/ro_test'])

            exports_content += (
                f'{export_ro_dir}  *(ro,sec=krb5:krb5i:krb5p)\n')

        master.put_file_contents('/etc/exports', exports_content)

        master.run_command(['systemctl', 'restart', 'nfs-server'])
        master.run_command(['systemctl', 'restart', 'rpc-gssd.service'])
        master.run_command(['systemctl', 'restart', 'gssproxy'])
        master.run_command(['exportfs', '-a'])

        # IPA automount location and maps
        master.run_command(
            ['ipa', 'automountlocation-add', AUTOMOUNT_LOCATION])
        master.run_command([
            'ipa', 'automountmap-add-indirect', AUTOMOUNT_LOCATION,
            AUTOMOUNT_INDIRECT_MAP,
            f'--mount={AUTOMOUNT_INDIRECT_MOUNTPOINT}',
            '--parentmap=auto.master'
        ])
        master.run_command([
            'ipa', 'automountkey-add', AUTOMOUNT_LOCATION,
            AUTOMOUNT_INDIRECT_MAP,
            '--key=*',
            f'--info=-rw,soft,fstype=nfs4,sec=krb5 '
            f'{master.hostname}:{EXPORT_RW_DIR}/&'
        ])
        for _domain, _realm, _user1, user2 in cls.nfs_configs:
            export_ro_dir = f'/export2/{user2}'
            automount_direct_key = f'/automnt2.d/{user2}'
            master.run_command([
                'ipa', 'automountkey-add', AUTOMOUNT_LOCATION,
                'auto.direct',
                f'--key={automount_direct_key}',
                f'--info=-rw,fstype=nfs4,sec=krb5 '
                f'{master.hostname}:{export_ro_dir}'
            ])

        time.sleep(WAIT_AFTER_AUTOMOUNT_LOCATION)

        client.run_command([
            'ipa-client-automount',
            f'--server={master.hostname}',
            f'--location={AUTOMOUNT_LOCATION}', '-U'
        ])

    def test_bug_1028422_automount_default_domain_suffix(self):
        """SSSD retrieves auto.master with default_domain_suffix.

        Regression test for
        https://bugzilla.redhat.com/show_bug.cgi?id=1028422
        and https://bugzilla.redhat.com/show_bug.cgi?id=1036157.
        """
        master = self.master
        client = self.clients[0]

        result = master.run_command(['ipa', 'trust-find'])
        assert self.ad_domain in result.stdout_text

        tasks.clear_sssd_cache(master)
        tasks.wait_for_sssd_domain_status_online(master)

        tasks.clear_sssd_cache(client)
        tasks.wait_for_sssd_domain_status_online(client)

        client.run_command(
            ['getent', 'passwd', f'testuser@{self.ad_domain}'])

        with tasks.FileBackup(client, paths.SSSD_CONF), \
             tasks.FileBackup(client, paths.NSSWITCH_CONF):
            # default_domain_suffix allows AD users to authenticate
            # using short names (e.g. 'testuser') without the @domain
            client.run_command([
                'sed', '-i',
                f'/\\[sssd\\]/ a default_domain_suffix = '
                f'{self.ad_domain}',
                paths.SSSD_CONF
            ])
            client.run_command([
                'sed', '-i', 's/services.*/&, autofs/g',
                paths.SSSD_CONF
            ])
            client.run_command([
                'sed', '-i',
                's/automount:.*/automount:  sss files/',
                paths.NSSWITCH_CONF
            ])
            client.run_command(
                ['authselect', 'apply-changes'],
                raiseonerr=False)

            # Enable autofs debug logging in sssd
            client.run_command([
                'sh', '-c',
                f'grep -q "\\[autofs\\]" {paths.SSSD_CONF} || '
                f'printf "\\n[autofs]\\n" >> {paths.SSSD_CONF}'
            ])
            client.run_command([
                'sed', '-i',
                '/\\[autofs\\]/a\\debug_level = 10',
                paths.SSSD_CONF
            ])

            result = client.run_command(
                ['grep', '-A3', '\\[sssd\\]', paths.SSSD_CONF])
            assert 'default_domain_suffix' in result.stdout_text

            tasks.clear_sssd_cache(client)
            tasks.wait_for_sssd_domain_status_online(client)
            client.run_command(['systemctl', 'restart', 'autofs'])

            client.run_command(['getent', 'passwd', 'testuser'])

            result = client.run_command(['automount', '-m'])
            assert ('setautomntent: lookup(sss): setautomntent: '
                    'No such file or directory'
                    not in result.stdout_text)
            assert 'autofs dump map information' in result.stdout_text
            assert 'Mount point: /-' in result.stdout_text

            log_result = client.run_command(
                ['cat', '/var/log/sssd/sssd_autofs.log'])
            assert 'failed' not in log_result.stdout_text.lower()

        client.run_command(
            ['authselect', 'apply-changes'], raiseonerr=False)
        client.run_command(['systemctl', 'restart', 'sssd'])
        client.run_command(['systemctl', 'restart', 'autofs'])

    def test_allow_ad_user_nfs_mount(self):
        """AD user with valid Kerberos ticket can write/read NFS."""
        client = self.clients[0]
        master = self.master
        for domain, realm, user1, _user2 in self.nfs_configs:
            marker = f'mytest.{user1}'

            client.run_command(
                ['umount',
                 f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}'],
                raiseonerr=False)

            kinit_ad_user(client, user1, domain, realm)

            run_as_ad_user(
                client, user1, domain,
                f'cd {AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1};'
                f' ls -ltra')

            run_as_ad_user(
                client, user1, domain,
                f'echo {marker} > '
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}/tfile')

            result = run_as_ad_user(
                client, user1, domain,
                f'cat '
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}/tfile')
            assert marker in result.stdout_text

            result = master.run_command(
                ['cat', f'/export/{user1}/tfile'])
            assert marker in result.stdout_text

    def test_deny_ad_user_nfs_mount_no_ticket(self):
        """AD user without Kerberos ticket is denied NFS access."""
        client = self.clients[0]
        for domain, _realm, user1, user2 in self.nfs_configs:
            automount_direct_key = f'/automnt2.d/{user2}'
            export_ro_dir = f'/export2/{user2}'

            umount_and_restart_autofs(client, automount_direct_key)

            run_as_ad_user(client, user1, domain, 'kdestroy -A')

            result = run_as_ad_user(
                client, user1, domain,
                f'cd {automount_direct_key}',
                raiseonerr=False)
            assert result.returncode != 0
            output = result.stdout_text + result.stderr_text
            assert 'Permission denied' in output

            result = client.run_command(['mount'])
            assert (f'{self.master.hostname}:{export_ro_dir}'
                    in result.stdout_text)

    def test_allow_ad_user_read_ro_nfs(self):
        """AD user can read files on read-only NFS mount."""
        client = self.clients[0]
        for domain, realm, _user1, user2 in self.nfs_configs:
            automount_direct_key = f'/automnt2.d/{user2}'

            umount_and_restart_autofs(client, automount_direct_key)

            kinit_ad_user(client, user2, domain, realm)

            result = run_as_ad_user(
                client, user2, domain,
                f'cat {automount_direct_key}/ro_test')
            assert 'Read-Only-Test' in result.stdout_text

    def test_deny_ad_user_write_ro_nfs(self):
        """AD user cannot write to read-only NFS mount."""
        client = self.clients[0]
        for domain, realm, _user1, user2 in self.nfs_configs:
            automount_direct_key = f'/automnt2.d/{user2}'

            umount_and_restart_autofs(client, automount_direct_key)

            kinit_ad_user(client, user2, domain, realm)

            result = run_as_ad_user(
                client, user2, domain,
                f'date >> {automount_direct_key}/ro_test',
                raiseonerr=False)
            assert result.returncode != 0
            output = result.stdout_text + result.stderr_text
            assert 'Read-only file system' in output

    def test_allow_ad_user_read_rw_nfs(self):
        """AD user can read files on read-write NFS mount."""
        client = self.clients[0]
        for domain, realm, user1, _user2 in self.nfs_configs:
            umount_and_restart_autofs(
                client,
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}')

            kinit_ad_user(client, user1, domain, realm)

            result = run_as_ad_user(
                client, user1, domain,
                f'cat '
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}/rw_test')
            assert 'Read-Write-Test' in result.stdout_text

    def test_write_rw_nfs_ownership(self):
        """Test ownership-based access control on rw NFS mount.

        For each domain: verifies the owner can write to their own
        directory. When user1 != user2 (top-domain), also verifies
        a different user is denied write access.
        """
        client = self.clients[0]
        for domain, realm, user1, user2 in self.nfs_configs:
            # Owner can write to own directory
            umount_and_restart_autofs(
                client,
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}')

            run_as_ad_user(client, user1, domain, 'kdestroy -A')
            kinit_ad_user(client, user1, domain, realm)

            run_as_ad_user(
                client, user1, domain,
                f'echo New-RW-Test >> '
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}/rw_test')

            result = run_as_ad_user(
                client, user1, domain,
                f'cat '
                f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}/rw_test')
            assert 'New-RW-Test' in result.stdout_text

            # Different user is denied (only when users differ)
            if user1 != user2:
                umount_and_restart_autofs(
                    client,
                    f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}')

                run_as_ad_user(
                    client, user2, domain, 'kdestroy -A')
                kinit_ad_user(client, user2, domain, realm)

                result = run_as_ad_user(
                    client, user2, domain,
                    f'echo Bad-Write >> '
                    f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}'
                    f'/{user1}/rw_test',
                    raiseonerr=False)
                assert result.returncode != 0
                output = result.stdout_text + result.stderr_text
                assert 'Permission denied' in output
