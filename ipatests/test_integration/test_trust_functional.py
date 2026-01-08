# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import textwrap
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
        """Run a sudo command using spawn_expect with proper error handling.

        :param host: Host to run the command on
        :param command: Command to execute
        :param username: Username for password prompt
        :param password: Password to send
        :param expected_output: Expected string in output (for assertion)
        :param raiseonerr: Whether to raise on error
        :param timeout: Timeout for expect_exit
        :returns: Output from the command
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


class TestTrustFunctionalUser(BaseTestTrust):
    """
    Test class for AD user functional tests covering both top domain
    and subdomain users.

    Tests cover: kinit, su, external group membership, home directory
    access, and group membership verification.
    """
    topology = 'line'
    num_ad_treedomains = 0

    @classmethod
    def install(cls, mh):
        super(TestTrustFunctionalUser, cls).install(mh)
        # Set fallback_homedir for AD users without home directory in AD.
        with tasks.remote_sssd_config(cls.master) as sssd_conf:
            sssd_conf.edit_domain(
                cls.master.domain, 'fallback_homedir', '/home/%d/%u')
        tasks.clear_sssd_cache(cls.master)

        # Enable automatic home directory creation for AD users
        # Requires both authselect feature AND oddjobd service running
        for host in [cls.master] + cls.clients:
            host.run_command(
                ['authselect', 'enable-feature', 'with-mkhomedir']
            )
            host.run_command(
                ['systemctl', 'enable', '--now', 'oddjobd']
            )

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
        for user in (self.aduser, self.subaduser):
            username, domain = user.split('@', maxsplit=1)
            for realm in (domain.upper(), domain.lower()):
                tasks.kdestroy_all(self.clients[0])
                tasks.kinit_as_user(
                    self.clients[0], f'{username}@{realm}', 'Secret123'
                )

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
        for domain, username in [
            (self.ad_domain, self.aduser),
            (self.ad_subdomain, self.subaduser)
        ]:
            # Get netbios names from domain (first part uppercase)
            netbios = domain.split('.')[0].upper()
            user = username.split('@', maxsplit=1)[0]
            result = tasks.kinit_as_user(
                self.clients[0], f'{netbios}\\{user}', 'Secret123',
                raiseonerr=False
            )
            assert result.returncode != 0

    def test_kinit_disabled_account(self):
        """
        Test kinit fails for disabled AD accounts.
        Related: BZ1162486, test 0006

        Uses pre-existing disabled users:
        - disabledaduser in forest root
        - subdomaindisabledadu (self.subaduser2) in subdomain
        """
        disabled_users = [
            f"disabledaduser@{self.ad_domain}",
            self.subaduser2,
        ]

        for disabled_user in disabled_users:
            tasks.kdestroy_all(self.clients[0])
            tasks.clear_sssd_cache(self.clients[0])

            result = tasks.kinit_as_user(
                self.clients[0], disabled_user, 'Secret123',
                raiseonerr=False
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert result.returncode != 0, (
                f"kinit should fail for disabled user {disabled_user}"
            )
            assert (
                "credentials have been revoked" in output
                or "locked" in output.lower()
            ), f"Expected 'revoked' or 'locked' in output for {disabled_user}"

    def test_kinit_expired_account(self):
        """
        Test kinit fails for expired AD accounts.
        Related: test 0007
        """
        test_user = "expiredtestuser"
        test_password = "Passw0rd1"

        for ad_host, ad_domain in [
            (self.ad, self.ad_domain),
            (self.child_ad, self.ad_subdomain)
        ]:
            try:
                self._ad_user_add(test_user, "Secret123", ad_host)
                self._ad_user_mod(
                    test_user,
                    ['-pwd', test_password, '-acctexpires', '-1'],
                    ad_host=ad_host
                )

                tasks.kdestroy_all(self.clients[0])
                tasks.clear_sssd_cache(self.clients[0])

                expired_user = f"{test_user}@{ad_domain}"
                result = tasks.kinit_as_user(
                    self.clients[0], expired_user, test_password,
                    raiseonerr=False
                )
                output = f"{result.stdout_text}{result.stderr_text}"
                assert result.returncode != 0, (
                    f"kinit should fail for {ad_domain}"
                )
                assert "credentials have been revoked" in output, (
                    f"Expected 'revoked' or 'expired' in output "
                    f"for {ad_domain}"
                )
            finally:
                self._ad_user_del(test_user, ad_host)

    def test_su_ad_user(self):
        """Test su to AD users from top and sub domains."""
        for user in (self.aduser, self.subaduser):
            username, domain = user.split('@', maxsplit=1)
            for realm in (domain.upper(), domain.lower()):
                result = self.clients[0].run_command(
                    ['su', '-', f'{username}@{realm}', '-c', 'whoami']
                )
                output = result.stdout_text.strip()
                # whoami returns fully qualified name for AD trust users
                assert output == f'{username}@{domain}'

    def test_passwd_change_by_user(self):
        """
        Test AD user can change their own password.
        Related: BZ870238, test 0010 (root) and sub_0010 (child)
        """
        test_user = "passwdtestuser"
        current_password = "Passw0rd1"
        new_password = "Dec3@4smsS3"

        for ad_host, ad_domain in [
            (self.ad, self.ad_domain),
            (self.child_ad, self.ad_subdomain),
        ]:
            try:
                # Set MinPasswordAge to 0 to allow immediate password change
                ad_host.run_command([
                    'powershell', '-c',
                    f'Set-ADDefaultDomainPasswordPolicy '
                    f'-Identity "{ad_domain}" -MinPasswordAge 0'
                ])

                # Create user directly with current_password
                self._ad_user_add(test_user, current_password, ad_host)
                self._ad_user_mod(
                    test_user,
                    ['-pwdneverexpires', 'yes', '-canchpwd', 'yes'],
                    ad_host=ad_host
                )

                tasks.clear_sssd_cache(self.clients[0])
                user_fqdn = f"{test_user}@{ad_domain}"
                self.clients[0].run_command(['id', user_fqdn])

                self._passwd_change_with_retry(
                    user_fqdn, current_password, new_password
                )

                tasks.kdestroy_all(self.clients[0])
                self.clients[0].run_command(
                    ['kinit', user_fqdn], stdin_text=f'{new_password}\n'
                )
            finally:
                self._ad_user_del(test_user, ad_host)
                # Restore MinPasswordAge to 1 day
                ad_host.run_command([
                    'powershell', '-c',
                    f'Set-ADDefaultDomainPasswordPolicy '
                    f'-Identity "{ad_domain}" -MinPasswordAge 1.00:00:00'
                ], raiseonerr=False)

    def test_homedir_access_commands(self):
        """Test home directory access commands for AD users."""
        tasks.clear_sssd_cache(self.clients[0])
        for user in [self.aduser, self.subaduser]:
            username = user.split('@', maxsplit=1)[0]
            domain = user.split('@', maxsplit=1)[1]
            # pwd
            tasks.clear_sssd_cache(self.clients[0])
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

    def test_add_ad_user_to_external_group(self):
        """Test adding AD users to external group."""
        ext_group = "user_ext_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for user in [self.aduser, self.subaduser]:
                tasks.group_add_member(
                    self.master, ext_group,
                    extra_args=['--external', user],
                    noninteractive=True
                )
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert user in result.stdout_text
        finally:
            tasks.group_del(self.master, ext_group)

    def test_remove_ad_user_from_external_group(self):
        """Test removing AD users from external group."""
        ext_group = "user_ext_group_del"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for user in [self.aduser, self.subaduser]:
                tasks.group_add_member(
                    self.master, ext_group,
                    extra_args=['--external', user],
                    noninteractive=True
                )
                self.master.run_command([
                    'ipa', '-n', 'group-remove-member', ext_group,
                    '--external', user
                ])
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert user not in result.stdout_text
        finally:
            tasks.group_del(self.master, ext_group)

    def test_add_ad_group_to_external_group(self):
        """Test adding AD groups to IPA external group."""
        ext_group = "grp_ext_group"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for ad_grp in [self.ad_group, self.ad_sub_group]:
                tasks.group_add_member(
                    self.master, ext_group,
                    extra_args=['--external', ad_grp],
                    noninteractive=True
                )
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert ad_grp in result.stdout_text
        finally:
            tasks.group_del(self.master, ext_group)

    def test_remove_ad_group_from_external_group(self):
        """Test removing AD groups from IPA external group."""
        ext_group = "grp_ext_group_del"
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            for ad_grp in [self.ad_group, self.ad_sub_group]:
                tasks.group_add_member(
                    self.master, ext_group,
                    extra_args=['--external', ad_grp],
                    noninteractive=True
                )
                self.master.run_command([
                    'ipa', '-n', 'group-remove-member', ext_group,
                    '--external', ad_grp
                ])
                result = self.master.run_command(
                    ['ipa', 'group-show', ext_group]
                )
                assert ad_grp not in result.stdout_text
        finally:
            tasks.group_del(self.master, ext_group)

    def test_child_user_in_forest_group(self):
        """
        Test that users appear in their respective domain groups.

        Verifies that SSSD can resolve users and groups from both root domain
        and child domain in a transitive trust.

        testgroup (self.ad_group) contains:
        - testuser (root domain)

        subdomaintestgroup (self.ad_sub_group) contains:
        - subdomaintestuser (self.subaduser)

        Related: BZ1002597, BZ1171382
        """
        tasks.clear_sssd_cache(self.clients[0])
        tasks.wait_for_sssd_domain_status_online(self.clients[0])

        testuser = f"testuser@{self.ad_domain}"

        # SSH with password to resolve users via PAM/SSSD
        for user in [self.subaduser, testuser]:
            tasks.ssh_with_password(
                self.clients[0], self.clients[0].hostname, user, 'Secret123',
                'id'
            )
        # Wait for SSSD to process membership
        time.sleep(10)
        # Resolve both users
        for user in [self.subaduser, testuser]:
            self.clients[0].run_command(['id', user])
        # Wait for group membership resolution
        time.sleep(5)

        # Check root domain: testuser in testgroup
        result = self.clients[0].run_command(
            ['getent', 'group', self.ad_group]
        )
        assert testuser in result.stdout_text, (
            f"Root domain user {testuser} not found in "
            f"group output: {result.stdout_text}"
        )

        # Check child domain: subdomaintestuser in subdomaintestgroup
        result = self.clients[0].run_command(
            ['getent', 'group', self.ad_sub_group]
        )
        assert self.subaduser in result.stdout_text, (
            f"Subdomain user {self.subaduser} not found in "
            f"group output: {result.stdout_text}"
        )

    @pytest.mark.skip(reason="SSSD regression, fix pending: "
                      "https://github.com/SSSD/sssd/pull/8442")
    def test_ad_user_in_posix_group_fully_qualified(self):
        """
        Test that AD users in IPA posix group are shown fully qualified.

        Tests both top domain and subdomain AD users are displayed with
        fully qualified names when added to IPA external/posix groups.

        Related: BZ877126, BZ1171383
        """
        ext_group = "tgroup5_external"
        posix_group = "tgroup5"
        testuser = f"testuser@{self.ad_domain}"
        subadtestuser_name = "subadtestuser"
        test_password = "Secret123"

        # Create subdomain test user
        self._ad_user_add(subadtestuser_name, test_password, self.child_ad)
        subadtestuser = f"{subadtestuser_name}@{self.ad_subdomain}"

        try:
            # Test both top domain and subdomain users
            test_cases = [
                ([self.aduser, testuser], "top domain"),
                ([self.subaduser, subadtestuser], "subdomain"),
            ]

            for users, domain_desc in test_cases:
                tasks.kdestroy_all(self.master)
                tasks.kinit_admin(self.master)
                # Setup on master
                tasks.clear_sssd_cache(self.master)
                for user in users:
                    self.master.run_command(['id', user], raiseonerr=False)

                try:
                    tasks.group_add(
                        self.master, ext_group, extra_args=["--external"]
                    )
                    tasks.group_add(self.master, posix_group)
                    tasks.group_add_member(
                        self.master, posix_group,
                        extra_args=[f'--groups={ext_group}']
                    )
                    for user in users:
                        tasks.group_add_member(
                            self.master, ext_group,
                            extra_args=[f'--external={user}'],
                            noninteractive=True
                        )
                    time.sleep(60)

                    # Test on client
                    tasks.clear_sssd_cache(self.clients[0])
                    tasks.wait_for_sssd_domain_status_online(self.clients[0])
                    # SSH with password to resolve users
                    for user in users:
                        tasks.ssh_with_password(
                            self.clients[0], self.clients[0].hostname,
                            user, test_password, 'id'
                        )
                    # Clear cache again
                    tasks.clear_sssd_cache(self.clients[0])
                    tasks.wait_for_sssd_domain_status_online(self.clients[0])
                    # Resolve users
                    for user in users:
                        self.clients[0].run_command(['id', user])
                    # Check group membership
                    result = self.clients[0].run_command(
                        ['getent', 'group', posix_group]
                    )
                    for user in users:
                        assert user in result.stdout_text, (
                            f"{domain_desc} user {user} not found in "
                            f"group output: {result.stdout_text}"
                        )
                finally:
                    tasks.kdestroy_all(self.master)
                    tasks.kinit_admin(self.master)
                    self.master.run_command(
                        ['ipa', 'group-del', posix_group], raiseonerr=False
                    )
                    self.master.run_command(
                        ['ipa', 'group-del', ext_group], raiseonerr=False
                    )
        finally:
            # Clean up subdomain test user
            self._ad_user_del(subadtestuser_name, self.child_ad)

    def test_ad_user_in_multiple_groups(self):
        """
        Test that AD users appear in multiple AD groups.

        Tests that getent commands display secondary groups for trusted AD
        users from both top domain and subdomain. Each user should belong
        to groups from their own domain.

        Related: BZ878583
        """
        # AD users and groups (from AD config)
        ad_user = 'testuser'
        ad_primary_group = 'testgroup'
        ad_secondary_group = 'testgroup1'

        child_user = 'subdomaintestuser'
        child_primary_group = 'subdomaintestgroup'
        child_secondary_group = 'subdomaintestgroup1'

        # Secondary groups to ensure exist with their users
        secondary_groups = [
            (self.ad, ad_secondary_group, ad_user),
            (self.child_ad, child_secondary_group, child_user),
        ]
        groups_created = []

        try:
            for ad_host, group, user in secondary_groups:
                created = self._ensure_ad_group_member(ad_host, group, user)
                if created:
                    groups_created.append(created)

            tasks.clear_sssd_cache(self.clients[0])

            # Test cases: (user, domain, expected_groups)
            test_cases = [
                (
                    ad_user,
                    self.ad_domain,
                    [ad_primary_group, ad_secondary_group]
                ),
                (
                    child_user,
                    self.ad_subdomain,
                    [child_primary_group, child_secondary_group]
                ),
            ]

            for user, domain, expected_groups in test_cases:
                user_fqdn = f'{user}@{domain}'
                tasks.ssh_with_password(
                    self.clients[0], self.clients[0].hostname,
                    user_fqdn, 'Secret123', 'id'
                )
                time.sleep(10)

                for group in expected_groups:
                    group_fqdn = f'{group}@{domain}'
                    result = self.clients[0].run_command(
                        ['getent', 'group', group_fqdn]
                    )
                    assert user_fqdn in result.stdout_text, (
                        f"User {user_fqdn} not found in group {group_fqdn}"
                    )
        finally:
            for ad_host, group in groups_created:
                self._ad_group_del(group, ad_host=ad_host)

    def test_group_find_external(self):
        """
        Test group-find with --external option.

        Tests that group-find command has option for filtering
        groups by type (external).

        Related: BZ952754
        """
        ext_group = "tgroup100_ext"
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(
                self.master, ext_group, extra_args=["--external"]
            )
            result = self.master.run_command(
                ['ipa', 'group-find', '--external']
            )
            assert ext_group in result.stdout_text, (
                f"Group {ext_group} not found in group-find --external output"
            )
        finally:
            self.master.run_command(
                ['ipa', 'group-del', ext_group], raiseonerr=False
            )

    def test_group_find_posix(self):
        """
        Test group-find with --posix option.

        Tests that group-find command has option for filtering
        groups by type (posix).

        Related: BZ952754
        """
        posix_group = "tgroup100_posix"
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        try:
            tasks.group_add(self.master, posix_group)
            result = self.master.run_command(
                ['ipa', 'group-find', '--posix']
            )
            assert posix_group in result.stdout_text, (
                f"Group {posix_group} not found in group-find --posix output"
            )
        finally:
            self.master.run_command(
                ['ipa', 'group-del', posix_group], raiseonerr=False
            )

    def test_passwd_change_by_root_not_supported(self):
        """
        Test that password change by root for AD users is not supported.

        Related: BZ870238
        """
        # Check if sss is the first provider in nsswitch.conf for passwd
        # If sss is not first, SSSD is not reached and test is meaningless
        result = self.clients[0].run_command(
            ['grep', '^passwd:', '/etc/nsswitch.conf']
        )
        passwd_line = result.stdout_text.strip()
        # Extract providers after 'passwd:' and check if sss is first
        if ':' in passwd_line:
            providers = passwd_line.split(':')[1].split()
        else:
            providers = []
        if not providers or providers[0] != 'sss':
            pytest.skip("sss is not the first provider in nsswitch.conf")

        for user in [self.aduser, self.subaduser]:
            # Ensure user is resolved in SSSD first
            self.clients[0].run_command(['id', user])
            result = self.clients[0].run_command(
                ['passwd', user], raiseonerr=False
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert (
                "Password reset by root is not supported" in output
            )

    def test_external_group_getgrnam_getgrgid(self):
        """
        Test external groups work with getgrnam/getgrgid in server mode.

        Creates an external group with AD group as member, then creates
        posix groups that include the external group. Verifies that AD
        users appear correctly in both posix groups via id and getent.

        Related: BZ1162486
        """
        ext_group = "bz1162486_external"
        posix_group1 = "bz1162486_1"
        posix_group2 = "bz1162486_2"
        testuser = f"testuser@{self.ad_domain}"
        ad_group = f"domain users@{self.ad_domain}"

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        # Clear SSSD cache on master first (as in bash test)
        tasks.clear_sssd_cache(self.master)

        try:
            # Create external group and posix groups
            tasks.group_add(
                self.master, ext_group, extra_args=['--desc=0', '--external']
            )
            tasks.group_add(self.master, posix_group1, extra_args=['--desc=0'])
            tasks.group_add(self.master, posix_group2, extra_args=['--desc=0'])
            # Add external group as member of posix groups
            tasks.group_add_member(
                self.master, posix_group1, extra_args=[f'--groups={ext_group}']
            )
            tasks.group_add_member(
                self.master, posix_group2, extra_args=[f'--groups={ext_group}']
            )
            # Add AD group as external member
            tasks.group_add_member(
                self.master, ext_group,
                extra_args=[f'--external={ad_group}'],
                noninteractive=True
            )

            # Show groups to verify setup (as in bash test)
            self.master.run_command(['ipa', 'group-show', ext_group])
            self.master.run_command(['ipa', 'group-show', posix_group1])
            self.master.run_command(['ipa', 'group-show', posix_group2])
            time.sleep(5)

            # Clear SSSD cache on client and wait for SSSD to come online
            tasks.clear_sssd_cache(self.clients[0])
            tasks.wait_for_sssd_domain_status_online(self.clients[0])

            # Retry loop: wait up to 120 seconds for user to be resolvable
            for _retry in range(12):
                result = self.clients[0].run_command(
                    ['id', testuser], raiseonerr=False
                )
                if result.returncode == 0:
                    break
                time.sleep(10)

            # Check user appears in both posix groups via id
            result = self.clients[0].run_command(['id', testuser])
            assert posix_group1 in result.stdout_text, (
                f"Group {posix_group1} not in id output: {result.stdout_text}"
            )
            assert posix_group2 in result.stdout_text, (
                f"Group {posix_group2} not in id output: {result.stdout_text}"
            )
            assert "domain users" in result.stdout_text, (
                f"domain users not in id output: {result.stdout_text}"
            )

            # Check getent group shows the user
            for grp in [posix_group1, posix_group2]:
                result = self.clients[0].run_command(['getent', 'group', grp])
                assert testuser in result.stdout_text, (
                    f"User {testuser} not in getent group {grp}: "
                    f"{result.stdout_text}"
                )

            # Verify again after brief wait (as in bash test)
            time.sleep(5)
            for grp in [posix_group1, posix_group2]:
                self.clients[0].run_command(['getent', 'group', grp])
            time.sleep(5)
            result = self.clients[0].run_command(['id', testuser])
            assert posix_group1 in result.stdout_text
            assert posix_group2 in result.stdout_text
            assert "domain users" in result.stdout_text

        finally:
            tasks.kinit_admin(self.master)
            for grp in [posix_group1, posix_group2, ext_group]:
                self.master.run_command(
                    ['ipa', 'group-del', grp], raiseonerr=False
                )

    def test_sid_resolution_uncached(self):
        """
        Test SID resolution for users/groups not in cache.

        Verifies that SIDs can be resolved to names even when the
        user or group is not yet cached in SSSD.

        Related: BZ1185188
        """
        # Install required package for SID resolution
        tasks.install_packages(self.clients[0], ['python3-libsss_nss_idmap'])

        testuser = f"testuser@{self.ad_domain}"
        testgroup = f"testgroup@{self.ad_domain}"

        # Get SIDs for user and group
        # getsidbyname returns dict like {'u': {'sid': 'S-1-...', 'type': N}}
        # We need to extract just the SID string
        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"d = pysss_nss_idmap.getsidbyname('{testuser}'); "
            f"print(d['{testuser}']['sid'])"
        ])
        user_sid = result.stdout_text.strip()

        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"d = pysss_nss_idmap.getsidbyname('{testgroup}'); "
            f"print(d['{testgroup}']['sid'])"
        ])
        group_sid = result.stdout_text.strip()

        # Clear SSSD cache
        tasks.clear_sssd_cache(self.clients[0])
        tasks.wait_for_sssd_domain_status_online(self.clients[0])

        # Resolve SIDs back to names
        # getnamebysid returns dict like {'S-1-...': {'name': 'u', 'type': N}}
        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"print(pysss_nss_idmap.getnamebysid('{user_sid}'))"
        ], raiseonerr=False)
        assert testuser in result.stdout_text, (
            f"User {testuser} not resolved from SID: {result.stdout_text}"
        )

        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"print(pysss_nss_idmap.getnamebysid('{group_sid}'))"
        ], raiseonerr=False)
        assert testgroup in result.stdout_text, (
            f"Group {testgroup} not resolved from SID: {result.stdout_text}"
        )

    def test_initgroups_unauthenticated_ad_users(self):
        """
        Test initgroups for unauthenticated AD users.

        Verifies that all AD user group memberships are shown without
        requiring authentication first.

        Related: BZ1030699, BZ1168378
        """
        ext_group = "bz1030699_external"
        posix_group = "bz1030699"
        testuser = f"testuser@{self.ad_domain}"

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        try:
            # Create external group and posix group
            tasks.group_add(
                self.master, ext_group, extra_args=['--desc=0', '--external']
            )
            tasks.group_add(self.master, posix_group, extra_args=['--desc=0'])
            # Add external group as member of posix group
            tasks.group_add_member(
                self.master, posix_group, extra_args=[f'--groups={ext_group}']
            )
            # Add AD user as external member
            tasks.group_add_member(
                self.master, ext_group,
                extra_args=[f'--external={testuser}'],
                noninteractive=True
            )

            # Clear SSSD cache on master
            tasks.clear_sssd_cache(self.master)
            tasks.wait_for_sssd_domain_status_online(self.master)

            # Check on master without prior authentication
            result = self.master.run_command(['id', testuser])
            assert posix_group in result.stdout_text, (
                f"Group {posix_group} not in id output: {result.stdout_text}"
            )
            assert "domain users" in result.stdout_text, (
                f"domain users not in id output: {result.stdout_text}"
            )

            # Clear SSSD cache on client
            tasks.clear_sssd_cache(self.clients[0])
            tasks.wait_for_sssd_domain_status_online(self.clients[0])

            # Check on client without prior authentication
            result = self.clients[0].run_command(['id', testuser])
            assert posix_group in result.stdout_text, (
                f"Group {posix_group} not in id output: {result.stdout_text}"
            )
            assert "domain users" in result.stdout_text, (
                f"domain users not in id output: {result.stdout_text}"
            )

        finally:
            tasks.kinit_admin(self.master)
            for grp in [posix_group, ext_group]:
                self.master.run_command(
                    ['ipa', 'group-del', grp], raiseonerr=False
                )

    def test_group_memberships_resolve_ad_users(self):
        """
        Test group memberships resolve for AD users from top and subdomain.

        Verifies that group memberships resolve correctly for AD users
        when using SSSD client in combination with IPA server with AD trust.

        Related: BZ1280207
        """
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

        # Test cases: user and expected group
        test_cases = [
            (f"testuser@{self.ad_domain}", f"testgroup@{self.ad_domain}"),
            (f"subdomaintestuser@{self.ad_subdomain}",
             f"subdomaintestgroup@{self.ad_subdomain}"),
        ]

        for user, expected_group in test_cases:
            result = self.clients[0].run_command(['id', user])
            assert expected_group in result.stdout_text, (
                f"Group {expected_group} not found for user {user}: "
                f"{result.stdout_text}"
            )
