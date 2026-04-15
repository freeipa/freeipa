# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import time
import textwrap
from datetime import datetime, timedelta

import pytest
from packaging.version import parse as parse_version

from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_trust import BaseTestTrust
from ipatests.util import xfail_context

PLUGIN_CONF = "/var/lib/sss/pubconf/krb5.include.d/localauth_plugin"


def xfail_fedora_sssd_before_2_12(host):
    """Return ``xfail_context`` for Fedora when SSSD is older than 2.12.0.

    Several trust sudo/HBAC checks are known to fail on Fedora until SSSD
    2.12.0+; callers wrap the affected assertions in this context manager.
    """
    sssd_version = tasks.get_sssd_version(host)
    condition = (
            osinfo.id == 'fedora'
            and sssd_version < parse_version('2.12.0')
    )
    return xfail_context(condition, reason="Fix available on 2.12.0+")


def ssh_with_password(host, login, target_host, password, expect_success=True):
    """Run SSH with password authentication.

    :param host: Host on which to run the SSH command.
    :param login: SSH login name (``-l`` argument).
    :param target_host: Hostname to connect to.
    :param password: Password for authentication.
    :param expect_success: If ``True``, raise on failure; if ``False``, return
        the result object even when the command fails.
    :returns: Object returned by ``host.run_command()``.
    """
    if not tasks.is_package_installed(host, 'sshpass'):
        pytest.skip(f"sshpass not available on {host.hostname}")
    result = host.run_command(
        [
            'sshpass', '-p', password,
            'ssh', '-o', 'StrictHostKeyChecking=no',
            "-o", "PubkeyAuthentication=no",
            "-o", "GSSAPIAuthentication=no",
            '-l', login, target_host, 'id'
        ],
        raiseonerr=expect_success,
    )
    return result


def ssh_with_gssapi(host, kinit_principal, login, target_host, password,
                    expect_success=True):
    """Run SSH with GSSAPI authentication after kinit.

    :param host: Host on which to run ``kinit`` and SSH.
    :param kinit_principal: Kerberos principal for ``kinit``.
    :param login: SSH login name (``-l`` argument).
    :param target_host: Hostname to connect to.
    :param password: Password for ``kinit``.
    :param expect_success: If ``True``, raise on failure; if ``False``, return
        the result object even when the command fails.
    :returns: Object returned by ``host.run_command()``.
    """
    tasks.kdestroy_all(host)
    tasks.kinit_as_user(host, kinit_principal, password)
    result = host.run_command(
        [
            'ssh', '-o', 'StrictHostKeyChecking=no', '-K',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'GSSAPIAuthentication=yes',
            '-l', login, target_host, 'id'
        ],
        raiseonerr=expect_success,
    )
    return result


def spawn_ssh_interactive(host, login, target_host, extra_ssh_options=None,
                          remote_cmd=None):
    """Return a ``spawn_expect`` context for an interactive SSH session.

    :param host: Host on which to run SSH.
    :param login: SSH login name (``-l`` argument).
    :param target_host: Hostname to connect to.
    :param extra_ssh_options: Extra SSH options (e.g. ``['-tt']`` for a PTY),
        or ``None``.
    :param remote_cmd: Optional remote command string, or ``None`` for an
        interactive shell.
    :returns: Context manager from ``host.spawn_expect()``.
    """
    cmd = [
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-l', login, target_host,
    ]
    if remote_cmd is not None:
        cmd.append(remote_cmd)
    return host.spawn_expect(cmd, extra_ssh_options=extra_ssh_options)


def expect_password_change_prompts(test, current_password, new_password):
    """Drive the current->new->confirm password-change prompt sequence.

    Handles the three-step interactive password-change dialogue that
    both SSH forced-change and ``passwd`` in-session flows share.

    :param test: Active ``spawn_expect`` context.
    :param current_password: User's current password.
    :param new_password: New password to set.
    """
    # (?i) ignores case, enabling flag this way is atypical.
    test.expect(r'(?i)current password:')
    test.sendline(current_password)
    test.expect(r'(?i).*password.*:')
    test.sendline(new_password)
    test.expect(r'(?i).*password.*:')
    test.sendline(new_password)


def get_localauth_module_from_plugin(host):
    """Extract module path from SSSD localauth plugin config on the given host.

    :param host: Host from which to read the plugin config at path
        ``PLUGIN_CONF``.
    :returns: Module path from the ``module:`` line in the config file.
    :rtype: str
    :raises ValueError: If no ``module`` line is found in the plugin config.
    """
    plugin_content = host.get_file_contents(PLUGIN_CONF, encoding='utf-8')
    for line in plugin_content.splitlines():
        if line.strip().startswith('module'):
            return line.split(':', 1)[-1].strip()
    raise ValueError("No 'module' line found in localauth plugin config")


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
                ssh_with_password(
                    self.clients[0],
                    user,
                    self.clients[0].hostname,
                    'Secret123',
                    expect_success=False,
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
                output = ssh_with_password(
                    self.clients[0],
                    user,
                    self.clients[0].hostname,
                    'Secret123',
                    expect_success=True,
                )
                assert "domain users" in output.stdout_text

            for user2 in [self.testuser, self.subaduser2]:
                output2 = ssh_with_password(
                    self.clients[0],
                    user2,
                    self.clients[0].hostname,
                    'Secret123',
                    expect_success=False,
                )
                assert "domain users" not in output2.stdout_text
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
            with xfail_fedora_sssd_before_2_12(self.clients[0]):
                for user in [self.aduser, self.subaduser]:
                    with self.clients[0].spawn_expect(
                            test_sudo.format(user=user)) as e:
                        e.sendline('Secret123')
                        e.sendline('exit')
                        e.expect_exit(
                            ignore_remaining_output=True, raiseonerr=False)
                        output = e.get_last_output()
                        assert 'uid=0(root)' in output
                for user in [self.testuser, self.subnonposixuser1]:
                    test_sudo = "su {0} -c 'sudo -S id'".format(user)
                    result = self.clients[0].run_command(
                        test_sudo,
                        stdin_text='Secret123',
                        raiseonerr=False
                    )
                    output = f"{result.stdout_text}{result.stderr_text}"
                    assert (
                            "PAM account management error: Permission denied"
                            in output
                    )
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
            with xfail_fedora_sssd_before_2_12(self.clients[0]):
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
            with xfail_fedora_sssd_before_2_12(self.clients[0]):
                test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                    self.aduser, self.aduser2
                )
                self._run_sudo_command(self.clients[0], test_sudo, self.aduser,
                                       expected_output=self.aduser2
                                       )

                test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                    self.subaduser, self.subaduser2
                )
                self._run_sudo_command(
                    self.clients[0], test_sudo, self.subaduser,
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
                with xfail_fedora_sssd_before_2_12(self.clients[0]):
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
            with xfail_fedora_sssd_before_2_12(self.clients[0]):
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


class TestTrustFunctionalSSH(BaseTestTrust):
    topology = 'line'
    num_ad_treedomains = 0

    ad_user_password = 'Secret123'
    ad_user_first_password = 'Passw0rd1'

    @classmethod
    def install(cls, mh):
        super().install(mh)
        tasks.kinit_admin(cls.clients[0])
        # mkhomedir + oddjobd for AD user home dir creation on first login
        for host in [cls.master, cls.clients[0]]:
            host.run_command(
                ["authselect", "enable-feature", "with-mkhomedir"]
            )
            host.run_command(
                ["systemctl", "enable", "--now", "oddjobd"]
            )
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])
        tasks.kinit_admin(cls.master)

    def _ad_hosts(self):
        """Return (ad_host, domain) pairs for primary AD and the subdomain.

        Each entry is a tuple of (AD host object, domain name string) so
        that callers can drive user-lifecycle operations (add/mod/del) against
        both the root AD DC and the child-domain DC in a single loop.
        """
        return [
            (self.ad, self.ad_domain),
            (self.child_ad, self.ad_subdomain),
        ]

    def _sssd_cache_reset_all(self):
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.clients[0])

    def _ad_user_domain_pairs(self):
        """Return (user_principal, domain) pairs for both AD and subdomain.

        Each entry is a tuple of (fully-qualified user principal, AD domain
        name) so that callers can build login names and UPNs for both the
        primary AD domain and its subdomain in a single loop.
        """
        return [
            (self.aduser, self.ad_domain),
            (self.subaduser, self.ad_subdomain),
        ]

    def test_ssh_password_unqualified_login_fails(self):
        """AD user SSH with password using short (unqualified) username fails.

        Verifies that password authentication is rejected when the AD user
        logs in with only their sAMAccountName (no domain suffix), because
        the IPA client cannot map an unqualified name to an AD identity.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            testuser = self._ad_user_base(user)
            result = ssh_with_password(
                self.clients[0], testuser, self.clients[0].hostname,
                self.ad_user_password, expect_success=False)
            assert result.returncode != 0, (
                f"Expected unqualified login for '{testuser}' "
                f"(domain: {domain}) to fail"
            )

    def test_ssh_gssapi_unqualified_login_fails(self):
        """AD user SSH with GSSAPI using short (unqualified) username fails.

        Verifies that GSSAPI authentication is rejected when the AD user's
        login name contains no domain suffix, even though a valid Kerberos
        ticket is obtained with the full UPN.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            testuser = self._ad_user_base(user)
            ad_upn = self._ad_principal(testuser, domain, realm=True)
            result = ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                self.ad_user_password, expect_success=False)
            assert result.returncode != 0, (
                f"Expected unqualified GSSAPI login for '{testuser}' "
                f"(domain: {domain}) to fail"
            )

    def test_ssh_password_fqdn_login(self):
        """AD user SSH with password using fully-qualified user@domain login.

        Verifies that password authentication succeeds when the AD user
        logs in as user@domain.lower.  Also checks that no sssd_be crash
        or core dump appears in journalctl after the login.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple()
        )
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ssh_with_password(
                self.clients[0], testuser, self.clients[0].hostname,
                self.ad_user_password)
        result = self.clients[0].run_command([
            'journalctl', f'--since={since}', '--no-pager'
        ], raiseonerr=False)
        log_output = result.stdout_text
        assert "core dump" not in log_output
        assert "sssd_be" not in log_output

    def test_ssh_gssapi_localauth_plugin(self):
        """SSSD localauth plugin is present and AD user GSSAPI login works.

        Verifies that the SSSD localauth plugin configuration file and its
        module binary exist on the client, that krb5.conf does not contain
        a legacy auth_to_local rule, and that the AD user can log in via
        GSSAPI using the lowercase domain principal.
        """
        assert self.clients[0].transport.file_exists(PLUGIN_CONF)
        localauth_module = get_localauth_module_from_plugin(self.clients[0])
        assert self.clients[0].transport.file_exists(localauth_module)
        krb5_conf = self.clients[0].get_file_contents(
            paths.KRB5_CONF, encoding='utf-8'
        )
        assert "auth_to_local" not in krb5_conf
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ad_upn = self._ad_principal(base, domain, realm=True)
            ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_password_upn_login(self):
        """AD user SSH with password using UPN (user@REALM) login succeeds.

        Verifies that password authentication works when the AD user's
        login name is in UPN format with the uppercase Kerberos realm
        (user@AD.DOMAIN.COM).
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=True)
            ssh_with_password(
                self.clients[0], testuser, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_gssapi_upn_login(self):
        """AD user SSH with GSSAPI using UPN for both kinit and login.

        Verifies that GSSAPI authentication succeeds when the same UPN
        (user@REALM) is used as the kinit principal and as the SSH login
        name.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            ad_upn = self._ad_principal(base, domain, realm=True)
            ssh_with_gssapi(
                self.clients[0], ad_upn, ad_upn, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_password_netbios_lower_login(self):
        """AD user SSH with password using lowercase NetBIOS prefix login.

        Verifies that password authentication succeeds when the AD user
        logs in with the Windows-style netbios\\user notation using a
        lowercase NetBIOS domain prefix.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            testuser = "{0}\\{1}".format(
                self._ad_domain_netbios(domain).lower(),
                self._ad_user_base(user),
            )
            ssh_with_password(
                self.clients[0], testuser, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_gssapi_netbios_lower_login(self):
        """AD user SSH with GSSAPI using lowercase NetBIOS prefix login.

        Verifies that GSSAPI authentication succeeds when the SSH login
        name uses the lowercase netbios\\user notation while kinit is
        performed with the full UPN.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            testuser = "{0}\\{1}".format(
                self._ad_domain_netbios(domain).lower(),
                self._ad_user_base(user),
            )
            base = self._ad_user_base(user)
            ad_upn = self._ad_principal(base, domain, realm=True)
            ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_password_netbios_upper_login(self):
        """AD user SSH with password using uppercase NetBIOS prefix login.

        Verifies that password authentication succeeds when the AD user
        logs in with the Windows-style NETBIOS\\user notation using an
        uppercase NetBIOS domain prefix.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            testuser = "{0}\\{1}".format(
                self._ad_domain_netbios(domain).upper(),
                self._ad_user_base(user),
            )
            ssh_with_password(
                self.clients[0], testuser, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_gssapi_netbios_upper_login(self):
        """AD user SSH with GSSAPI using uppercase NetBIOS prefix login.

        Verifies that GSSAPI authentication succeeds when the SSH login
        name uses the uppercase NETBIOS\\user notation while kinit is
        performed with the full UPN.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            testuser = "{0}\\{1}".format(
                self._ad_domain_netbios(domain).upper(),
                self._ad_user_base(user),
            )
            base = self._ad_user_base(user)
            ad_upn = self._ad_principal(base, domain, realm=True)
            ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                self.ad_user_password)

    def test_ssh_gssapi_credential_forwarding(self):
        """AD user kinit and SSH as a second AD user via credential forwarding.

        Verifies that one AD user can obtain a Kerberos ticket and then
        forward GSSAPI credentials to SSH into the client as a different
        AD user, confirming cross-user credential delegation within an AD
        trust environment.
        Repeated for the root AD domain (testuser1 -> testuser2) and
        for subdomaintestuser -> subdomaintestuser2.
        """
        pairs = [(self.testuser1, self.testuser2),
                 (self.subaduser, self.subdomaintestuser2)
                 ]
        client = self.clients[0]
        for first_user, second_user in pairs:
            tasks.kdestroy_all(client)
            tasks.kinit_as_user(client, first_user, self.ad_user_password)
            result = client.run_command([
                'ssh', '-o', 'StrictHostKeyChecking=no', '-K',
                '-l', first_user, client.hostname,
                '--',
                'sshpass', '-p', self.ad_user_password,
                'ssh', '-o', 'StrictHostKeyChecking=no',
                '-o', 'GSSAPIAuthentication=no',
                '-o', 'PubkeyAuthentication=no',
                '-o', 'PasswordAuthentication=yes',
                '-l', second_user, client.hostname, 'id',
            ])
            assert second_user in result.stdout_text

    def test_ssh_gssapi_new_user_no_cache_flush(self):
        """Newly created AD user can SSH with GSSAPI without cache flush.

        Verifies that an AD user added during the test can immediately
        authenticate via GSSAPI over SSH, confirming that SSSD resolves
        brand-new AD accounts without requiring a manual cache reset.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        username = 'adnew1'
        for ad_host, domain in self._ad_hosts():
            testuser = self._ad_principal(username, domain)
            ad_upn = self._ad_principal(username, domain, realm=True)
            try:
                self._ad_user_add(
                    username, self.ad_user_password,
                    ad_host=ad_host, domain=domain)
                ssh_with_gssapi(
                    self.clients[0], ad_upn, testuser,
                    self.clients[0].hostname, self.ad_user_password)
            finally:
                self._ad_user_del(username, ad_host=ad_host, domain=domain)

    def test_ssh_deleted_user_evicted_from_cache(self):
        """Deleted AD user is evicted from SSSD cache and kinit fails.

        Creates an AD user, resolves it via getent (populating the SSSD
        cache), deletes the user, flushes the SSSD cache, and then verifies
        that getent returns no entry and kinit reports the principal is not
        found in the Kerberos database.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        username = 'adnew2'
        for ad_host, domain in self._ad_hosts():
            testuser = self._ad_principal(username, domain)
            ad_upn = self._ad_principal(username, domain, realm=True)
            try:
                self._ad_user_add(
                    username, self.ad_user_password,
                    ad_host=ad_host, domain=domain)
                self.master.run_command(['getent', 'passwd', testuser])
                ssh_with_gssapi(
                    self.clients[0], ad_upn, testuser,
                    self.clients[0].hostname, self.ad_user_password)
                self._ad_user_del(username, ad_host=ad_host, domain=domain)
                self._sssd_cache_reset_all()
                result = self.clients[0].run_command(
                    ['getent', '-s', 'sss', 'passwd', testuser],
                    raiseonerr=False,
                )
                assert result.returncode != 0
                result = self.clients[0].run_command(
                    ['kinit', testuser],
                    stdin_text=self.ad_user_password,
                    raiseonerr=False,
                )
                output = f"{result.stdout_text}{result.stderr_text}"
                assert "not found in Kerberos database" in output
            finally:
                self._ad_user_del(username, ad_host=ad_host, domain=domain)

    def test_ssh_recreated_user_login_after_cache_clear(self):
        """Re-created AD user can SSH after SSSD cache is cleared.

        Verifies that an AD user which was deleted and then re-added with
        the same name can still authenticate via GSSAPI and password SSH
        once the SSSD cache is flushed, ensuring stale cache entries do
        not block the re-created account.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        username = 'adnew3'
        for ad_host, domain in self._ad_hosts():
            testuser = self._ad_principal(username, domain)
            ad_upn = self._ad_principal(username, domain, realm=True)
            try:
                self._ad_user_add(
                    username, self.ad_user_password,
                    ad_host=ad_host, domain=domain)
                self.master.run_command(['getent', 'passwd', testuser])
                self._ad_user_del(username, ad_host=ad_host, domain=domain)
                self._sssd_cache_reset_all()
                self.master.run_command(['getent', 'passwd', testuser],
                                        raiseonerr=False)
                self._ad_user_add(
                    username, self.ad_user_password,
                    ad_host=ad_host, domain=domain)
                self._sssd_cache_reset_all()
                tasks.kdestroy_all(self.clients[0])
                tasks.clear_sssd_cache(self.clients[0])
                self.clients[0].run_command(['getent', 'passwd', testuser])
                ssh_with_gssapi(
                    self.clients[0], ad_upn, testuser,
                    self.clients[0].hostname, self.ad_user_password)
                ssh_with_password(
                    self.clients[0], testuser, self.clients[0].hostname,
                    self.ad_user_password)
            finally:
                self._ad_user_del(username, ad_host=ad_host, domain=domain)

    def test_ssh_su_second_ad_user_in_session(self):
        """AD user can switch to a second AD user via su within SSH session.

        Verifies that after logging in via GSSAPI as one AD user, it is
        possible to switch to a different AD user using su inside the same
        SSH session, confirming correct PAM/SSSD identity handling for
        cross-user switches under an AD trust.
        Repeated for the root AD domain (testuser1 -> testuser2) and
        subdomaintestuser -> subdomaintestuser2.
        """
        pairs = [(self.testuser1, self.testuser2),
                 (self.subaduser, self.subdomaintestuser2)
                 ]
        client = self.clients[0]
        for first_user, second_user in pairs:
            tasks.kdestroy_all(client)
            tasks.kinit_as_user(client, first_user, self.ad_user_password)
            with client.spawn_expect([
                'ssh', '-t', '-o', 'StrictHostKeyChecking=no', '-K',
                '-l', first_user, client.hostname,
                '--', 'su', '-', second_user, '-c', 'id',
            ], extra_ssh_options=['-t']) as test:
                # (?i) ignores case, enabling flag this way is atypical.
                test.expect(r'(?i)password')
                test.sendline(self.ad_user_password)
                test.expect_exit(ignore_remaining_output=True, timeout=60)
                output = test.get_last_output()
            assert second_user in output

    def test_ssh_password_to_master(self):
        """AD user SSH with password to the IPA master (server mode).

        Verifies that password authentication succeeds when the AD user
        connects to the IPA master rather than to a regular IPA client,
        exercising the server-mode SSSD code path.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ssh_with_password(
                self.clients[0], testuser, self.master.hostname,
                self.ad_user_password)

    def test_ssh_gssapi_to_master(self):
        """AD user SSH with GSSAPI to the IPA master (server mode).

        Verifies that GSSAPI authentication succeeds when the AD user
        connects to the IPA master, exercising the server-mode SSSD and
        Kerberos PAC processing code paths.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ad_upn = self._ad_principal(base, domain, realm=True)
            ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.master.hostname,
                self.ad_user_password)

    def test_ssh_gssapi_ad_user_ipa_cmd_denied(self):
        """AD user cannot run privileged IPA commands over GSSAPI SSH.

        Verifies that an AD user authenticated via GSSAPI is denied when
        attempting to execute `ipa trust-del` on the master over SSH,
        receiving an "insufficient access" or "cannot connect" error.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ad_upn = self._ad_principal(base, domain, realm=True)
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
            assert ("insufficient access" in output.lower()), (
                f"Expected trust-del to be denied for '{testuser}' "
                f"(domain: {domain}), got: {output}"
            )

    def test_ssh_gssapi_ad_admin_trust_del_denied(self):
        """AD domain admin cannot delete the IPA-AD trust over GSSAPI SSH.

        Verifies that even the AD domain administrator is denied when
        trying to execute `ipa trust-del` on the master over SSH using
        GSSAPI credentials, ensuring the trust cannot be removed by an
        AD-side account.
        """
        admin = self.master.config.ad_admin_name
        admin_principal = self._ad_principal(admin, self.ad_domain, realm=True)
        admin_login = self._ad_principal(admin, self.ad_domain, realm=False)
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
        assert ("insufficient access" in output.lower())

    def test_ssh_password_change_forced_at_login(self):
        """AD user forced to change password on first SSH login can do so.

        Verifies the SSH session prompts for the current and a new
        password, accepts the change, and subsequently allows a successful
        login with the new credentials.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        ad_user_new_password = 'Password01'
        for user in [self.changepwdatlogonuser, self.submustchgpwduser]:
            tasks.clear_sssd_cache(self.clients[0])
            with spawn_ssh_interactive(
                    self.clients[0], user, self.clients[0].hostname,
                    extra_ssh_options=['-tt']
            ) as test:
                # (?i) ignores case, enabling flag this way is atypical.
                test.expect(r'(?i).*password.*:')
                test.sendline('Secret123')
                expect_password_change_prompts(
                    test, 'Secret123', ad_user_new_password
                )
                test.expect(r'.*[$#] ')
                test.sendline('whoami')
                test.expect(user)
                test.sendline('exit')
                test.expect_exit(
                    ignore_remaining_output=True, raiseonerr=False
                )

    def test_ssh_passwd_change_denied_canchpwd_no(self):
        """Aduser with 'cannot change password' is denied password change SSH

        ADuser with "cannot change password" flag, logs in over
        SSH, attempts a password change via passwd, and verifies that the
        change is rejected with a "password change failed" message.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        ad_user_new_password = 'Password01'
        for user in [self.cannotchangepwduser, self.subcantchgpwduser]:
            with spawn_ssh_interactive(
                    self.clients[0], user, self.clients[0].hostname,
                    extra_ssh_options=['-tt']
            ) as test:
                # (?i) ignores case, enabling flag this way is atypical.
                test.expect(r'(?i).*password.*:')
                test.sendline('Secret123')
                test.expect(r'.*[$#] ')
                test.sendline('passwd')
                expect_password_change_prompts(
                    test, 'Secret123', ad_user_new_password
                )
                test.sendline('exit')
                test.expect_exit(
                    ignore_remaining_output=True, raiseonerr=False
                )
                assert 'password change failed' in test.before.lower()

    def test_ssh_password_disabled_account_rejected(self):
        """Disabled AD account is rejected during SSH password authentication.

        Disables an AD user account, attempts SSH password authentication,
        and verifies the login is denied.  Also checks that the failure is
        recorded as an authentication failure in journalctl (sshd).
        Repeated for both the primary AD domain and the AD subdomain.
        """
        for user in [self.disabledaduser, self.subdisableduser]:
            tasks.clear_sssd_cache(self.clients[0])
            tasks.wait_for_sssd_domain_status_online(self.clients[0])

            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=5)).timetuple()
            )

            with spawn_ssh_interactive(
                    self.clients[0], user, self.clients[0].hostname,
                    extra_ssh_options=['-tt']
            ) as test:
                # (?i) ignores case, enabling flag this way is atypical.
                test.expect(r'(?i).*password.*:')
                test.sendline(self.ad_user_first_password)
                test.expect(r'(?i).*password.*:')
                test.sendcontrol('c')
                test.expect_exit(
                    ignore_remaining_output=True, raiseonerr=False
                )

            result = self.clients[0].run_command([
                'journalctl', '-u', 'sshd', f'--since={since}',
                '--no-pager'
            ], raiseonerr=False)
            log_data = result.stdout_text
            assert (
                    "authentication failure" in log_data.lower()
            ), f"No auth failure in log for disabled user {user}"

    def test_ipa_trust_func_sssd_error(self):
        """
        Test sssd logs do not throw error when AD user tries to login via
        ipa client.

        Bug: [BZ954342] In IPA AD trust setup, the sssd logs throws
        'sysdb_search_user_by_name failed' error when AD user tries to
        login via ipa client.
        Repeated for both the primary AD domain and the AD subdomain.
        """
        sssd_log = '{0}/sssd_{1}.log'.format(
            paths.VAR_LOG_SSSD_DIR, self.master.domain.name)

        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ad_upn = self._ad_principal(base, domain, realm=True)

            tasks.kdestroy_all(self.master)
            tasks.kinit_as_user(
                self.master, ad_upn, self.master.config.ad_admin_password)

            # Capture current sssd log offset so we only inspect new entries
            sssd_log_offset = len(self.master.get_file_contents(sssd_log))

            # SSH with GSSAPI
            self.master.run_command([
                'ssh', '-K', '-l', testuser, self.master.hostname,
                'echo login successful $(whoami)'
            ])

            # Check only the log content generated during this test step
            if self.master.transport.file_exists(sssd_log):
                log_content = self.master.get_file_contents(sssd_log)
                new_log_content = log_content[sssd_log_offset:]
                assert b'sysdb_search_user_by_name failed' not in (
                    new_log_content
                ), f"sysdb_search_user_by_name failed for {testuser}"

        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)

    def test_ipa_trust_func_pac_responder(self):
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
        ssh_with_gssapi(
            self.master, testuserupn, testuser, self.master.hostname,
            self.master.config.ad_admin_password)

        # Test on client
        sssd_conf = self.clients[0].get_file_contents(
            paths.SSSD_CONF, encoding='utf-8')
        assert f'ipa_server = _srv_, {self.master.hostname}' in sssd_conf

        tasks.kdestroy_all(self.clients[0])
        ssh_with_gssapi(
            self.clients[0], testuserupn, testuser,
            self.clients[0].hostname,
            self.clients[0].config.ad_admin_password)

    def test_ipa_trust_func_sssd_crash_check(self):
        """
        Test sssd_be must not crash on passwordless login.

        Bug: [BZ1123432] sssdbe must not crash on passwordless login
        Repeated for both the primary AD domain and the AD subdomain.
        """
        # Capture timestamp to scope log check to this test (journalctl)
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple()
        )

        for user, domain in self._ad_user_domain_pairs():
            base = self._ad_user_base(user)
            testuser = self._ad_principal(base, domain, realm=False)
            ad_upn = self._ad_principal(base, domain, realm=True)
            ssh_with_gssapi(
                self.clients[0], ad_upn, testuser, self.clients[0].hostname,
                self.ad_user_password)

        # Check logs via journalctl (equivalent to /var/log/messages)
        result = self.clients[0].run_command([
            'journalctl', f'--since={since}', '--no-pager'
        ], raiseonerr=False)
        log_output = result.stdout_text
        assert 'Internal credentials cache error' not in log_output
        assert 'core_backtrace' not in log_output
        assert 'segfault' not in log_output
