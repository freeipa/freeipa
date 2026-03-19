# Copyright (C) 2019 FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import time
import textwrap
import pytest

from datetime import datetime, timedelta
from packaging.version import parse as parse_version
from ipaplatform.base.paths import BasePathNamespace
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


def ssh_with_password(host, login, target_host, password, expect_success=True,
                      remote_cmd='id'):
    """Run SSH with password authentication (uses ``sshpass``).

    :param host: Host on which to run the SSH command.
    :param login: SSH login name (``-l`` argument).
    :param target_host: Hostname to connect to.
    :param password: Password for authentication.
    :param expect_success: If ``True``, raise on failure; if ``False``, return
        the result object even when the command fails.
    :param remote_cmd: Command to run on the remote host (default: ``id``).
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
            '-l', login, target_host, remote_cmd
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


def passwd_change_with_retry(host, user_fqdn, current_password,
                             new_password, max_retries=5):
    """Change password via ``passwd`` command with retry logic.

    :param host: Host where the passwd command is executed.
    :param user_fqdn: Fully qualified user (e.g. ``user@domain``).
    :param current_password: The user's current password.
    :param new_password: The desired new password.
    :param max_retries: Number of retry attempts (default 5).
    :raises pytest.fail: If password change fails after all retries.
    """
    passwd_cmd = f"su - {user_fqdn} -c passwd"
    last_output = ""

    for _attempt in range(max_retries):
        with host.spawn_expect(passwd_cmd) as e:
            expect_password_change_prompts(
                e, current_password, new_password
            )
            e.expect_exit(ignore_remaining_output=True, raiseonerr=False)
            last_output = e.before if e.before else ""

        if "password updated successfully" in last_output:
            return
        time.sleep(2)

    pytest.fail(
        f"Password change for {user_fqdn} failed after "
        f"{max_retries} attempts. Last output: {last_output}"
    )


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


AD_PASSWORD = 'Secret123'

AUTOMOUNT_LOCATION = 'trust_location'
AUTOMOUNT_INDIRECT_MAP = 'auto.share'
AUTOMOUNT_INDIRECT_MOUNTPOINT = '/automnt.d'
AUTOMOUNT_DIRECT_MOUNTPOINT = '/automnt2.d'
EXPORT_RW_DIR = '/export'
EXPORT_RO_DIR = '/export2'


def run_as_ad_user(host, user, domain, command, **kwargs):
    """Run a shell command on host as user@domain via su.

    Uses su without -l to avoid attempting cd to a potentially
    non-existent AD user home directory.
    """
    return host.run_command(
        ['su', f'{user}@{domain}', '-c', command], **kwargs
    )


def kinit_ad_user(host, user, domain, realm, password=AD_PASSWORD):
    """Obtain a Kerberos ticket for an AD user via su."""
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
    pam_error = "sudo: PAM account management error: Permission denied"

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
                assert self.pam_error in output
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
                    assert self.pam_error in output
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
            test_sudo = "su {0} -c 'sudo -S -u {1} id'".format(
                self.aduser, self.aduser2
            )
            with xfail_fedora_sssd_before_2_12(self.clients[0]):
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
            with xfail_fedora_sssd_before_2_12(self.clients[0]):
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
            assert "authentication failure" in log_data.lower(), (
                f"No auth failure in log for disabled user {user}"
            )

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


class TestTrustFunctionalUser(BaseTestTrust):
    """
    Test class for AD user functional tests covering both top domain
    and subdomain users.

    Tests cover: kinit, su, external group membership, home directory
    access, and group membership verification.
    """
    topology = 'line'
    num_ad_treedomains = 0

    # Default password for AD test users (Ansible / fixture convention).
    DEFAULT_AD_USER_PASSWORD = 'Secret123'

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
            username = self._ad_user_base(user)
            domain = user.split('@', 1)[1]
            for realm in (domain.upper(), domain.lower()):
                tasks.kdestroy_all(self.clients[0])
                tasks.kinit_as_user(
                    self.clients[0], f'{username}@{realm}',
                    self.DEFAULT_AD_USER_PASSWORD,
                )

    def test_kinit_canonical(self):
        """Test kinit with canonicalization flag for AD users."""
        tasks.kdestroy_all(self.clients[0])
        for user in [self.aduser, self.subaduser]:
            result = self.clients[0].run_command(
                ['kinit', '-C', user],
                stdin_text=f'{self.DEFAULT_AD_USER_PASSWORD}\n',
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
            netbios = self._ad_domain_netbios(domain).upper()
            user = self._ad_user_base(username)
            result = tasks.kinit_as_user(
                self.clients[0], f'{netbios}\\{user}',
                self.DEFAULT_AD_USER_PASSWORD,
                raiseonerr=False
            )
            assert result.returncode != 0

    def test_kinit_disabled_account(self):
        """
        Test kinit fails for disabled AD accounts.
        Related: BZ1162486, test 0006

        Uses pre-existing disabled users from :class:`BaseTestTrust`:
        ``disabledaduser`` (forest root) and ``subdisableduser`` (subdomain).
        """
        disabled_users = [
            self.disabledaduser,
            self.subdisableduser,
        ]

        for disabled_user in disabled_users:
            tasks.kdestroy_all(self.clients[0])
            tasks.clear_sssd_cache(self.clients[0])

            result = tasks.kinit_as_user(
                self.clients[0], disabled_user,
                self.DEFAULT_AD_USER_PASSWORD,
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
        Uses pre-created expired users from :class:`BaseTestTrust`:
        ``expiredaduser`` (forest root) and ``subexpiredaduser`` (subdomain).
        Related: test 0007
        """
        expired_users = [
            (self.expiredaduser, self.DEFAULT_AD_USER_PASSWORD),
            (self.subexpiredaduser, self.DEFAULT_AD_USER_PASSWORD),
        ]

        for expired_user, password in expired_users:
            tasks.kdestroy_all(self.clients[0])
            tasks.clear_sssd_cache(self.clients[0])

            result = tasks.kinit_as_user(
                self.clients[0], expired_user, password,
                raiseonerr=False
            )
            output = f"{result.stdout_text}{result.stderr_text}"
            assert result.returncode != 0, (
                f"kinit should fail for {expired_user}"
            )
            assert "credentials have been revoked" in output, (
                f"Expected 'revoked' in output for {expired_user}"
            )

    def test_su_ad_user(self):
        """Test su to AD users from top and sub domains."""
        for user in (self.aduser, self.subaduser):
            username = self._ad_user_base(user)
            domain = user.split('@', 1)[1]
            for realm in (domain.upper(), domain.lower()):
                result = self.clients[0].run_command(
                    ['su', '-', f'{username}@{realm}', '-c', 'whoami']
                )
                output = result.stdout_text.strip()
                # whoami returns fully qualified name for AD trust users
                assert f'{username}@{domain}' in output

    def test_passwd_change_by_user(self):
        """
        Test AD user can change their own password.
        Uses pre-created AD users from Ansible playbook.
        Related: BZ870238, test 0010 (root) and sub_0010 (child)
        """
        original_password = self.DEFAULT_AD_USER_PASSWORD
        new_password = "Dec3@4smsS3"

        test_users = [
            (self.ad, self.ad_domain, self._ad_user_base(self.testuser2)),
            (
                self.child_ad, self.ad_subdomain,
                self._ad_user_base(self.subdomaintestuser2),
            ),
        ]

        for ad_host, ad_domain, test_user in test_users:
            user_fqdn = f"{test_user}@{ad_domain}"
            try:
                # Set MinPasswordAge to 0 to allow immediate password change
                ad_host.run_command([
                    'powershell', '-c',
                    f'$ProgressPreference = "SilentlyContinue"; '
                    f'Set-ADDefaultDomainPasswordPolicy '
                    f'-Identity "{ad_domain}" -MinPasswordAge 0'
                ], set_env=False)

                tasks.clear_sssd_cache(self.clients[0])
                self.clients[0].run_command(['id', user_fqdn])

                passwd_change_with_retry(
                    self.clients[0], user_fqdn,
                    original_password, new_password
                )

                tasks.kdestroy_all(self.clients[0])
                self.clients[0].run_command(
                    ['kinit', user_fqdn], stdin_text=f'{new_password}\n'
                )
            finally:
                # Reset password back to original
                ad_host.run_command([
                    'powershell', '-c',
                    f'$ProgressPreference = "SilentlyContinue"; '
                    f'Set-ADAccountPassword -Identity "{test_user}" '
                    f'-Reset -NewPassword '
                    f'(ConvertTo-SecureString "{original_password}" '
                    f'-AsPlainText -Force)'
                ], raiseonerr=False, set_env=False)
                # Restore MinPasswordAge to 1 day
                ad_host.run_command([
                    'powershell', '-c',
                    f'$ProgressPreference = "SilentlyContinue"; '
                    f'Set-ADDefaultDomainPasswordPolicy '
                    f'-Identity "{ad_domain}" -MinPasswordAge 1.00:00:00'
                ], raiseonerr=False, set_env=False)

    def test_homedir_access_commands(self):
        """Test home directory access commands for AD users."""
        tasks.clear_sssd_cache(self.clients[0])
        for user in [self.aduser, self.subaduser]:
            username = self._ad_user_base(user)
            domain = user.split('@', 1)[1]
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

        # SSH with password to resolve users via PAM/SSSD
        for user in [self.subaduser, self.testuser]:
            ssh_with_password(
                self.clients[0], user, self.clients[0].hostname,
                self.DEFAULT_AD_USER_PASSWORD)
        # Wait for SSSD to process membership
        time.sleep(10)
        # Resolve both users
        for user in [self.subaduser, self.testuser]:
            self.clients[0].run_command(['id', user])
        # Wait for group membership resolution
        time.sleep(5)

        # Check root domain: testuser in testgroup
        result = self.clients[0].run_command(
            ['getent', 'group', self.ad_group]
        )
        assert self.testuser in result.stdout_text, (
            f"Root domain user {self.testuser} not found in "
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

    def test_ad_user_in_posix_group_fully_qualified(self):
        """
        Test that AD users in IPA posix group are shown fully qualified.

        Tests both top domain and subdomain AD users are displayed with
        fully qualified names when added to IPA external/posix groups.

        Related: BZ877126, BZ1171383
        """

        ext_group = "tgroup5_external"
        posix_group = "tgroup5"

        # Test both top domain and subdomain users
        test_cases = [
            ([self.aduser, self.testuser], "top domain"),
            ([self.subaduser, self.subdomaintestuser2], "subdomain"),
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

                # Test on client: xfail on Fedora when SSSD is 2.12.0
                client = self.clients[0]
                with xfail_context(
                    osinfo.id == 'fedora'
                    and tasks.get_sssd_version(client)
                    == parse_version('2.12.0'),
                    reason=(
                        "Fix available after 2.12.0; "
                        "https://github.com/SSSD/sssd/issues/8441"
                    ),
                ):
                    tasks.clear_sssd_cache(client)
                    tasks.wait_for_sssd_domain_status_online(client)
                    # SSH with password to resolve users
                    for user in users:
                        ssh_with_password(
                            client, user, client.hostname,
                            self.DEFAULT_AD_USER_PASSWORD)
                    # Clear cache again
                    tasks.clear_sssd_cache(client)
                    tasks.wait_for_sssd_domain_status_online(client)
                    # Resolve users
                    for user in users:
                        client.run_command(['id', user])
                    # Check group membership
                    result = client.run_command(
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

    def test_ad_user_in_multiple_groups(self):
        """
        Test that AD users appear in multiple AD groups.

        Tests that getent commands display secondary groups for trusted AD
        users from both top domain and subdomain. Each user should belong
        to groups from their own domain.

        Related: BZ878583
        """
        ad_user = self._ad_user_base(self.testuser)
        ad_primary_group = self._ad_user_base(self.ad_group)
        ad_secondary_group = 'testgroup1'

        child_user = self._ad_user_base(self.subaduser)
        child_primary_group = self._ad_user_base(self.ad_sub_group)
        child_secondary_group = 'subdomaintestgroup1'

        # Secondary groups to ensure exist with their users
        secondary_groups = [
            (self.ad, ad_secondary_group, ad_user),
            (self.child_ad, child_secondary_group, child_user),
        ]
        # Only groups created by _ensure_ad_group_member in this run—do not
        # delete AD groups that already existed from provisioning (playbook).
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
                ssh_with_password(
                    self.clients[0], user_fqdn, self.clients[0].hostname,
                    self.DEFAULT_AD_USER_PASSWORD)
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

            # Clear SSSD cache on client and wait for SSSD to come online
            tasks.clear_sssd_cache(self.clients[0])
            tasks.wait_for_sssd_domain_status_online(self.clients[0])

            # Retry loop: wait up to 120 seconds for user to be resolvable
            for _retry in range(12):
                result = self.clients[0].run_command(
                    ['id', self.testuser], raiseonerr=False
                )
                if result.returncode == 0:
                    break
                time.sleep(10)

            # Check user appears in both posix groups via id
            result = self.clients[0].run_command(['id', self.testuser])
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
                assert self.testuser in result.stdout_text, (
                    f"User {self.testuser} not in getent group {grp}: "
                    f"{result.stdout_text}"
                )

            # Verify again after brief wait (as in bash test)
            time.sleep(5)
            for grp in [posix_group1, posix_group2]:
                self.clients[0].run_command(['getent', 'group', grp])
            time.sleep(5)
            result = self.clients[0].run_command(['id', self.testuser])
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

        # Get SIDs for user and group
        # getsidbyname returns dict like {'u': {'sid': 'S-1-...', 'type': N}}
        # We need to extract just the SID string
        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"d = pysss_nss_idmap.getsidbyname('{self.testuser}'); "
            f"print(d['{self.testuser}']['sid'])"
        ])
        user_sid = result.stdout_text.strip()

        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"d = pysss_nss_idmap.getsidbyname('{self.ad_group}'); "
            f"print(d['{self.ad_group}']['sid'])"
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
        assert self.testuser in result.stdout_text, (
            f"User {self.testuser} not resolved from SID: {result.stdout_text}"
        )

        result = self.clients[0].run_command([
            'python3', '-c',
            f"import pysss_nss_idmap; "
            f"print(pysss_nss_idmap.getnamebysid('{group_sid}'))"
        ], raiseonerr=False)
        assert self.ad_group in result.stdout_text, (
            f"Group {self.ad_group} not resolved from SID: "
            f"{result.stdout_text}"
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
                extra_args=[f'--external={self.testuser}'],
                noninteractive=True
            )

            # Clear SSSD cache on master
            tasks.clear_sssd_cache(self.master)
            tasks.wait_for_sssd_domain_status_online(self.master)

            # Check on master without prior authentication
            result = self.master.run_command(['id', self.testuser])
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
            result = self.clients[0].run_command(['id', self.testuser])
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
            (self.testuser, self.ad_group),
            (self.subaduser, self.ad_sub_group),
        ]

        for user, expected_group in test_cases:
            result = self.clients[0].run_command(['id', user])
            assert expected_group in result.stdout_text, (
                f"Group {expected_group} not found for user {user}: "
                f"{result.stdout_text}"
            )


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

        # (domain, realm, user1_rw_owner, user2_ro_owner)
        # user1 owns the rw export and is used for write/read tests;
        # user2 owns the ro export and is used for read-only and
        # cross-user ownership denial tests.
        cls.nfs_configs = [
            (cls.ad_domain, cls.ad_domain.upper(),
             'testuser', 'nonposixuser'),
        ]
        if cls.num_ad_subdomains > 0:
            # subdomain has only one active CI user
            cls.nfs_configs.append(
                (cls.ad_subdomain, cls.ad_subdomain.upper(),
                 'subdomaintestuser', 'subdomaintestuser'))

        master = cls.master
        client = cls.clients[0]

        tasks.install_packages(master, ['gssproxy'])
        tasks.kinit_admin(master)

        nfs_principal = f'nfs/{master.hostname}'
        master.run_command(['ipa', 'service-add', nfs_principal])
        master.run_command([
            'ipa-getkeytab', '-k', paths.KRB5_KEYTAB,
            '-s', master.hostname, '-p', nfs_principal
        ])

        content = master.get_file_contents(
            paths.SYSCONFIG_NFS, encoding='utf-8')
        master.put_file_contents(
            paths.SYSCONFIG_NFS, content + 'SECURE_NFS="yes"\n')

        exports_content = '/export  *(rw,sec=krb5:krb5i:krb5p)\n'

        for domain, _realm, user1, user2 in cls.nfs_configs:
            ad_user1 = f'{user1}@{domain}'
            ad_user2 = f'{user2}@{domain}'
            export_ro_dir = f'{EXPORT_RO_DIR}/{user2}'

            master.run_command(
                ['mkdir', '-p', f'/export/{user1}'])
            master.run_command(
                ['chmod', '770', f'/export/{user1}'])
            master.run_command(
                ['chown', f'{ad_user1}:{ad_user1}',
                 f'/export/{user1}'])
            master.put_file_contents(
                f'/export/{user1}/rw_test',
                'Read-Write-Test\n')
            master.run_command(
                ['chown', f'{ad_user1}:{ad_user1}',
                 f'/export/{user1}/rw_test'])
            master.run_command(
                ['chmod', '664', f'/export/{user1}/rw_test'])

            master.run_command(
                ['mkdir', '-p', export_ro_dir])
            master.run_command(
                ['chmod', '770', export_ro_dir])
            master.run_command(
                ['chown', f'{ad_user2}:{ad_user2}',
                 export_ro_dir])
            master.put_file_contents(
                f'{export_ro_dir}/ro_test',
                'Read-Only-Test\n')
            master.run_command(
                ['chown', f'{ad_user2}:{ad_user2}',
                 f'{export_ro_dir}/ro_test'])
            master.run_command(
                ['chmod', '664', f'{export_ro_dir}/ro_test'])

            exports_content += (
                f'{export_ro_dir}'
                f'  *(ro,sec=krb5:krb5i:krb5p)\n')

        master.put_file_contents('/etc/exports', exports_content)

        master.run_command(
            ['systemctl', 'restart', 'nfs-server'])
        master.run_command(
            ['systemctl', 'restart', 'rpc-gssd.service'])
        master.run_command(
            ['systemctl', 'restart', 'gssproxy'])
        master.run_command(['exportfs', '-a'])

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
            export_ro_dir = f'{EXPORT_RO_DIR}/{user2}'
            automount_direct_key = f'{AUTOMOUNT_DIRECT_MOUNTPOINT}/{user2}'
            master.run_command([
                'ipa', 'automountkey-add', AUTOMOUNT_LOCATION,
                'auto.direct',
                f'--key={automount_direct_key}',
                f'--info=-rw,fstype=nfs4,sec=krb5 '
                f'{master.hostname}:{export_ro_dir}'
            ])

        time.sleep(5)

        client.run_command([
            'ipa-client-automount',
            f'--server={master.hostname}',
            f'--location={AUTOMOUNT_LOCATION}', '-U'
        ])

    @classmethod
    def uninstall(cls, mh):
        tasks.kinit_admin(cls.master, raiseonerr=False)
        cls.master.run_command(
            ['ipa', 'automountlocation-del', AUTOMOUNT_LOCATION],
            raiseonerr=False)
        cls.master.run_command(
            ['rm', '-rf', EXPORT_RW_DIR, EXPORT_RO_DIR],
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

    def test_automount_default_domain_suffix(self):
        """SSSD retrieves auto.master with default_domain_suffix."""
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

        try:
            with tasks.FileBackup(client, paths.SSSD_CONF), \
                 tasks.FileBackup(client,
                                  BasePathNamespace.NSSWITCH_CONF):
                # default_domain_suffix allows AD users to
                # authenticate using short names (e.g. 'testuser')
                # without the @domain
                client.run_command([
                    'sed', '-i',
                    f'/\\[sssd\\]/ a default_domain_suffix = '
                    f'{self.ad_domain}',
                    paths.SSSD_CONF
                ])
                client.run_command([
                    'sed', '-i',
                    's/automount:.*/automount:  sss files/',
                    BasePathNamespace.NSSWITCH_CONF
                ])

                # Enable autofs debug logging in sssd
                client.run_command([
                    'sh', '-c',
                    f'grep -q "\\[autofs\\]" {paths.SSSD_CONF}'
                    f' || printf "\\n[autofs]\\n"'
                    f' >> {paths.SSSD_CONF}'
                ])
                client.run_command([
                    'sed', '-i',
                    '/\\[autofs\\]/a\\debug_level = 10',
                    paths.SSSD_CONF
                ])

                result = client.run_command(
                    ['grep', '-A3', '\\[sssd\\]',
                     paths.SSSD_CONF])
                assert 'default_domain_suffix' in \
                    result.stdout_text

                tasks.clear_sssd_cache(client)
                tasks.wait_for_sssd_domain_status_online(client)
                client.run_command(
                    ['systemctl', 'restart', 'autofs'])

                client.run_command(
                    ['getent', 'passwd', 'testuser'])

                result = client.run_command(['automount', '-m'])
                assert (
                    'setautomntent: lookup(sss): '
                    'setautomntent: No such file or directory'
                    not in result.stdout_text)
                assert 'autofs dump map information' \
                    in result.stdout_text
                assert 'Mount point: /-' in result.stdout_text

                log_result = client.run_command(
                    ['cat', '/var/log/sssd/sssd_autofs.log'])
                assert 'failed' not in \
                    log_result.stdout_text.lower()
        finally:
            client.run_command(
                ['systemctl', 'restart', 'sssd'],
                raiseonerr=False)
            tasks.wait_for_sssd_domain_status_online(client)
            client.run_command(
                ['systemctl', 'restart', 'autofs'],
                raiseonerr=False)

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
                ' ls -ltra')

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
            automount_direct_key = f'{AUTOMOUNT_DIRECT_MOUNTPOINT}/{user2}'
            export_ro_dir = f'{EXPORT_RO_DIR}/{user2}'

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
            automount_direct_key = f'{AUTOMOUNT_DIRECT_MOUNTPOINT}/{user2}'

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
            automount_direct_key = f'{AUTOMOUNT_DIRECT_MOUNTPOINT}/{user2}'

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

    def test_deny_wrong_user_write_rw_nfs(self):
        """Different AD user cannot write to another user's rw directory.

        Uses the root domain config where user1 (testuser) and user2
        (nonposixuser) are different, verifying that user2 is denied
        write access to user1's directory.
        """
        client = self.clients[0]
        domain, realm, user1, user2 = self.nfs_configs[0]

        umount_and_restart_autofs(
            client,
            f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}')

        run_as_ad_user(client, user2, domain, 'kdestroy -A')
        kinit_ad_user(client, user2, domain, realm)

        result = run_as_ad_user(
            client, user2, domain,
            f'echo Bad-Write >> '
            f'{AUTOMOUNT_INDIRECT_MOUNTPOINT}/{user1}/rw_test',
            raiseonerr=False)
        assert result.returncode != 0
        output = result.stdout_text + result.stderr_text
        assert 'Permission denied' in output
