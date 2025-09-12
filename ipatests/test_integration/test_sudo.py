# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import pytest

from ipaplatform.paths import paths
import time
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.tasks import (
    clear_sssd_cache, get_host_ip_with_hostmask, remote_sssd_config,
    FileBackup, install_master, install_client, kinit_admin)

class TestSudo(IntegrationTest):
    """
    Test Sudo
    http://www.freeipa.org/page/V4/Sudo_Integration#Test_Plan
    """
    num_clients = 1

    @classmethod
    def install(cls, mh):
        super(TestSudo, cls).install(mh)

        extra_args = ["--idstart=60001", "--idmax=65000"]
        install_master(cls.master, setup_dns=True, extra_args=extra_args)
        install_client(cls.master, cls.clients[0])

        cls.client = cls.clients[0]
        cls.clientname = cls.client.run_command(
            ['hostname', '-s']).stdout_text.strip()

        for i in range(1, 3):
            # Add 1. and 2. testing user
            cls.master.run_command(['ipa', 'user-add',
                                     'testuser%d' % i,
                                     '--first', 'Test',
                                     '--last', 'User%d' % i])

            # Add 1. and 2. testing groups
            cls.master.run_command(['ipa', 'group-add',
                                     'testgroup%d' % i,
                                     '--desc', '"%d. testing group"' % i])

            # Add respective members to each group
            cls.master.run_command(['ipa', 'group-add-member',
                                     'testgroup%d' % i,
                                     '--users', 'testuser%d' % i])

        # Add hostgroup containing the client
        cls.master.run_command(['ipa', 'hostgroup-add',
                                 'testhostgroup',
                                 '--desc', '"Contains client"'])

        # Add the client to the host group
        cls.master.run_command(['ipa', 'hostgroup-add-member',
                                 'testhostgroup',
                                 '--hosts', cls.client.hostname])

        # Create local user and local group he's member of
        cls.client.run_command(['groupadd', 'localgroup'])
        cls.client.run_command(['useradd',
                                '-M',
                                '-G', 'localgroup',
                                'localuser'])

        # Create sudorule 'defaults' for not requiring authentication
        cls.master.run_command(['ipa', 'sudorule-add', 'defaults'])
        cls.master.run_command(['ipa', 'sudorule-add-option',
                                'defaults',
                                '--sudooption', "!authenticate"])

        # Create test user -- member of group admins
        cls.master.run_command(['ipa', 'user-add', 'admin2',
                                '--first', 'Admin', '--last', 'Second'])
        cls.master.run_command(['ipa', 'group-add-member', 'admins',
                                '--users', 'admin2'])

    @classmethod
    def uninstall(cls, mh):
        cls.client.run_command(['groupdel', 'localgroup'], raiseonerr=False)
        cls.client.run_command(['userdel', 'localuser'], raiseonerr=False)
        super(TestSudo, cls).uninstall(mh)

    def list_sudo_commands(self, user, raiseonerr=False, verbose=False):
        clear_sssd_cache(self.client)
        list_flag = '-ll' if verbose else '-l'
        return self.client.run_command(
            'su -c "sudo %s -n" %s' % (list_flag, user),
            raiseonerr=raiseonerr)

    def reset_rule_categories(self, safe_delete=True):
        if safe_delete:
            # Remove and then add the rule back, since the deletion of some
            # entries might cause setting categories to ALL to fail
            # and therefore cause false negatives in the tests
            self.master.run_command(['ipa', 'sudorule-del', 'testrule'])
            self.master.run_command(['ipa', 'sudorule-add', 'testrule'])
            self.master.run_command(['ipa', 'sudorule-add-option',
                                     'testrule',
                                     '--sudooption', "!authenticate"])

        # Reset testrule to allow everything
        result = self.master.run_command(['ipa', 'sudorule-mod',
                                          'testrule',
                                          '--usercat=all',
                                          '--hostcat=all',
                                          '--cmdcat=all',
                                          '--runasusercat=all',
                                          '--runasgroupcat=all'],
                                          raiseonerr=False)

        return result

    # testcases test_admins_group_does_not_have_sudo_permission and
    # test_advise_script_enable_sudo_admins must be run before any other sudo
    # rules are applied
    def test_admins_group_does_not_have_sudo_permission(self):
        result = self.list_sudo_commands('admin2', raiseonerr=False)
        assert result.returncode == 1
        assert "Sorry, user admin2 may not run sudo on {}.".format(
            self.clientname) in result.stderr_text

    def test_advise_script_enable_sudo_admins(self):
        """
            Test for advise scipt to add sudo permissions for admin users
            https://pagure.io/freeipa/issue/7538
        """
        result = self.master.run_command('ipa-advise enable_admins_sudo')
        script = result.stdout_text
        self.master.run_command('bash', stdin_text=script)
        try:
            result = self.list_sudo_commands('admin2')
            assert '(root) ALL' in result.stdout_text
        finally:
            result1 = self.master.run_command(
                ['ipa', 'sudorule-del', 'admins_all'], raiseonerr=False)
            result2 = self.master.run_command(
                ['ipa', 'hbacrule-del', 'admins_sudo'], raiseonerr=False)
            assert result1.returncode == 0 and result2.returncode == 0,\
                'rules cleanup failed'

    @pytest.mark.skip_if_platform(
        "debian", reason="NISDOMAIN has not been set on Debian"
    )
    @pytest.mark.skip_if_container(
        "any", reason="NISDOMAIN cannot be set in containerized environment"
    )
    def test_nisdomainname(self):
        result = self.client.run_command('nisdomainname')
        assert self.client.domain.name in result.stdout_text

    def test_add_sudo_commands(self):
        # Group: Readers
        self.master.run_command(['ipa', 'sudocmd-add', '/bin/cat'])
        self.master.run_command(['ipa', 'sudocmd-add', '/bin/tail'])

        # No group
        self.master.run_command(['ipa', 'sudocmd-add', '/usr/bin/yum'])

        # Invalid command
        result = self.master.run_command(
            ['ipa', 'sudocmd-add', '/bin/cat.'], raiseonerr=False)
        assert result.returncode == 1

    def test_add_sudo_command_groups(self):
        self.master.run_command(['ipa', 'sudocmdgroup-add', 'readers',
                                 '--desc', '"Applications that read"'])

        self.master.run_command(['ipa', 'sudocmdgroup-add-member', 'readers',
                                 '--sudocmds', '/bin/cat'])

        self.master.run_command(['ipa', 'sudocmdgroup-add-member', 'readers',
                                 '--sudocmds', '/bin/tail'])

    def test_create_allow_all_rule(self):
        # Create rule that allows everything
        self.master.run_command(['ipa', 'sudorule-add',
                                 'testrule',
                                 '--usercat=all',
                                 '--hostcat=all',
                                 '--cmdcat=all',
                                 '--runasusercat=all',
                                 '--runasgroupcat=all'])

        # Add !authenticate option
        self.master.run_command(['ipa', 'sudorule-add-option',
                                 'testrule',
                                 '--sudooption', "!authenticate"])

    def test_add_sudo_rule(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

        result2 = self.list_sudo_commands("testuser2")
        assert "(ALL : ALL) NOPASSWD: ALL" in result2.stdout_text

    def test_sudo_rule_restricted_to_one_user_setup(self):
        # Configure the rule to not apply to anybody
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--usercat='])

        # Add the testuser1 to the rule
        self.master.run_command(['ipa', 'sudorule-add-user',
                                 'testrule',
                                 '--users', 'testuser1'])

    def test_sudo_rule_restricted_to_one_user(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

        result2 = self.list_sudo_commands("testuser2", raiseonerr=False)
        assert result2.returncode != 0
        assert "Sorry, user testuser2 may not run sudo on {}.".format(
            self.clientname) in result2.stderr_text

    def test_sudo_rule_restricted_to_one_user_without_defaults_rule(self):
        # Verify password is requested with the 'defaults' sudorule disabled
        self.master.run_command(['ipa', 'sudorule-disable', 'defaults'])

        result3 = self.list_sudo_commands("testuser2", raiseonerr=False)
        assert result3.returncode != 0
        assert "sudo: a password is required" in result3.stderr_text

    def test_setting_category_to_all_with_valid_entries_user(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_user_teardown(self):
        # Remove the testuser1 from the rule
        self.master.run_command(['ipa', 'sudorule-remove-user',
                                 'testrule',
                                 '--users', 'testuser1'])
        self.master.run_command(['ipa', 'sudorule-enable', 'defaults'])

    def test_sudo_rule_restricted_to_one_group_setup(self):
        # Add the testgroup2 to the rule
        self.master.run_command(['ipa', 'sudorule-add-user',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_one_group(self):
        result1 = self.list_sudo_commands("testuser1", raiseonerr=False)
        assert result1.returncode != 0
        assert "Sorry, user testuser1 may not run sudo on {}.".format(
            self.clientname) in result1.stderr_text

        result2 = self.list_sudo_commands("testuser2")
        assert "(ALL : ALL) NOPASSWD: ALL" in result2.stdout_text

    def test_setting_category_to_all_with_valid_entries_user_group(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_group_teardown(self):
        # Remove the testgroup2 from the rule
        self.master.run_command(['ipa', 'sudorule-remove-user',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_one_host_negative_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

        # Configure the rule to not apply anywhere
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--hostcat='])

        # Add the master to the rule
        self.master.run_command(['ipa', 'sudorule-add-host',
                                 'testrule',
                                 '--hosts', self.master.hostname])

    def test_sudo_rule_restricted_to_one_host_negative(self):
        result1 = self.list_sudo_commands("testuser1", raiseonerr=False)
        assert result1.returncode != 0
        assert "Sorry, user testuser1 may not run sudo on {}.".format(
            self.clientname) in result1.stderr_text

    def test_sudo_rule_restricted_to_one_host_negative_teardown(self):
        # Remove the master from the rule
        self.master.run_command(['ipa', 'sudorule-remove-host',
                                 'testrule',
                                 '--hosts', self.master.hostname])

    def test_sudo_rule_restricted_to_one_host_setup(self):
        # Configure the rulle to not apply anywhere
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--hostcat='], raiseonerr=False)

        # Add the master to the rule
        self.master.run_command(['ipa', 'sudorule-add-host',
                                 'testrule',
                                 '--hosts', self.client.hostname])

    def test_sudo_rule_restricted_to_one_host(self):
        result1 = self.list_sudo_commands("testuser1", raiseonerr=False)
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_host(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_host_teardown(self):
        # Remove the master from the rule
        self.master.run_command(['ipa', 'sudorule-remove-host',
                                 'testrule',
                                 '--hosts', self.client.hostname])

    def test_sudo_rule_restricted_to_one_hostgroup_setup(self):
        # Add the testhostgroup to the rule
        self.master.run_command(['ipa', 'sudorule-add-host',
                                 'testrule',
                                 '--hostgroups', 'testhostgroup'])

    def test_sudo_rule_restricted_to_one_hostgroup(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_host_group(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_hostgroup_teardown(self):
        # Remove the testhostgroup from the rule
        self.master.run_command(['ipa', 'sudorule-remove-host',
                                 'testrule',
                                 '--hostgroups', 'testhostgroup'])

    def test_sudo_rule_restricted_to_one_hostmask_setup(self):
        # We need to detect the hostmask first
        full_ip = get_host_ip_with_hostmask(self.client)

        # Make a note for the next test, which needs to be skipped
        # if hostmask detection failed
        self.__class__.skip_hostmask_based = False

        if not full_ip:
            self.__class__.skip_hostmask_based = True
            raise pytest.skip("Hostmask could not be detected")

        self.master.run_command(['ipa', '-n', 'sudorule-add-host',
                                 'testrule',
                                 '--hostmask', full_ip])

        # SSSD >= 1.13.3-3 uses native IPA schema instead of compat entries to
        # pull in sudoers. Since native schema does not (yet) support
        # hostmasks, we need to point ldap_sudo_search_base to the old schema
        self.__class__.client_sssd_conf_backup = FileBackup(
            self.client, paths.SSSD_CONF)
        domain = self.client.domain
        with remote_sssd_config(self.client) as sssd_conf:
            sssd_conf.edit_domain(domain, 'sudo_provider', 'ipa')
            sssd_conf.edit_domain(domain, 'ldap_sudo_search_base',
                                  'ou=sudoers,{}'.format(domain.basedn))

    def test_sudo_rule_restricted_to_one_hostmask(self):
        if self.__class__.skip_hostmask_based:
            raise pytest.skip("Hostmask could not be detected")

        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_host_mask(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_hostmask_teardown(self):
        if self.__class__.skip_hostmask_based:
            raise pytest.skip("Hostmask could not be detected")

        # Detect the hostmask first to delete the hostmask based rule
        full_ip = get_host_ip_with_hostmask(self.client)

        # Remove the client's hostmask from the rule
        self.master.run_command(['ipa', '-n', 'sudorule-remove-host',
                                 'testrule',
                                 '--hostmask', full_ip])

    def test_sudo_rule_restricted_to_one_hostmask_negative_setup(self):
        # Add the master's hostmask to the rule
        ip = self.master.ip
        self.master.run_command(['ipa', '-n', 'sudorule-add-host',
                                 'testrule',
                                 '--hostmask', '%s/32' % ip])

    def test_sudo_rule_restricted_to_one_hostmask_negative(self):
        result1 = self.list_sudo_commands("testuser1")
        assert result1.returncode != 0
        assert "Sorry, user testuser1 may not run sudo on {}.".format(
            self.clientname) in result1.stderr_text

    def test_sudo_rule_restricted_to_one_hostmask_negative_teardown(self):
        # Remove the master's hostmask from the rule
        ip = self.master.ip
        self.master.run_command(['ipa', '-n', 'sudorule-remove-host',
                                 'testrule',
                                 '--hostmask', '%s/32' % ip])

        # reset ldap_sudo_search_base back to the default value, the old
        # schema is not needed for the upcoming tests
        self.client_sssd_conf_backup.restore()

    def test_sudo_rule_restricted_to_one_command_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

        # Configure the rule to not allow any command
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--cmdcat='])

        # Add the yum command to the rule
        self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'])

    def test_sudo_rule_restricted_to_one_command(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: /usr/bin/yum" in result1.stdout_text

    def test_sudo_rule_restricted_to_command_and_command_group_setup(self):
        # Add the readers command group to the rule
        self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

    def test_sudo_rule_restricted_to_command_and_command_group(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD:" in result1.stdout_text
        assert "/usr/bin/yum" in result1.stdout_text
        assert "/bin/tail" in result1.stdout_text
        assert "/bin/cat" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_command(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_command_and_command_group_teardown(self):
        # Remove the yum command from the rule
        self.master.run_command(['ipa', 'sudorule-remove-allow-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'])

        # Remove the readers command group from the rule
        self.master.run_command(['ipa', 'sudorule-remove-allow-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

    def test_sudo_rule_restricted_to_running_as_single_user_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

        # Configure the rule to not allow running commands as anybody
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--runasusercat='])

        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--runasgroupcat='])

        # Allow running commands as testuser2
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--users', 'testuser2'])

    def test_sudo_rule_restricted_to_running_as_single_user(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: testuser2" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasuser(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_user_teardown(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--users', 'testuser2'])

    def test_sudo_rule_restricted_to_running_as_single_local_user_setup(self):
        # Allow running commands as testuser2
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--users', 'localuser'])

    def test_sudo_rule_restricted_to_running_as_single_local_user(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: localuser" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasuser_local(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_user_local_tear(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--users', 'localuser'])

    def test_sudo_rule_restricted_to_running_as_users_from_group_setup(self):
        # Allow running commands as users from testgroup2
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_running_as_users_from_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: %testgroup2" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasuser_group(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_users_from_group_teardown(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_run_as_users_from_local_group_setup(self):
        # Allow running commands as users from localgroup
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_sudo_rule_restricted_to_run_as_users_from_local_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: %localgroup" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_set_category_to_all_with_valid_entries_runasuser_group_local(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_run_as_users_from_local_group_tear(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_sudo_rule_restricted_to_running_as_single_group_setup(self):
        # Allow running commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-add-runasgroup',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_running_as_single_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: testuser1" in result1.stdout_text
        assert "RunAsGroups: testgroup2" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasgroup(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_group_teardown(self):
        # Remove permission to run commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-remove-runasgroup',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_running_as_single_local_group_setup(self):
        # Allow running commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-add-runasgroup',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_sudo_rule_restricted_to_running_as_single_local_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: testuser1" in result1.stdout_text
        assert "RunAsGroups: localgroup" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasgroup_local(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_local_group_tear(self):
        # Remove permission to run commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-remove-runasgroup',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_category_all_validation_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

    def test_category_all_validation_user(self):
        # Add the testuser1 to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-user',
                                          'testrule',
                                          '--users', 'testuser1'],
                                         raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_user_group(self):
        # Try to add the testgroup2 to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-user',
                                          'testrule',
                                          '--groups', 'testgroup2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_user_local(self):
        # Try to add the local user to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-user',
                                          'testrule',
                                          '--users', 'localuser'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_host(self):
        # Try to add the master to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-host',
                                          'testrule',
                                          '--hosts', self.master.hostname],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_host_group(self):
        # Try to add the testhostgroup to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-host',
                                          'testrule',
                                          '--hostgroups', 'testhostgroup'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_host_mask(self):
        # Try to add the client's /24 hostmask to the rule
        ip = self.client.ip
        result = self.master.run_command(['ipa', '-n', 'sudorule-add-host',
                                          'testrule',
                                          '--hostmask', '%s/24' % ip],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_command_allow(self):
        # Try to add the yum command to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                          'testrule',
                                          '--sudocmds', '/usr/bin/yum'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_command_allow_group(self):
        # Try to add the readers command group to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                          'testrule',
                                          '--sudocmdgroups', 'readers'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_command_deny(self):
        # Try to add the yum command to the rule
        # This SHOULD be allowed
        self.master.run_command(['ipa', 'sudorule-add-deny-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'],
                                 raiseonerr=False)

        self.master.run_command(['ipa', 'sudorule-remove-deny-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'],
                                 raiseonerr=False)

    def test_category_all_validation_command_deny_group(self):
        # Try to add the readers command group to the rule
        # This SHOULD be allowed
        self.master.run_command(['ipa', 'sudorule-add-deny-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

        self.master.run_command(['ipa', 'sudorule-remove-deny-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

    def test_category_all_validation_runasuser(self):
        # Try to allow running commands as testuser2
        result = self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                          'testrule',
                                          '--users', 'testuser2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_runasuser_group(self):
        # Try to allow running commands as users from testgroup2
        result = self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                          'testrule',
                                          '--groups', 'testgroup2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_runasgroup(self):
        # Try to allow running commands as testgroup2
        result = self.master.run_command(['ipa', 'sudorule-add-runasgroup',
                                          'testrule',
                                          '--groups', 'testgroup2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_domain_resolution_order(self):
        """Test sudo with runAsUser and domain resolution order.

        Regression test for bug https://pagure.io/SSSD/sssd/issue/3957.
        Running commands with sudo as specific user should succeed
        when sudo rule has ipasudorunas field defined with value of that user
        and domain-resolution-order is defined in ipa config.
        """
        self.master.run_command(
            ['ipa', 'config-mod', '--domain-resolution-order',
             self.domain.name])
        try:
            # prepare the sudo rule: set only one user for ipasudorunas
            self.reset_rule_categories()
            self.master.run_command(
                ['ipa', 'sudorule-mod', 'testrule',
                 '--runasgroupcat=', '--runasusercat='],
                raiseonerr=False
            )
            self.master.run_command(
                ['ipa', 'sudorule-add-runasuser', 'testrule',
                 '--users', 'testuser2'])

            # check that testuser1 is allowed to run commands as testuser2
            # according to listing of allowed commands
            result = self.list_sudo_commands('testuser1')
            expected_rule = ('(testuser2@%s) NOPASSWD: ALL'
                             % self.domain.name)
            assert expected_rule in result.stdout_text

            # check that testuser1 can actually run commands as testuser2
            self.client.run_command(
                ['su', 'testuser1', '-c', 'sudo -u testuser2 true'])
        finally:
            self.master.run_command(
                ['ipa', 'config-mod', '--domain-resolution-order='])


class TestSudo_Functional(IntegrationTest):
    """
    Test Sudo Functional
    """
    num_clients = 1

    @classmethod
    def install(cls, mh):
        super(TestSudo_Functional, cls).install(mh)

        extra_args = ["--idstart=60001", "--idmax=65000"]
        install_master(cls.master, setup_dns=True, extra_args=extra_args)
        install_client(cls.master, cls.clients[0])

        cls.client = cls.clients[0]
        cls.clientname = cls.client.run_command(
            ['hostname', '-s']).stdout_text.strip()
        cls.user_password = "Secret123!"
        adduser_stdin_text = "%s\n%s\n" % (cls.user_password,
                                           cls.user_password)

        for i in range(1, 3):
            cls.master.run_command(['ipa', 'user-add',
                                 'testuser%d' % i,
                                 '--first', 'Test',
                                 '--last', 'User%d' % i,
                                 '--password'],
                                stdin_text=adduser_stdin_text)

    def list_sudo_commands(self, user, raiseonerr=False, verbose=False, password=None):
        clear_sssd_cache(self.client)
        list_flag = '-ll' if verbose else '-l'

        if password:
            # allow sudo to prompt, send password
            cmd = f'su -c "sudo {list_flag} -S" {user}'
            return self.client.run_command(
                cmd,
                stdin_text=password + "\n",
                raiseonerr=raiseonerr
            )
        else:
            # keep current non-interactive behavior
            cmd = f'su -c "sudo {list_flag} -n" {user}'
            return self.client.run_command(
                cmd,
                raiseonerr=raiseonerr
            )

    def list_sudo_commands(self, user, raiseonerr=False, verbose=False):
        clear_sssd_cache(self.client)
        list_flag = '-ll' if verbose else '-l'
        return self.client.run_command(
            'su -c "sudo %s -n" %s' % (list_flag, user),
            raiseonerr=raiseonerr)

    def bug711786(self):
        master = self.master

        master.run_command(["ipa", "user-add", "pranav",
                            "--first=pranav", "--last=thube"])
        master.run_command(["ipa", "sudorule-add", "rule1"])
        master.run_command(["ipa", "sudorule-add-runasuser", "rule1",
                            "--users=pranav"])

        result = master.run_command([
            "/usr/bin/ldapsearch", "-x", "-h", master.hostname,
            "-D", master.config.dirman_dn,
            "-w", master.config.dirman_password,
            "-b", f"cn=rule1,ou=sudoers,{master.config.basedn}"
        ])

        content = result.stdout_text
        assert not re.search(r"sudorunasgroup:.*pranav", content)

        master.run_command(["ipa", "sudorule-del", "rule1"])
        master.run_command(["ipa", "user-del", "shanks"])


    def test_sudorule_add_allow_command_func001(self):
        master = self.master
        user1 = "testuser1"
        client = self.clients[0].hostname
        kinit_admin(self.master)

        master.run_command(["ipa", "sudocmdgroup-del", "sudogrp1"], raiseonerr=False)
        master.run_command(["ipa", "sudorule-del", "sudorule1"], raiseonerr=False)

        for cmd in ["/bin/mkdir", "/bin/date", "/bin/df", "/bin/touch", "/bin/rm", "/bin/uname", "/bin/hostname", "/bin/rmdir"]:
            master.run_command(["ipa", "sudocmd-add", cmd])

        master.run_command(["ipa", "sudocmdgroup-add", "sudogrp1", "--desc=sudogrp1"])
        master.run_command([
            "ipa", "sudocmdgroup-add-member", "sudogrp1",
            "--sudocmds=/bin/date", "--sudocmds=/bin/touch", "--sudocmds=/bin/uname"
        ])
        master.run_command(["ipa", "sudorule-add", "sudorule1"])
        master.run_command(["ipa", "sudorule-add-option", "--sudooption=!authenticate", "sudorule1"])
        master.run_command(["ipa", "sudorule-add-host", "sudorule1", "--hosts", client])
        master.run_command(["ipa", "sudorule-add-user", "sudorule1", "--users", user1])
        master.run_command(["ipa", "sudorule-add-allow-command", "--sudocmds=/bin/mkdir", "sudorule1"])
        master.run_command(["ipa", "sudorule-find", "sudorule1"])

        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "/bin/mkdir" in result.stdout_text

    def test_sudorule_add_allow_commandgrp_func001(self):
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-allow-command", "--sudocmdgroups=sudogrp1", "sudorule1"])
        master.run_command(["ipa", "sudorule-show", "sudorule1"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "User {} may run the following commands".format(user1) in result.stdout_text
        assert all(cmd in result.stdout_text for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"])


    def test_sudorule_remove_allow_command_func001(self):
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-allow-command", "--sudocmds=/bin/mkdir", "sudorule1"])

        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "/bin/mkdir" not in result.stdout_text
        assert all(cmd in result.stdout_text for cmd in ["/bin/uname", "/bin/touch", "/bin/date"])

    def test_sudorule_remove_allow_commandgrp_func001(self):
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-find", "sudorule1"])
        master.run_command(["ipa", "sudorule-remove-allow-command", "--sudocmdgroups=sudogrp1", "sudorule1"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "/bin/mkdir" not in result.stdout_text

    def test_sudorule_add_deny_command_func001(self):
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-deny-command", "--sudocmds=/bin/mkdir", "sudorule1"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "User {} may run the following commands".format(user1) in result.stdout_text
        assert "!/bin/mkdir" in result.stdout_text

    def test_sudorule_remove_deny_command_func001(self):
        """
        Test case: Remove command from denied command for sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-deny-command", "--sudocmds=/bin/mkdir", "sudorule1"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "!/bin/mkdir" not in result.stdout_text

    def test_sudorule_add_deny_commandgrp_func001(self):
        """
        Test case: Add command group to denied commands for sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-deny-command", "--sudocmdgroups=sudogrp1", "sudorule1"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "User {} may run the following commands".format(user1) in result.stdout_text
        assert all(cmd in result.stdout_text for cmd in ["!/bin/uname", "!/bin/touch", "!/bin/date"])

    def test_sudorule_remove_deny_commandgrp_func001(self):
        """
        Test case: Remove command group from denied commands for sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-deny-command", "--sudocmdgroups=sudogrp1", "sudorule1"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "!/bin/mkdir" not in result.stdout_text

    def test_sudorule_add_host_func001(self):
        """
        Test case: Adding host and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-host", "sudorule1", "--hosts=test.example.com"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "sudo: ldap sudoHost 'test.example.com' ... not" in result.stdout_text

    def test_sudorule_remove_host_func001(self):
        """
        Test case: Removing host and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-host", "sudorule1", "--hosts=test.example.com"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "sudo: ldap sudoHost 'test.example.com' ... not" not in result.stdout_text

    def test_sudorule_add_hostgrp_func001(self):
        """
        Test case: Adding hostgroup and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "hostgroup-add", "hostgrp1", "--desc=test_hostgrp"])
        master.run_command(["ipa", "hostgroup-add-member", "hostgrp1", "--hosts=" + self.client.hostname])  # Replace with actual client
        master.run_command(["ipa", "sudorule-add-allow-command", "--sudocmds=/bin/mkdir", "sudorule1"])
        master.run_command(["ipa", "sudorule-remove-host", "sudorule1", "--hosts=" + self.client.hostname])
        master.run_command(["ipa", "sudorule-add-host", "sudorule1", "--hostgroup=hostgrp1"])

        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "/bin/mkdir" in result.stdout_text
        assert "User {} is not allowed to run sudo".format(user1) not in result.stdout_text, "Failing because of https://bugzilla.redhat.com/show_bug.cgi?id=923753"

    def test_sudorule_remove_hostgrp_func001(self):
        """
        Test case: Removing hostgroup and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-host", "sudorule1", "--hostgroup=hostgrp1"])
        master.run_command(["ipa", "hostgroup-del", "hostgrp1"])

        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "Sorry, user {} may not run sudo on".format(user1) in result.stdout_text
        master.run_command(["ipa", "sudorule-add-host", "sudorule1", "--hosts=" + self.client.hostname])

    def test_sudorule_add_option_func001(self):
        """
        Test case: Adding sudo option sudolog and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-option", "sudorule1", "--sudooption=logfile=/var/log/sudolog"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        time.sleep(180)
        assert "/var/log/sudolog" in result.stdout_text

    def test_sudorule_add_option_func002(self):
        """
        Test case: Adding sudo option env_keep and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-option", "sudorule1", "--sudooption='env_keep = LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE'"])

        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        time.sleep(180)
        assert "env_keep" in result.stdout_text


    def test_sudorule_remove_option_sudolog(self):
        """
        Test case: Remove sudo option sudolog and verify from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-option", "sudorule1", "--sudooption=logfile=/var/log/sudolog"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "logfile=/var/log/sudolog" not in result.stdout_text

    def test_sudorule_remove_option_env_keep(self):
        """
        Test case: Remove sudo option env_keep and verify from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command([
            "ipa", "sudorule-remove-option", "sudorule1",
            "--sudooption='env_keep = LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE'"
        ])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "env_keep" not in result.stdout_text

    def test_sudorule_remove_option_authenticate(self):
        """
        Test case: Remove sudo option authenticate and verify from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-option", "sudorule1", "--sudooption='!authenticate'"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands_wo_passwd(user1, verbose=True)
        assert "(root) NOPASSWD: /bin/mkdir" not in result.stdout_text

    def test_sudorule_add_runasuser(self):
        """
        Test case: Adding RunAs user and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-runasuser", "sudorule1", "--users={}".format(user2)])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        #assert all(cmd in result.stdout_text for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"])
        assert "({}) /bin/uname, /bin/touch, /bin/date, /bin/mkdir".format(user2) in result.stdout_text

    def test_sudorule_remove_runasuser(self):
        """
        Test case: Removing RunAs user and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-runasuser", "sudorule1", "--users={}".format(user2)])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "({}) /bin/mkdir, /bin/date, /bin/touch, /bin/uname".format(user2) not in result.stdout_text

    def test_sudorule_add_runasgroup(self):
        """
        Test case: Adding RunAs group and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-runasuser", "sudorule1", "--groups={}".format(user2)])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "(%{}) /bin/uname, /bin/touch, /bin/date, /bin/mkdir".format(user2) in result.stdout_text

    def test_sudorule_remove_runasgroup(self):
        """
        Test case: Removing RunAs group and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-runasuser", "sudorule1", "--groups={}".format(user2)])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "(%{}) /bin/mkdir, /bin/date, /bin/touch, /bin/uname".format(user2) not in result.stdout_text

    def test_sudorule_add_multiple_runasusers(self):
        """
        Test case: "Adding comma separated list of RunAs user and verifying from sudo client"
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        user3 = "testuser3"
        kinit_admin(self.master)

        master.run_command([
                "ipa", "sudorule-add-runasuser", "sudorule1",
                "--users", user2,
                "--users", user3
            ])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "({},{}) /bin/uname, /bin/touch, /bin/date, /bin/mkdir".format(user2, user3) in result.stdout_text

    def test_sudorule_remove_multiple_runasusers(self):
        """
        Test case: "Removing comma separated list of RunAs user and verifying from sudo client"
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        user3 = "testuser3"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-runasuser", "sudorule1", "--users={}".format(",".join([user2, user3]))])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "({},{}) /bin/mkdir, /bin/date, /bin/touch, /bin/uname".format(user2, user3) not in result.stdout_text

    def test_sudorule_add_runasuser_func004(self):
        """
        Test case: Adding comma separated list of RunAs group and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        user3 = "testuser3"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-runasuser", "sudorule1", "--groups={}".format(",".join([user2, user3]))])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "({},{}) /bin/uname, /bin/touch, /bin/date, /bin/mkdir".format(user2, user3) in result.stdout_text

    def test_sudorule_remove_runasuser_func004(self):
        """
        Test case: Removing comma separated list of RunAs group and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        user3 = "testuser3"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-remove-runasuser", "sudorule1", "--groups={}".format(",".join([user2, user3]))])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "({},{}) /bin/mkdir, /bin/date, /bin/touch, /bin/uname".format(user2, user3) not in result.stdout_text

    def test_sudorule_add_runasuser_func005(self):
        """
        Test case: Adding RunAs user with 'ALL' as a special value should fail (bz719009)
        """
        master = self.master
        kinit_admin(self.master)

        result = master.run_command(["ipa", "sudorule-add-runasuser", "sudorule1", "--users=ALL"], raiseonerr=False)
        assert "ERROR: invalid 'runas-user': RunAsUser does not accept 'ALL' as a user name" in result.stdout_text

    def test_sudorule_remove_runasuser_func005(self):
        """
        Test case: Removing RunAs user with 'ALL' from sudo rule and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        user2 = "testuser2"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-runasuser", "sudorule1", "--users=ALL"])
        master.run_command(["ipa", "sudorule-remove-runasuser", "sudorule1", "--users=ALL"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.sudo_run_with_user(user1, user2, password=self.user_password)
        assert "sudo: ldap sudoRunAsUser 'all' ... MATCH" not in result.stdout_text
        assert "sudo: host_matches=1" in result.stdout_text

    def test_sudorule_add_runasgroup_func001(self):
        """
        Test case: Adding RunAs group with 'ALL' should fail (bz719009)
        """
        master = self.master
        kinit_admin(self.master)

        # Attempt to add RunAs group with ALL (should fail)
        error_msg = master.run_command(["ipa", "sudorule-add-runasgroup", "sudorule1", "--groups=ALL"], raiseonerr=False)
        assert "ERROR: invalid 'runas-group': RunAsGroup does not accept 'ALL' as a group name" in error_msg.stdout_text

    def test_sudorule_remove_runasgroup_func001(self):
        """
        Test case: Removing RunAs group with 'ALL' and verifying from sudo client
        """
        master = self.master
        user1 = "testuser1"
        kinit_admin(self.master)

        master.run_command(["ipa", "sudorule-add-runasgroup", "sudorule1", "--groups=ALL"])
        master.run_command(["ipa", "sudorule-remove-runasgroup", "sudorule1", "--groups=ALL"])
        master.run_command(["rm", "-rf", "/var/lib/sss/db/*"])
        master.run_command(["systemctl", "restart", "sssd"])
        master.run_command(["sleep", "3"])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(user1, verbose=True)
        assert "sudo: ldap sudoRunAsGroup 'all'" not in result.stdout_text
