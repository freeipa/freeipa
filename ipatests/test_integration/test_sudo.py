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
import re
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.tasks import (
    clear_sssd_cache, get_host_ip_with_hostmask, remote_sssd_config,
    FileBackup, install_master, install_client, kinit_admin,
    create_active_user, ldapsearch_dm, stop_ipa_server,
    start_ipa_server, kinit_as_user)

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

    # Define constants for reuse
    SUDO_RULE = "sudorule1"
    USER_1 = "testuser1"
    USER_2 = "testuser2"
    USER_3 = "testuser3"
    SUDO_GROUP = "sudogrp1"
    HOST_GROUP = "hostgrp1"
    GROUP = "testgroup"

    @classmethod
    def install(cls, mh):
        super(TestSudo_Functional, cls).install(mh)

        extra_args = ["--idstart=60001", "--idmax=65000"]
        install_master(cls.master, setup_dns=True, extra_args=extra_args)
        install_client(cls.master, cls.clients[0])

        cls.client = cls.clients[0]
        cls.user_password = "Secret123!"

        for username in [cls.USER_1, cls.USER_2, cls.USER_3]:
            create_active_user(
                cls.master,
                username,
                password=cls.user_password
            )

    def list_sudo_commands(
            self, user, raiseonerr=False, verbose=False,
            skip_kinit=False, skip_sssd_cache_clear=False,
            skip_password=False):
        """
        List sudo commands for a given user.

        - If skip_password=False (default), the function uses the command
        `echo <password> | sudo -S -l`.
        - If skip_password=True, it uses `sudo -l -n` (non-interactive, no
        password).
        - The verbose flag (-ll) can be used to get more detailed sudo output.
        """
        list_flag = '-ll' if verbose else '-l'

        if not skip_sssd_cache_clear:
            clear_sssd_cache(self.client)
        if not skip_kinit:
            kinit_as_user(self.client, user, self.user_password)

        if skip_password:
            cmd = f'su -c "sudo {list_flag} -n" {user}'
        else:
            cmd = (
                f'su -c "echo {self.user_password} | '
                f'sudo {list_flag} -S" {user}'
            )

        return self.client.run_command(cmd, raiseonerr=raiseonerr)

    def run_as_sudo_user(
            self, command, sudo_user, su_user, raiseonerr=False,
            skip_kinit=False, skip_sssd_cache_clear=False,
            skip_password=False):
        """
        Run a command as 'sudo_user' through 'su' to 'su_user'.

        Parameters:
        - command: str, the command to execute
        - sudo_user: str, the user to run the command as via sudo (-u)
        - su_user: str, the user to switch to via su
        - skip_password: bool, if True, run sudo non-interactively (-n)
        without providing password. If False, provide password via -S.
        - raiseonerr: bool, whether to raise an exception on non-zero exit.
        """
        if not skip_sssd_cache_clear:
            clear_sssd_cache(self.client)
        if not skip_kinit:
            kinit_as_user(self.client, su_user, self.user_password)

        if skip_password:
            cmd = f'su -c "sudo -u {sudo_user} -n {command}" {su_user}'
        else:
            cmd = (
                f'su -c "echo {self.user_password} | '
                f'sudo -u {sudo_user} -S {command}" {su_user}'
            )

        return self.client.run_command(cmd, raiseonerr=raiseonerr)

    def run_as_sudo_group(
            self, command, sudo_group, su_user, raiseonerr=False,
            skip_kinit=False, skip_sssd_cache_clear=False,
            skip_password=False):
        """
        Run a command as 'sudo_group' through 'su' to 'su_user'.

        Parameters:
        - command: str, the command to execute
        - sudo_group: str, the group to run the command as via sudo (-g)
        - su_user: str, the user to switch to via su
        - skip_password: bool, if True, run sudo non-interactively (-n)
        without providing password. If False, provide password via -S.
        - raiseonerr: bool, whether to raise an exception on non-zero exit.

        Returns:
        - Result from self.client.run_command()
        """
        if not skip_sssd_cache_clear:
            clear_sssd_cache(self.client)
        if not skip_kinit:
            kinit_as_user(self.client, su_user, self.user_password)

        if skip_password:
            cmd = f'su -c "sudo -g {sudo_group} -n {command}" {su_user}'
        else:
            cmd = (
                f'su -c "echo {self.user_password} | '
                f'sudo -g {sudo_group} -S {command}" {su_user}'
            )

        return self.client.run_command(cmd, raiseonerr=raiseonerr)

    def setup_sudo_rule(
            self, master, client, user, rule_name,
            group_name, allowed_command):
        """
        Common helper to set up a sudo rule with the same flow as the test:
        1. Add sudo commands
        2. Create sudo command group and add members
        3. Create sudo rule
        4. Add !authenticate option
        5. Add host, user, and allowed command (variable)
        """
        kinit_admin(master)

        cmds = [
            "/bin/mkdir", "/bin/date", "/bin/df", "/bin/touch", "/bin/rm",
            "/bin/uname", "/bin/hostname", "/bin/rmdir"
        ]
        for cmd in cmds:
            master.run_command(["ipa", "sudocmd-add", cmd])
        master.run_command([
            "ipa", "sudocmdgroup-add", group_name, "--desc=sudogrp1"
        ])
        master.run_command([
            "ipa", "sudocmdgroup-add-member", group_name,
            "--sudocmds=/bin/date", "--sudocmds=/bin/touch",
            "--sudocmds=/bin/uname"
        ])
        master.run_command(["ipa", "sudorule-add", rule_name])
        master.run_command([
            "ipa", "sudorule-add-host", rule_name, "--hosts", client
        ])
        master.run_command([
            "ipa", "sudorule-add-user", rule_name, "--users", user
        ])
        master.run_command([
            "ipa", "sudorule-add-allow-command",
            f"--sudocmds={allowed_command}", rule_name
        ])

    def test_sudorule_add_allow_command_func001(self):
        master = self.master
        client = self.clients[0].hostname
        kinit_admin(master)

        self.setup_sudo_rule(
            master=master,
            client=client,
            user=self.USER_1,
            rule_name=self.SUDO_RULE,
            group_name=self.SUDO_GROUP,
            allowed_command="/bin/mkdir"
        )
        clear_sssd_cache(self.client)
        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert re.search(r'(?<!!)/bin/mkdir', result.stdout_text)

    def test_sudorule_add_allow_commandgrp_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command",
            f"--sudocmdgroups={self.SUDO_GROUP}", self.SUDO_RULE
        ])
        master.run_command(["ipa", "sudorule-show", self.SUDO_RULE])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert (f"User {self.USER_1} may run the following commands"
                ) in result.stdout_text
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"]:
            assert cmd in result.stdout_text

    def test_sudorule_remove_allow_command_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-allow-command", "--sudocmds=/bin/mkdir",
            self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert "/bin/mkdir" not in result.stdout_text
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date"]:
            assert cmd in result.stdout_text

    def test_sudorule_remove_allow_commandgrp_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "sudorule-find", self.SUDO_RULE])
        master.run_command([
            "ipa", "sudorule-remove-allow-command",
            f"--sudocmdgroups={self.SUDO_GROUP}",
            self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert "/bin/mkdir" not in result.stdout_text

    def test_sudorule_add_deny_command_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-deny-command", "--sudocmds=/bin/mkdir",
            self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert (f"User {self.USER_1} may run the following commands"
                ) in result.stdout_text
        assert re.search(r'!/bin/mkdir', result.stdout_text)

    def test_sudorule_remove_deny_command_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-deny-command", "--sudocmds=/bin/mkdir",
            self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert not re.search(r'!/bin/mkdir', result.stdout_text)

    def test_sudorule_add_deny_commandgrp_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-deny-command",
            f"--sudocmdgroups={self.SUDO_GROUP}", self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1)
        assert (f"User {self.USER_1} may run the following commands"
                ) in result.stdout_text
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date"]:
            assert f"!{cmd}" in result.stdout_text

    def test_sudorule_remove_deny_commandgrp_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-deny-command",
            f"--sudocmdgroups={self.SUDO_GROUP}", self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1)
        assert not re.search(r'!/bin/mkdir', result.stdout_text)

    def test_sudorule_add_hostgrp_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "hostgroup-add", self.HOST_GROUP,
                            "--desc=test_hostgrp"])
        master.run_command([
            "ipa", "hostgroup-add-member", self.HOST_GROUP,
            "--hosts=" + self.client.hostname
        ])
        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/mkdir",
            self.SUDO_RULE
        ])
        master.run_command([
            "ipa", "sudorule-remove-host", self.SUDO_RULE,
            "--hosts=" + self.client.hostname
        ])
        master.run_command([
            "ipa", "sudorule-add-host", self.SUDO_RULE,
            f"--hostgroup={self.HOST_GROUP}"
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1)
        assert "/bin/mkdir" in result.stdout_text
        assert (f"User {self.USER_1} is not allowed to run sudo"
                ) not in result.stdout_text

    def test_sudorule_remove_hostgrp_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-host", self.SUDO_RULE,
            f"--hostgroup={self.HOST_GROUP}"
        ])
        master.run_command(["ipa", "hostgroup-del", self.HOST_GROUP])
        clear_sssd_cache(self.client)
        clear_sssd_cache(master)

        result = self.list_sudo_commands(self.USER_1)
        assert (f"Sorry, user {self.USER_1} may not run sudo on client"
                ) in result.stderr_text
        master.run_command([
            "ipa", "sudorule-add-host", self.SUDO_RULE,
            "--hosts=" + self.client.hostname
        ])

    def test_sudorule_add_option_func001(self):
        master = self.master
        kinit_admin(master)
        master.run_command([
            'ipa', 'sudorule-add-option', self.SUDO_RULE,
            '--sudooption', "!authenticate"
        ])
        clear_sssd_cache(master)
        clear_sssd_cache(self.client)
        result = self.list_sudo_commands(self.USER_1, skip_password=True)
        assert re.search(r"\(root\) NOPASSWD.*?/bin/mkdir", result.stdout_text)

    def test_sudorule_remove_option_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            'ipa', 'sudorule-remove-option', self.SUDO_RULE,
            '--sudooption', "!authenticate"
        ])
        clear_sssd_cache(master)
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1)
        assert "(root) NOPASSWD: /bin/mkdir" not in result.stdout_text

    # ----------------------
    # RunAs user/group tests
    # ----------------------
    def test_sudorule_add_runasuser_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command",
            f"--sudocmdgroups={self.SUDO_GROUP}", self.SUDO_RULE
        ])
        master.run_command([
            "ipa", "sudorule-add-runasuser", self.SUDO_RULE,
            f"--users={self.USER_2}"
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert f"RunAsUsers: {self.USER_2}" in result.stdout_text
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"]:
            assert cmd in result.stdout_text

    def test_sudorule_remove_runasuser_func001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-runasuser", self.SUDO_RULE,
            f"--users={self.USER_2}"
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert f"RunAsUsers: {self.USER_2}" not in result.stdout_text

    def test_sudorule_add_runasuser_func002(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-runasuser", self.SUDO_RULE,
            f"--groups={self.USER_2}"
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert f"RunAsUsers: %{self.USER_2}" in result.stdout_text
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"]:
            assert cmd in result.stdout_text

    def test_sudorule_remove_runasuser_func002(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-runasuser", self.SUDO_RULE,
            f"--groups={self.USER_2}"
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert f"RunAsUsers: {self.USER_2}" not in result.stdout_text

    def test_sudorule_add_runasuser_func003(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-runasuser", self.SUDO_RULE,
            "--users", self.USER_2, "--users", self.USER_3
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert (
            f"RunAsUsers: {self.USER_2}, {self.USER_3}"
            in result.stdout_text
        )
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"]:
            assert cmd in result.stdout_text

    def test_sudorule_remove_runasuser_func003(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-runasuser", self.SUDO_RULE,
            "--users", self.USER_2, "--users", self.USER_3
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert (
            f"RunAsUsers: {self.USER_2}, {self.USER_3}"
            not in result.stdout_text
        )

    def test_sudorule_add_runasuser_func004(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-runasuser", self.SUDO_RULE,
            "--groups", self.USER_2, "--groups", self.USER_3
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert (
            f"RunAsUsers: %{self.USER_2}, %{self.USER_3}"
            in result.stdout_text
        )
        for cmd in ["/bin/uname", "/bin/touch", "/bin/date", "/bin/mkdir"]:
            assert cmd in result.stdout_text

    def test_sudorule_remove_runasuser_func004(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-remove-runasuser", self.SUDO_RULE,
            "--groups", self.USER_2, "--groups", self.USER_3
        ])
        clear_sssd_cache(self.client)

        result = self.list_sudo_commands(self.USER_1, verbose=True)
        assert (
            f"RunAsUsers: %{self.USER_2}, %{self.USER_3}"
            not in result.stdout_text
        )

    def test_sudorule_add_runasuser_func005(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command([
            "ipa", "sudorule-add-runasuser", self.SUDO_RULE, "--users=ALL"
        ], raiseonerr=False)
        assert ("ERROR: invalid 'runas-user': RunAsUser does not accept 'ALL' "
                "as a user name") in result.stderr_text

    def test_sudorule_add_runasgroup_func001(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command([
            "ipa", "sudorule-add-runasgroup", self.SUDO_RULE,
            "--groups=ALL"
        ], raiseonerr=False)
        assert (
            "ERROR: invalid 'runas-group': RunAsGroup does not accept 'ALL' "
            "as a group name"
        ) in result.stderr_text

    # ----------------------
    # Sudo disable/enable
    # ----------------------
    def test_sudorule_disable_func001(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command(["ipa", "sudorule-show", self.SUDO_RULE])
        master.run_command(["ipa", "sudorule-disable", self.SUDO_RULE])
        master.run_command(["ipa", "sudocmd-add", "/bin/newcmd"])
        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/newcmd",
            self.SUDO_RULE
        ])
        clear_sssd_cache(master)
        clear_sssd_cache(self.client)
        result = self.list_sudo_commands(self.USER_1)
        assert not re.search(r"\(root\).*?/bin/newcmd", result.stdout_text)

        master.run_command(["ipa", "sudorule-enable", self.SUDO_RULE])
        clear_sssd_cache(self.client)
        result = self.list_sudo_commands(self.USER_1)
        assert (
            "(root) /bin/uname, /bin/touch, "
            "/bin/date, /bin/newcmd, /bin/mkdir"
            in result.stdout_text
        )

    # ----------------------
    # Cleanup
    # ----------------------
    def test_cleanup(self):
        master = self.master
        kinit_admin(master)

        # Delete sudo command group
        master.run_command(["ipa", "sudocmdgroup-del", self.SUDO_GROUP],
                           raiseonerr=False)
        # Delete sudo rule
        master.run_command(["ipa", "sudorule-del", self.SUDO_RULE],
                           raiseonerr=False)
        # Delete sudo commands
        sudo_commands = [
            "/bin/mkdir", "/bin/date", "/bin/df", "/bin/touch", "/bin/rm",
            "/bin/uname", "/bin/hostname", "/bin/rmdir", "/bin/newcmd"
        ]
        for cmd in sudo_commands:
            master.run_command(["ipa", "sudocmd-del", cmd], raiseonerr=False)
        clear_sssd_cache(self.master)

    # ----------------------
    # Offline client caching functional test
    # ----------------------
    def test_001_sudorule_offline_caching_allow_command(self):
        master = self.master
        client = self.clients[0].hostname
        kinit_admin(master)

        self.setup_sudo_rule(
            master=master,
            client=client,
            user=self.USER_1,
            rule_name=self.SUDO_RULE,
            group_name=self.SUDO_GROUP,
            allowed_command="/bin/date"
        )
        clear_sssd_cache(master)
        clear_sssd_cache(self.client)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(self.USER_1,
                                         skip_sssd_cache_clear=True)
        assert "(root) /bin/date" in result.stdout_text

        stop_ipa_server(master)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_kinit=True, skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True
        )
        assert "(root) /bin/date" in result.stdout_text

        start_ipa_server(master)
        master.run_command([
            "ipa", "sudorule-remove-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])

    def test_002_sudorule_offline_caching_deny_command(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-deny-command", "--sudocmds=/bin/uname",
            self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)
        clear_sssd_cache(master)
        result = self.run_as_sudo_user(
            "uname", sudo_user="root", su_user=self.USER_1,
            skip_sssd_cache_clear=True)

        result = self.list_sudo_commands(self.USER_1,
                                         skip_sssd_cache_clear=True)
        assert "(root) !/bin/uname" in result.stdout_text

        stop_ipa_server(master)
        self.run_as_sudo_user(
            "uname", sudo_user="root", su_user=self.USER_1,
            skip_kinit=True, skip_sssd_cache_clear=True)

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True
        )
        assert "(root) !/bin/uname" in result.stdout_text

        start_ipa_server(master)
        master.run_command([
            "ipa", "sudorule-remove-deny-command", "--sudocmds=/bin/uname",
            self.SUDO_RULE
        ])

    def test_003_sudorule_offline_caching_runasuser_command(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])

        master.run_command([
            "ipa", "sudorule-add-runasuser", self.SUDO_RULE,
            f"--users={self.USER_2}"
        ])
        clear_sssd_cache(master)
        clear_sssd_cache(self.client)
        result = self.run_as_sudo_user(
            "date", sudo_user=self.USER_2, su_user=self.USER_1,
            skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_sssd_cache_clear=True)
        assert f"({self.USER_2}) /bin/date" in result.stdout_text

        stop_ipa_server(master)
        result = self.run_as_sudo_user(
            "date", sudo_user=self.USER_2, su_user=self.USER_1,
            skip_kinit=True, skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True
        )
        assert f"({self.USER_2}) /bin/date" in result.stdout_text

        start_ipa_server(master)
        master.run_command([
            "ipa", "sudorule-remove-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])

        master.run_command([
            "ipa", "sudorule-remove-runasuser", self.SUDO_RULE,
            f"--users={self.USER_2}"
        ])

    def test_005_sudorule_offline_caching_hostgroup_command(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])
        master.run_command([
            "ipa", "hostgroup-add", "--desc=testhostgroup",
            self.HOST_GROUP
        ])
        master.run_command([
            "ipa", "sudorule-remove-host", self.SUDO_RULE,
            "--hosts=" + self.client.hostname
        ])
        master.run_command([
            "ipa", "hostgroup-add-member", self.HOST_GROUP,
            "--hosts=" + self.client.hostname
        ])
        master.run_command([
            "ipa", "sudorule-add-host", self.SUDO_RULE,
            f"--hostgroup={self.HOST_GROUP}"
        ])
        master.run_command([
            "ipa", "sudorule-add-user", self.SUDO_RULE,
            "--users", self.USER_1], raiseonerr=False
        )
        clear_sssd_cache(self.client)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(self.USER_1,
                                         skip_sssd_cache_clear=True)
        assert "(root) /bin/date" in result.stdout_text

        stop_ipa_server(master)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_kinit=True, skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True
        )
        assert "(root) /bin/date" in result.stdout_text

        start_ipa_server(master)
        kinit_admin(master)
        master.run_command([
            "ipa", "sudorule-remove-allow-command",
            "--sudocmds=/bin/date", self.SUDO_RULE
        ])
        master.run_command([
            "ipa", "sudorule-remove-host", self.SUDO_RULE,
            f"--hostgroup={self.HOST_GROUP}"
        ])
        master.run_command([
            "ipa", "hostgroup-remove-member", self.HOST_GROUP,
            "--hosts=" + self.client.hostname
        ])
        master.run_command(["ipa", "hostgroup-del", self.HOST_GROUP])
        master.run_command([
            "ipa", "sudorule-add-host", self.SUDO_RULE,
            f"--hosts=" + self.client.hostname
        ])

    def test_006_sudorule_offline_caching_group_command(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])
        master.run_command([
            "ipa", "sudorule-remove-user", self.SUDO_RULE,
            "--users", self.USER_1], raiseonerr=False
        )
        master.run_command([
            "ipa", "group-add", "--desc=testgroup", self.GROUP
        ])
        master.run_command([
            "ipa", "group-add-member", self.GROUP,
            f"--users={self.USER_1}"
        ])
        master.run_command([
            "ipa", "sudorule-add-user", self.SUDO_RULE,
            f"--groups={self.GROUP}"], raiseonerr=False
        )
        clear_sssd_cache(self.client)

        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(self.USER_1,
                                         skip_sssd_cache_clear=True)
        assert "(root) /bin/date" in result.stdout_text

        stop_ipa_server(master)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_kinit=True, skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True
        )
        assert "(root) /bin/date" in result.stdout_text

        start_ipa_server(master)
        kinit_admin(master)
        master.run_command([
            "ipa", "sudorule-remove-allow-command",
            "--sudocmds=/bin/date", self.SUDO_RULE
        ])
        master.run_command([
            "ipa", "sudorule-remove-user", self.SUDO_RULE,
            f"--groups={self.GROUP}"], raiseonerr=False
        )
        master.run_command([
            "ipa", "sudorule-add-user", self.SUDO_RULE,
            f"--users={self.USER_1}"], raiseonerr=False
        )
        master.run_command([
            "ipa", "group-remove-member", self.GROUP,
            f"--users={self.USER_1}"
        ])
        master.run_command([
            "ipa", "group-del", self.GROUP])

    def test_007_sudorule_offline_caching_option_command(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])
        master.run_command([
            'ipa', 'sudorule-add-option', self.SUDO_RULE,
            '--sudooption', "!authenticate"
        ])
        clear_sssd_cache(self.client)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_password=True, skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(self.USER_1,
                                         skip_sssd_cache_clear=True)
        assert "(root) NOPASSWD: /bin/date" in result.stdout_text

        stop_ipa_server(master)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_password=True, skip_kinit=True,
            skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True)
        assert "(root) NOPASSWD: /bin/date" in result.stdout_text

        start_ipa_server(master)
        kinit_admin(master)
        master.run_command([
            'ipa', 'sudorule-remove-option', self.SUDO_RULE,
            '--sudooption', "!authenticate"
        ])
        master.run_command([
            "ipa", "sudorule-remove-allow-command",
            "--sudocmds=/bin/date", self.SUDO_RULE
        ])
        clear_sssd_cache(self.client)
        clear_sssd_cache(master)

    def test_008_disable_sudorule_offline_caching(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "sudorule-add-allow-command", "--sudocmds=/bin/date",
            self.SUDO_RULE
        ])
        master.run_command(["ipa", "sudorule-disable", self.SUDO_RULE])
        clear_sssd_cache(self.client)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day not in result.stdout_text

        result = self.list_sudo_commands(self.USER_1,
                                         skip_sssd_cache_clear=True)
        assert "(root) /bin/date" not in result.stdout_text

        stop_ipa_server(master)
        result = self.run_as_sudo_user(
            "date", sudo_user="root", su_user=self.USER_1,
            skip_kinit=True, skip_sssd_cache_clear=True)

        sys_day = self.client.run_command(
            ["date", "+%a"]).stdout_text.strip()
        assert sys_day not in result.stdout_text

        result = self.list_sudo_commands(
            self.USER_1, skip_kinit=True, skip_sssd_cache_clear=True)
        assert "(root) /bin/date" not in result.stdout_text

        start_ipa_server(master)
        kinit_admin(master)
        master.run_command(["ipa", "sudorule-enable", self.SUDO_RULE])
        master.run_command([
            "ipa", "sudorule-remove-allow-command",
            "--sudocmds=/bin/date", self.SUDO_RULE
        ])


class TestSudo_BugFunctional(IntegrationTest):
    """
    Sudo Bug Functional Tests converted from Bash to Pytest
    """
    num_clients = 1

    @classmethod
    def install(cls, mh):
        super(TestSudo_BugFunctional, cls).install(mh)

        extra_args = ["--idstart=60001", "--idmax=65000"]
        install_master(cls.master, setup_dns=True, extra_args=extra_args)
        install_client(cls.master, cls.clients[0])

        cls.client = cls.clients[0]
        cls.user_password = "Secret123!"
        # Create basic users for tests
        for i in range(1, 3):
            username = f"user{i}"
            create_active_user(
                cls.master, username, password=cls.user_password
            )

    def test_bug769491(self):
        """
        Add certain sudo commands to groups, bz769491
        https://bugzilla.redhat.com/show_bug.cgi?id=769491
        """
        master = self.master
        kinit_admin(master)
        cmd = "/bin/chown -R apache:developers /var/www/*/shared/log"

        out = master.run_command(["ipa", "sudocmd-add", cmd]).stdout_text
        assert "Added Sudo Command" in out

        master.run_command(["ipa", "sudocmdgroup-add", "sudogrp1",
                            "--desc=sudogrp1"])

        out = master.run_command(
            ["ipa", "sudocmdgroup-add-member", "sudogrp1", f"--sudocmds={cmd}"]
        ).stdout_text
        assert ("Member Sudo commands: /bin/chown -R apache:developers "
                "/var/www/*/shared/log") in out
        assert "Number of members added 1" in out

        out = master.run_command(
            ["ipa", "sudocmdgroup-show", "sudogrp1"]
        ).stdout_text
        assert "Sudo Command Group: sudogrp1" in out
        assert ("Member Sudo commands: /bin/chown -R apache:developers "
                "/var/www/*/shared/log") in out

        out = master.run_command(
            ["ipa", "sudocmdgroup-remove-member", "sudogrp1",
             f"--sudocmds={cmd}"]
        ).stdout_text
        assert "Sudo Command Group: sudogrp1" in out
        assert ("Member Sudo commands: /bin/chown -R apache:developers "
                "/var/www/*/shared/log") not in out
        assert "Number of members removed 1" in out

        master.run_command(["ipa", "sudocmd-del", cmd])
        master.run_command(["ipa", "sudocmdgroup-del", "sudogrp1"])

    def test_bug741604(self):
        """
        Proper error when adding duplicate external members to sudo rule,
        bz741604
        """
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "sudorule-add", "741604rule"])

        out = master.run_command(
            ["ipa", "sudorule-add-user", "--users=user1", "--users=unknown",
             "741604rule"]
        ).stdout_text
        assert "This entry is already a member" not in out

        out = master.run_command(
            ["ipa", "sudorule-add-user", "--users=user1", "--users=unknown",
             "741604rule"],
            raiseonerr=False,
        ).stdout_text
        assert "member user: user1: This entry is already a member" in out
        assert "member user: unknown: This entry is already a member" in out
        assert "no such entry" not in out

        master.run_command(["ipa", "sudorule-del", "741604rule"])

    def test_bug782976(self):
        """
        Users/groups should detect ALL and error appropriately, bz782976
        """
        master = self.master
        kinit_admin(master)

        out = master.run_command(
            ["ipa", "sudorule-add", "bug782976", "--usercat=all"]
        ).stdout_text
        assert "User category: all" in out

        out = master.run_command(
            ["ipa", "sudorule-add-user", "bug782976", "--users=shanks"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: users cannot be added when user category='all'"
                in out)

        master.run_command(["ipa", "group-add", "group1", "--desc=group1"])
        out = master.run_command(
            ["ipa", "sudorule-add-user", "bug782976", "--groups=group1"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: users cannot be added when user category='all'"
                in out)

        master.run_command(["ipa", "sudorule-del", "bug782976"])
        master.run_command(["ipa", "sudorule-add", "bug782976"])
        master.run_command(
            ["ipa", "sudorule-add-user", "bug782976", "--users=user1"]
        )
        out = master.run_command(
            ["ipa", "sudorule-mod", "bug782976", "--usercat=all"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: user category cannot be set to 'all' "
                "while there are allowed users") in out

        master.run_command(["ipa", "sudorule-del", "bug782976"])
        master.run_command(["ipa", "sudorule-add", "bug782976"])
        master.run_command(
            ["ipa", "sudorule-add-user", "bug782976", "--groups=group1"]
        )
        out = master.run_command(
            ["ipa", "sudorule-mod", "bug782976", "--usercat=all"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: user category cannot be set to 'all' "
                "while there are allowed users") in out

        master.run_command(["ipa", "group-del", "group1"])
        master.run_command(["ipa", "sudorule-del", "bug782976"])

    def test_bug783286(self):
        """
        Setting HBAC SUDO category to anyone should remove users/groups,
        bz783286
        """
        master = self.master
        kinit_admin(master)

        create_active_user(
            self.master,
            "pranav",
            password=self.user_password,
            first="pranav",
            last="thube"
        )

        kinit_admin(master)
        master.run_command(["ipa", "group-add", "group1", "--desc=group1"])
        master.run_command(["ipa", "sudocmd-add", "/bin/ls"])

        out = master.run_command(
            ["ipa", "sudorule-add", "bug783286", "--usercat=all"]
        ).stdout_text
        assert "User category: all" in out

        master.run_command(
            ["ipa", "sudorule-add-host", "bug783286",
             f"--hosts={master.hostname}"]
        )

        out = master.run_command(
            ["ipa", "sudorule-add-user", "bug783286", "--users=pranav"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: users cannot be added when user category='all'"
                in out)

        out = master.run_command(
            ["ipa", "sudorule-add-user", "bug783286", "--groups=group1"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: users cannot be added when user category='all'"
                in out)

        master.run_command(["ipa", "sudorule-del", "bug783286"])
        master.run_command(["ipa", "sudorule-add", "bug783286"])
        master.run_command(
            ["ipa", "sudorule-add-user", "bug783286", "--users=pranav"],
            raiseonerr=False,
        )

        out = master.run_command(
            ["ipa", "sudorule-mod", "bug783286", "--usercat=all"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: user category cannot be set to 'all' "
                "while there are allowed users") in out

        master.run_command(["ipa", "sudorule-del", "bug783286"])
        master.run_command(["ipa", "sudorule-add", "bug783286"])
        master.run_command(
            ["ipa", "sudorule-add-user", "bug783286", "--groups=group1"]
        )

        out = master.run_command(
            ["ipa", "sudorule-mod", "bug783286", "--usercat=all"],
            raiseonerr=False,
        ).stderr_text
        assert ("ipa: ERROR: user category cannot be set to 'all' "
                "while there are allowed users") in out

        # cleanup
        master.run_command(["ipa", "group-del", "group1"])
        master.run_command(["ipa", "user-del", "pranav"])
        master.run_command(["ipa", "sudocmd-del", "/bin/ls"])
        master.run_command(["ipa", "sudorule-del", "bug783286"])

    def test_bug800537(self):
        """
        Remove sudo commands with special characters from command groups,
        bz800537
        """
        master = self.master
        kinit_admin(master)

        for testcmd in ["/bin/ls /lost+found", r"/bin/ls /tmp/test\ dir",
                        "/bin/ls /bin/cp"]:
            master.run_command(["ipa", "sudocmd-add", testcmd])
            master.run_command(
                ["ipa", "sudocmdgroup-add", "a-group", "--desc=test"]
            )
            master.run_command(
                ["ipa", "sudocmdgroup-add-member", "a-group",
                 f"--sudocmds={testcmd}"]
            )
            master.run_command(
                ["ipa", "sudocmdgroup-remove-member", "a-group",
                 f"--sudocmds={testcmd}"]
            )
            master.run_command(["ipa", "sudocmdgroup-del", "a-group"])
            master.run_command(["ipa", "sudocmd-del", testcmd])

    def test_bug800544(self):
        """
        Sudo commands are case insensitive, bz800544
        """
        master = self.master
        kinit_admin(master)

        for cmd in ["/usr/bin/X", "/usr/bin/x"]:
            master.run_command(["ipa", "sudocmd-add", cmd])

        master.run_command(["ipa", "sudocmdgroup-add", "group800544",
                            "--desc=blabla"])

        for cmd in ["/usr/bin/X", "/usr/bin/x"]:
            master.run_command([
                "ipa", "sudocmdgroup-add-member", "group800544",
                f"--sudocmds={cmd}"
            ])

        for cmd in ["/usr/bin/X", "/usr/bin/x"]:
            master.run_command([
                "ipa", "sudocmdgroup-remove-member", "group800544",
                f"--sudocmds={cmd}"
            ])

        for cmd in ["/usr/bin/x", "/usr/bin/X"]:
            master.run_command(["ipa", "sudocmd-del", cmd])

        master.run_command(["ipa", "sudocmdgroup-del", "group800544"])

    def test_bug912673(self):
        """
        Sudorule disable should remove rule from ou sudoers, bz912637
        """
        master = self.master
        rule = "rule4bug912673"
        kinit_admin(master)

        master.run_command(["ipa", "sudorule-add", rule])
        master.run_command(["ipa", "sudorule-show", rule])
        result = ldapsearch_dm(
            self.master,
            f"cn={rule},ou=sudoers,{master.domain.basedn}",
            ldap_args=[],
            scope="base"
        )
        assert (f"cn={rule},ou=sudoers,{master.domain.basedn}" in
                result.stdout_text), "ldap entry not found is not expected"

        master.run_command(["ipa", "sudorule-disable", rule])
        master.run_command(
            ["ipa", "sudorule-show", rule], raiseonerr=False
        )
        result = ldapsearch_dm(
            self.master,
            f"cn={rule},ou=sudoers,{master.domain.basedn}",
            ldap_args=[],
            scope="base",
            raiseonerr=False
        )
        assert "No such object (32)" in result.stderr_text, (
            "found ldap entry via ldapsearch is not expected"
        )

        master.run_command(["ipa", "sudorule-enable", rule])
        master.run_command(["ipa", "sudorule-show", rule])
        result = ldapsearch_dm(
            self.master,
            f"cn={rule},ou=sudoers,{master.domain.basedn}",
            ldap_args=[],
            scope="base"
        )
        assert (f"cn={rule},ou=sudoers,{master.domain.basedn}" in
                result.stdout_text), "ldap entry not found is not expected"

    def test_bug837356(self):
        """
        Deleting command should not bring LDAP to inconsistent state, bz837356
        """
        master = self.master
        rule = "rule4bz837356"
        cmd = "/usr/bin/yum"

        kinit_admin(master)

        master.run_command(["ipa", "sudorule-add", rule])
        master.run_command(["ipa", "sudorule-show", rule])
        master.run_command(["ipa", "sudocmd-add", cmd])
        master.run_command(
            ["ipa", "sudorule-add-allow-command", rule, f"--sudocmds={cmd}"]
        )
        master.run_command(["ipa", "sudorule-show", rule, "--all", "--raw"])
        # Try to delete command (should fail)
        result = master.run_command(
            ["ipa", "sudocmd-del", cmd],
            raiseonerr=False
        )
        err_msg = (
            f"{cmd} cannot be deleted because sudorule {rule} "
            "requires it"
        )
        assert err_msg in result.stderr_text

        master.run_command(["ipa", "sudorule-del", rule])
        master.run_command(["ipa", "sudocmd-del", cmd])
