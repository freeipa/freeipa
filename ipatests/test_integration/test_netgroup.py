#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import pytest
import re

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


test_data = []
for i in range(3):
    data = {
        'user': {
            'login': 'testuser_{}'.format(i),
            'first': 'Test_{}'.format(i),
            'last': 'User_{}'.format(i),
        },
        'netgroup': 'testgroup_{}'.format(i),
        'nested_netgroup': 'testgroup_{}'.format(i-1) if i > 0 else None
    }
    test_data.append(data)
    members = [d['user']['login'] for d in test_data]
    test_data[-1]['netgroup_nested_members'] = members


@pytest.fixture()
def three_netgroups(request):
    """Prepare basic netgroups with users"""

    for d in test_data:
        request.cls.master.run_command(['ipa', 'user-add', d['user']['login'],
                                        '--first', d['user']['first'],
                                        '--last', d['user']['last']],
                                       raiseonerr=False)

        request.cls.master.run_command(['ipa', 'netgroup-add', d['netgroup']],
                                       raiseonerr=False)

        user_opt = '--users={u[login]}'.format(u=d['user'])
        request.cls.master.run_command(['ipa', 'netgroup-add-member', user_opt,
                                        d['netgroup']], raiseonerr=False)

    def teardown_three_netgroups():
        """Clean basic netgroups with users"""
        for d in test_data:
            request.cls.master.run_command(['ipa', 'user-del',
                                            d['user']['login']],
                                           raiseonerr=False)

            request.cls.master.run_command(['ipa', 'netgroup-del',
                                            d['netgroup']],
                                           raiseonerr=False)

    request.addfinalizer(teardown_three_netgroups)


class TestNetgroups(IntegrationTest):
    """Test Netgroups - nested, managed, find, show, delete operations."""

    topology = 'line'

    # Find test entities
    FND_USER1 = 'fnduser1'
    FND_USER2 = 'fnduser2'
    FND_GROUP = 'fndgroup1'
    FND_HOSTGRP = 'fndhostgrp1'
    FND_NG1 = 'fndng1'
    FND_NG2 = 'fndng2'
    FND_NG3 = 'fndng3'

    # In-netgroups test entities
    INNG_USER1 = 'inng_user1'
    INNG_USER2 = 'inng_user2'
    INNG_GRP1 = 'inng_grp1'
    INNG_GRP2 = 'inng_grp2'
    INNG_HG1 = 'inng_hg1'
    INNG_HG2 = 'inng_hg2'
    INNG_NG1 = 'inng_ng1'
    INNG_NG2 = 'inng_ng2'
    INNG_NG3 = 'inng_ng3'

    def check_users_in_netgroups(self):
        """Check if users are in groups, no nested things"""
        master = self.master
        tasks.clear_sssd_cache(master)

        for d in test_data:
            result = master.run_command(['getent', 'passwd',
                                         d['user']['login']], raiseonerr=False)
            assert result.returncode == 0

            user = '{u[first]} {u[last]}'.format(u=d['user'])
            assert user in result.stdout_text

            result = master.run_command(['getent', 'netgroup',
                                         d['netgroup']], raiseonerr=False)
            assert result.returncode == 0

            netgroup = '(-,{},{})'.format(d['user']['login'],
                                          self.master.domain.name)
            assert netgroup in result.stdout_text

    def check_nested_netgroup_hierarchy(self):
        """Check if nested netgroups hierarchy is complete"""
        master = self.master
        tasks.clear_sssd_cache(master)

        for d in test_data:
            result = master.run_command(['getent', 'netgroup', d['netgroup']],
                                        raiseonerr=False)
            assert result.returncode == 0

            for member in d['netgroup_nested_members']:
                if not member:
                    continue

                netgroup = '(-,{},{})'.format(member, self.master.domain.name)
                assert netgroup in result.stdout_text

    def prepare_nested_netgroup_hierarchy(self):
        """Prepares nested netgroup hierarchy from basic netgroups"""
        for d in test_data:
            if not d['nested_netgroup']:
                continue

            netgroups_opt = '--netgroups={}'.format(d['nested_netgroup'])
            self.master.run_command(['ipa', 'netgroup-add-member',
                                     netgroups_opt, d['netgroup']])

    def test_add_nested_netgroup(self, three_netgroups):
        """Test of adding nested groups"""
        self.check_users_in_netgroups()
        self.prepare_nested_netgroup_hierarchy()
        self.check_nested_netgroup_hierarchy()

    def test_remove_nested_netgroup(self, three_netgroups):
        """Test of removing nested groups"""
        master = self.master

        trinity = ['(-,{},{})'.format(d['user']['login'],
                                      self.master.domain.name)
                   for d in test_data]

        self.check_users_in_netgroups()
        self.prepare_nested_netgroup_hierarchy()
        self.check_nested_netgroup_hierarchy()

        # Removing of testgroup_1 from testgroup_2
        netgroups_opt = '--netgroups={n[netgroup]}'.format(n=test_data[0])
        result = self.master.run_command(['ipa', 'netgroup-remove-member',
                                          netgroups_opt,
                                          test_data[1]['netgroup']],
                                         raiseonerr=False)
        assert result.returncode == 0
        tasks.clear_sssd_cache(master)

        result = master.run_command(['getent', 'netgroup',
                                     test_data[1]['netgroup']],
                                    raiseonerr=False)
        assert result.returncode == 0
        assert trinity[1] in result.stdout_text

        result = master.run_command(['getent', 'netgroup',
                                     test_data[2]['netgroup']],
                                    raiseonerr=False)
        assert result.returncode == 0
        assert trinity[0] not in result.stdout_text
        assert trinity[1] in result.stdout_text
        assert trinity[2] in result.stdout_text

        # Removing of testgroup_2 from testgroup_3
        netgroups_opt = '--netgroups={n[netgroup]}'.format(n=test_data[1])
        result = self.master.run_command(['ipa', 'netgroup-remove-member',
                                          netgroups_opt,
                                          test_data[2]['netgroup']],
                                         raiseonerr=False)
        assert result.returncode == 0
        tasks.clear_sssd_cache(master)

        result = master.run_command(['getent', 'netgroup',
                                     test_data[2]['netgroup']],
                                    raiseonerr=False)
        assert result.returncode == 0
        assert trinity[0] not in result.stdout_text
        assert trinity[1] not in result.stdout_text
        assert trinity[2] in result.stdout_text

    # --- Managed Netgroups Tests ---

    def test_managed_netgroup_lifecycle(self):
        """Test managed netgroup created/deleted with hostgroup."""
        master = self.master
        # Enable NGP plugin
        master.run_command(
            ['ipa-managed-entries', '--entry=NGP Definition', 'enable'],
            raiseonerr=False
        )
        # Add hostgroup - managed netgroup should be created
        tasks.hostgroup_add(master, 'mng_testgrp', ('--desc=test',))
        result = master.run_command(
            ['ipa', 'netgroup-find', '--managed', 'mng_testgrp'],
            raiseonerr=False
        )
        assert result.returncode == 0

        # Delete hostgroup - managed netgroup should be deleted
        tasks.hostgroup_del(master, 'mng_testgrp')
        result = master.run_command(
            ['ipa', 'netgroup-find', '--managed', 'mng_testgrp'],
            raiseonerr=False
        )
        assert '0 netgroups matched' in result.stdout_text

    def test_cannot_delete_managed_netgroup(self):
        """Deleting managed netgroup directly should fail."""
        master = self.master
        master.run_command(
            ['ipa-managed-entries', '--entry=NGP Definition', 'enable'],
            raiseonerr=False
        )
        tasks.hostgroup_add(master, 'mng_nodelete', ('--desc=test',))
        result = master.run_command(
            ['ipa', 'netgroup-del', 'mng_nodelete'], raiseonerr=False
        )
        assert result.returncode != 0
        assert 'Deleting a managed entry is not allowed' in result.stderr_text
        tasks.hostgroup_del(master, 'mng_nodelete', raiseonerr=False)

    # --- Netgroup Show/Delete Tests ---

    def test_show_and_delete_netgroup(self):
        """Test netgroup-show and netgroup-del operations."""
        master = self.master
        # Show existing
        master.run_command(
            ['ipa', 'netgroup-add', 'show_del_ng', '--desc=test']
        )
        result = master.run_command(['ipa', 'netgroup-show', 'show_del_ng'])
        assert 'show_del_ng' in result.stdout_text

        # Delete and verify
        master.run_command(['ipa', 'netgroup-del', 'show_del_ng'])
        result = master.run_command(
            ['ipa', 'netgroup-show', 'show_del_ng'], raiseonerr=False
        )
        assert result.returncode != 0

    def test_show_nonexistent_netgroup(self):
        """Show non-existent netgroup fails."""
        result = self.master.run_command(
            ['ipa', 'netgroup-show', 'ghost'], raiseonerr=False
        )
        assert 'netgroup not found' in result.stderr_text

    def test_delete_nonexistent_netgroup(self):
        """Delete non-existent netgroup fails."""
        result = self.master.run_command(
            ['ipa', 'netgroup-del', 'ghost'], raiseonerr=False
        )
        assert 'netgroup not found' in result.stderr_text

    # --- Netgroup Find Tests ---

    @pytest.fixture
    def find_setup(self, request):
        """Setup entities for netgroup-find tests."""
        master = self.master
        domain = master.domain.name
        fnd_host = f'fndhost1.{domain}'

        # Register cleanup first so it runs even if setup fails
        def cleanup():
            for ng in [self.FND_NG1, self.FND_NG2, self.FND_NG3]:
                master.run_command(
                    ['ipa', 'netgroup-del', ng], raiseonerr=False
                )
            tasks.hostgroup_del(master, self.FND_HOSTGRP, raiseonerr=False)
            tasks.host_del(master, fnd_host, raiseonerr=False)
            tasks.group_del(master, self.FND_GROUP, raiseonerr=False)
            tasks.user_del(master, self.FND_USER1, raiseonerr=False)
            tasks.user_del(master, self.FND_USER2, raiseonerr=False)
        request.addfinalizer(cleanup)

        # Create test entities
        tasks.user_add(master, self.FND_USER1)
        tasks.user_add(master, self.FND_USER2)
        tasks.group_add(master, self.FND_GROUP, ('--desc=test',))
        tasks.host_add(master, fnd_host, '--force')
        tasks.hostgroup_add(master, self.FND_HOSTGRP, ('--desc=test',))

        # Create netgroups with various attributes
        master.run_command([
            'ipa', 'netgroup-add', self.FND_NG1,
            '--desc=findtest', '--nisdomain=testdomain'
        ])
        master.run_command([
            'ipa', 'netgroup-add', self.FND_NG2,
            '--desc=findtest2', '--usercat=all', '--hostcat=all'
        ])
        master.run_command(
            ['ipa', 'netgroup-add', self.FND_NG3, '--desc=findtest3']
        )

        # Add members to fndng1
        master.run_command([
            'ipa', 'netgroup-add-member', self.FND_NG1,
            f'--users={self.FND_USER1}',
            f'--groups={self.FND_GROUP}',
            f'--hosts={fnd_host}',
            f'--hostgroups={self.FND_HOSTGRP}'
        ])
        master.run_command([
            'ipa', 'netgroup-add-member', self.FND_NG3,
            f'--netgroups={self.FND_NG1}'
        ])

    def test_netgroup_find_positive(self, find_setup):
        """Test netgroup-find with various positive scenarios."""
        master = self.master
        domain = master.domain.name
        fnd_host = f'fndhost1.{domain}'

        # Get UUID for uuid test
        result = master.run_command(
            ['ipa', 'netgroup-show', self.FND_NG1, '--all', '--raw']
        )
        uuid = re.search(r'ipaUniqueID: (\S+)', result.stdout_text).group(1)

        # Test cases: (args_list, expected_in_output)
        find_tests = [
            (['netgroup-find'], self.FND_NG1),
            (['netgroup-find', 'fndng'], self.FND_NG1),
            (['netgroup-find', f'--name={self.FND_NG1}'], self.FND_NG1),
            (['netgroup-find', '--desc=findtest'], self.FND_NG1),
            (['netgroup-find', '--nisdomain=testdomain'], self.FND_NG1),
            (['netgroup-find', f'--uuid={uuid}'], self.FND_NG1),
            (['netgroup-find', '--usercat=all'], self.FND_NG2),
            (['netgroup-find', '--hostcat=all'], self.FND_NG2),
            (['netgroup-find', '--sizelimit=1'], 'netgroup matched'),
            (['netgroup-find', '--timelimit=5'], 'netgroup'),
            (['netgroup-find', f'--users={self.FND_USER1}'], self.FND_NG1),
            (['netgroup-find', f'--no-users={self.FND_USER2}'], self.FND_NG1),
            (['netgroup-find', f'--groups={self.FND_GROUP}'], self.FND_NG1),
            (['netgroup-find', f'--no-groups={self.FND_GROUP}'], self.FND_NG2),
            (['netgroup-find', f'--hosts={fnd_host}'], self.FND_NG1),
            (['netgroup-find', f'--no-hosts={fnd_host}'], self.FND_NG2),
            (['netgroup-find', f'--hostgroups={self.FND_HOSTGRP}'],
             self.FND_NG1),
            (['netgroup-find', f'--no-hostgroups={self.FND_HOSTGRP}'],
             self.FND_NG2),
            (['netgroup-find', f'--netgroups={self.FND_NG1}'],
             self.FND_NG3),
            (['netgroup-find', f'--no-netgroups={self.FND_NG1}'],
             self.FND_NG1),
            (['netgroup-find', f'--in-netgroups={self.FND_NG3}'],
             self.FND_NG1),
            (['netgroup-find', f'--not-in-netgroups={self.FND_NG3}'],
             self.FND_NG2),
            (['netgroup-find', '--pkey-only'], self.FND_NG1),
        ]

        for args, expected in find_tests:
            result = master.run_command(['ipa'] + args)
            assert expected in result.stdout_text, f"Failed: {args}"

    def test_netgroup_find_negative(self, find_setup):
        """Test netgroup-find with various negative scenarios."""
        master = self.master

        # Tests returning 0 matches
        bad_uuid = '00000000-0000-0000-0000-000000000000'
        zero_match_tests = [
            ['netgroup-find', 'nonexistent'],
            ['netgroup-find', '--name=badname'],
            ['netgroup-find', '--desc=baddesc'],
            ['netgroup-find', '--nisdomain=baddomain'],
            ['netgroup-find', f'--uuid={bad_uuid}'],
            ['netgroup-find', '--users=baduser'],
            ['netgroup-find', '--groups=badgroup'],
            ['netgroup-find', '--hosts=badhost'],
            ['netgroup-find', '--hostgroups=badhg'],
            ['netgroup-find', '--netgroups=badng'],
            ['netgroup-find', '--in-netgroups=badng'],
        ]

        for args in zero_match_tests:
            result = master.run_command(['ipa'] + args, raiseonerr=False)
            assert '0 netgroups matched' in result.stdout_text, \
                f"Failed: {args}"

        # Tests with invalid parameter types
        result = master.run_command(
            ['ipa', 'netgroup-find', '--timelimit=bad'], raiseonerr=False
        )
        assert "must be an integer" in result.stderr_text

        result = master.run_command(
            ['ipa', 'netgroup-find', '--sizelimit=bad'], raiseonerr=False
        )
        assert "must be an integer" in result.stderr_text

    def test_netgroup_find_space_inputs(self, find_setup):
        """Test netgroup-find with space inputs (bz798792)."""
        master = self.master

        # Space inputs should not cause internal errors
        space_tests = [
            '--netgroups= ',
            '--no-netgroups= ',
            '--users= ',
            '--no-users= ',
            '--groups= ',
            '--no-groups= ',
            '--hosts= ',
            '--no-hosts= ',
            '--hostgroups= ',
            '--no-hostgroups= ',
            '--in-netgroups= ',
            '--not-in-netgroups= ',
        ]

        for arg in space_tests:
            result = master.run_command(
                ['ipa', 'netgroup-find', arg], raiseonerr=False
            )
            assert 'internal error' not in result.stderr_text.lower(), \
                f"Internal error with {arg}"

    # --- In-Netgroups Tests for Various Entity Types ---

    @pytest.fixture
    def in_netgroups_setup(self, request):
        """Setup for --in-netgroups tests across entity types."""
        master = self.master
        domain = master.domain.name
        innghost1 = f'innghost1.{domain}'
        innghost2 = f'innghost2.{domain}'

        # Register cleanup FIRST so it runs even if setup fails
        def cleanup():
            for ng in [self.INNG_NG1, self.INNG_NG2, self.INNG_NG3]:
                master.run_command(
                    ['ipa', 'netgroup-del', ng], raiseonerr=False
                )
            tasks.hostgroup_del(master, self.INNG_HG1, raiseonerr=False)
            tasks.hostgroup_del(master, self.INNG_HG2, raiseonerr=False)
            tasks.host_del(master, innghost1, raiseonerr=False)
            tasks.host_del(master, innghost2, raiseonerr=False)
            tasks.group_del(master, self.INNG_GRP1, raiseonerr=False)
            tasks.group_del(master, self.INNG_GRP2, raiseonerr=False)
            tasks.user_del(master, self.INNG_USER1, raiseonerr=False)
            tasks.user_del(master, self.INNG_USER2, raiseonerr=False)
        request.addfinalizer(cleanup)

        # Create entities
        tasks.user_add(master, self.INNG_USER1)
        tasks.user_add(master, self.INNG_USER2)
        tasks.group_add(master, self.INNG_GRP1, ('--desc=test',))
        tasks.group_add(master, self.INNG_GRP2, ('--desc=test',))
        tasks.host_add(master, innghost1, '--force')
        tasks.host_add(master, innghost2, '--force')
        tasks.hostgroup_add(master, self.INNG_HG1, ('--desc=test',))
        tasks.hostgroup_add(master, self.INNG_HG2, ('--desc=test',))

        for ng in [self.INNG_NG1, self.INNG_NG2, self.INNG_NG3]:
            master.run_command(['ipa', 'netgroup-add', ng, '--desc=test'])

        # Add members to inng_ng1 only
        master.run_command(['ipa', 'netgroup-add-member', self.INNG_NG1,
                            f'--users={self.INNG_USER1}',
                            f'--groups={self.INNG_GRP1}',
                            f'--hosts={innghost1}',
                            f'--hostgroups={self.INNG_HG1}',
                            f'--netgroups={self.INNG_NG2}'])

    def test_in_netgroups_across_entities(self, in_netgroups_setup):
        """Test --in-netgroups and --not-in-netgroups for all entity types."""
        master = self.master
        domain = master.domain.name

        # (command, in-member, not-in-member)
        entity_tests = [
            ('user-find', self.INNG_USER1, self.INNG_USER2),
            ('group-find', self.INNG_GRP1, self.INNG_GRP2),
            ('host-find', f'innghost1.{domain}', f'innghost2.{domain}'),
            ('hostgroup-find', self.INNG_HG1, self.INNG_HG2),
            ('netgroup-find', self.INNG_NG2, self.INNG_NG3),
        ]

        for cmd, member, non_member in entity_tests:
            # Test --in-netgroups
            result = master.run_command(
                ['ipa', cmd, f'--in-netgroups={self.INNG_NG1}']
            )
            assert member in result.stdout_text, \
                f"--in-netgroups failed for {cmd}"
            assert non_member not in result.stdout_text

            # Test --not-in-netgroups
            result = master.run_command(
                ['ipa', cmd, f'--not-in-netgroups={self.INNG_NG1}']
            )
            assert non_member in result.stdout_text, \
                f"--not-in-netgroups failed for {cmd}"

    def test_removed_members_not_in_netgroups(self, in_netgroups_setup):
        """Verify removed members don't appear in --in-netgroups."""
        master = self.master
        domain = master.domain.name
        innghost1 = f'innghost1.{domain}'

        # Remove user from netgroup
        master.run_command(['ipa', 'netgroup-remove-member', self.INNG_NG1,
                            f'--users={self.INNG_USER1}'])
        result = master.run_command(
            ['ipa', 'user-find', f'--in-netgroups={self.INNG_NG1}'],
            raiseonerr=False
        )
        assert self.INNG_USER1 not in result.stdout_text

        # Removed user should now appear in --not-in-netgroups
        result = master.run_command(
            ['ipa', 'user-find', f'--not-in-netgroups={self.INNG_NG1}']
        )
        assert self.INNG_USER1 in result.stdout_text

        # Remove host from netgroup
        master.run_command(['ipa', 'netgroup-remove-member', self.INNG_NG1,
                            f'--hosts={innghost1}'])
        result = master.run_command(
            ['ipa', 'host-find', f'--in-netgroups={self.INNG_NG1}'],
            raiseonerr=False
        )
        assert 'innghost1' not in result.stdout_text

    def test_delete_multiple_netgroups(self):
        """Delete multiple netgroups and verify they're deleted."""
        master = self.master

        # Create multiple netgroups
        for i in range(1, 4):
            master.run_command(
                ['ipa', 'netgroup-add', f'del_ng{i}', '--desc=test']
            )

        # Delete all at once
        master.run_command(
            ['ipa', 'netgroup-del', 'del_ng1', 'del_ng2', 'del_ng3']
        )

        # Verify all deleted
        for i in range(1, 4):
            result = master.run_command(
                ['ipa', 'netgroup-show', f'del_ng{i}'], raiseonerr=False
            )
            assert result.returncode != 0
            assert 'netgroup not found' in result.stderr_text
