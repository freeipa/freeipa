#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

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
        master.run_command(
            ['ipa', 'netgroup-find', '--managed', 'mng_testgrp']
        )

        # Delete hostgroup - managed netgroup should be deleted
        tasks.hostgroup_del(master, 'mng_testgrp')
        # ipa *-find returns exit code 1 when 0 results found
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
        try:
            result = master.run_command(
                ['ipa', 'netgroup-del', 'mng_nodelete'], raiseonerr=False
            )
            assert result.returncode != 0
            assert 'Deleting a managed entry is not allowed' in \
                result.stderr_text
        finally:
            tasks.hostgroup_del(master, 'mng_nodelete', raiseonerr=False)

    # --- In-Netgroups Tests for Various Entity Types ---

    @pytest.fixture(scope='class')
    def in_netgroups_setup(self, request):
        """Setup for --in-netgroups tests across entity types."""
        master = self.master
        domain = master.domain.name
        innghost1 = f'innghost1.{domain}'
        innghost2 = f'innghost2.{domain}'

        # Register cleanup FIRST so it runs even if setup fails
        def cleanup():
            for ng in [INNG_NG1, INNG_NG2, INNG_NG3]:
                master.run_command(
                    ['ipa', 'netgroup-del', ng], raiseonerr=False
                )
            tasks.hostgroup_del(master, INNG_HG1, raiseonerr=False)
            tasks.hostgroup_del(master, INNG_HG2, raiseonerr=False)
            tasks.host_del(master, innghost1, raiseonerr=False)
            tasks.host_del(master, innghost2, raiseonerr=False)
            tasks.group_del(master, INNG_GRP1, raiseonerr=False)
            tasks.group_del(master, INNG_GRP2, raiseonerr=False)
            tasks.user_del(master, INNG_USER1, raiseonerr=False)
            tasks.user_del(master, INNG_USER2, raiseonerr=False)
        request.addfinalizer(cleanup)

        # Create entities
        tasks.user_add(master, INNG_USER1)
        tasks.user_add(master, INNG_USER2)
        tasks.group_add(master, INNG_GRP1, ('--desc=test',))
        tasks.group_add(master, INNG_GRP2, ('--desc=test',))
        tasks.host_add(master, innghost1, '--force')
        tasks.host_add(master, innghost2, '--force')
        tasks.hostgroup_add(master, INNG_HG1, ('--desc=test',))
        tasks.hostgroup_add(master, INNG_HG2, ('--desc=test',))

        for ng in [INNG_NG1, INNG_NG2, INNG_NG3]:
            master.run_command(['ipa', 'netgroup-add', ng, '--desc=test'])

        # Add members to inng_ng1 only
        master.run_command(['ipa', 'netgroup-add-member', INNG_NG1,
                            f'--users={INNG_USER1}',
                            f'--groups={INNG_GRP1}',
                            f'--hosts={innghost1}',
                            f'--hostgroups={INNG_HG1}',
                            f'--netgroups={INNG_NG2}'])

    def test_in_netgroups_across_entities(self, in_netgroups_setup):
        """Test --in-netgroups and --not-in-netgroups for all entity types."""
        master = self.master
        domain = master.domain.name

        # (command, in-member, not-in-member)
        entity_tests = [
            ('user-find', INNG_USER1, INNG_USER2),
            ('group-find', INNG_GRP1, INNG_GRP2),
            ('host-find', f'innghost1.{domain}', f'innghost2.{domain}'),
            ('hostgroup-find', INNG_HG1, INNG_HG2),
            ('netgroup-find', INNG_NG2, INNG_NG3),
        ]

        for cmd, member, non_member in entity_tests:
            # Test --in-netgroups
            result = master.run_command(
                ['ipa', cmd, f'--in-netgroups={INNG_NG1}']
            )
            assert member in result.stdout_text, \
                f"--in-netgroups failed for {cmd}"
            assert non_member not in result.stdout_text

            # Test --not-in-netgroups
            result = master.run_command(
                ['ipa', cmd, f'--not-in-netgroups={INNG_NG1}']
            )
            assert non_member in result.stdout_text, \
                f"--not-in-netgroups failed for {cmd}"

    def test_removed_members_not_in_netgroups(self, in_netgroups_setup):
        """Verify removed members don't appear in --in-netgroups."""
        master = self.master
        domain = master.domain.name
        innghost1 = f'innghost1.{domain}'

        # Remove user from netgroup
        master.run_command(['ipa', 'netgroup-remove-member', INNG_NG1,
                            f'--users={INNG_USER1}'])
        result = master.run_command(
            ['ipa', 'user-find', f'--in-netgroups={INNG_NG1}'],
            raiseonerr=False
        )
        assert INNG_USER1 not in result.stdout_text

        # Removed user should now appear in --not-in-netgroups
        result = master.run_command(
            ['ipa', 'user-find', f'--not-in-netgroups={INNG_NG1}']
        )
        assert INNG_USER1 in result.stdout_text

        # Remove host from netgroup
        master.run_command(['ipa', 'netgroup-remove-member', INNG_NG1,
                            f'--hosts={innghost1}'])
        result = master.run_command(
            ['ipa', 'host-find', f'--in-netgroups={INNG_NG1}'],
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
