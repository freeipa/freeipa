#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# In-netgroups test entities
# *_MEMBER entities are added to INNG_NG_PARENT netgroup
# *_NONMEMBER entities are NOT added to any netgroup
INNG_USER_MEMBER = 'inng_user_member'
INNG_USER_NONMEMBER = 'inng_user_nonmember'
INNG_GRP_MEMBER = 'inng_grp_member'
INNG_GRP_NONMEMBER = 'inng_grp_nonmember'
INNG_HG_MEMBER = 'inng_hg_member'
INNG_HG_NONMEMBER = 'inng_hg_nonmember'
INNG_NG_PARENT = 'inng_ng_parent'
INNG_NG_MEMBER = 'inng_ng_member'
INNG_NG_NONMEMBER = 'inng_ng_nonmember'


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
            for ng in [INNG_NG_PARENT, INNG_NG_MEMBER, INNG_NG_NONMEMBER]:
                master.run_command(
                    ['ipa', 'netgroup-del', ng], raiseonerr=False
                )
            tasks.hostgroup_del(master, INNG_HG_MEMBER, raiseonerr=False)
            tasks.hostgroup_del(master, INNG_HG_NONMEMBER, raiseonerr=False)
            tasks.host_del(master, innghost1, raiseonerr=False)
            tasks.host_del(master, innghost2, raiseonerr=False)
            tasks.group_del(master, INNG_GRP_MEMBER, raiseonerr=False)
            tasks.group_del(master, INNG_GRP_NONMEMBER, raiseonerr=False)
            tasks.user_del(master, INNG_USER_MEMBER, raiseonerr=False)
            tasks.user_del(master, INNG_USER_NONMEMBER, raiseonerr=False)
        request.addfinalizer(cleanup)

        # Create entities
        tasks.user_add(master, INNG_USER_MEMBER)
        tasks.user_add(master, INNG_USER_NONMEMBER)
        tasks.group_add(master, INNG_GRP_MEMBER, ('--desc=test',))
        tasks.group_add(master, INNG_GRP_NONMEMBER, ('--desc=test',))
        tasks.host_add(master, innghost1, '--force')
        tasks.host_add(master, innghost2, '--force')
        tasks.hostgroup_add(master, INNG_HG_MEMBER, ('--desc=test',))
        tasks.hostgroup_add(master, INNG_HG_NONMEMBER, ('--desc=test',))

        for ng in [INNG_NG_PARENT, INNG_NG_MEMBER, INNG_NG_NONMEMBER]:
            master.run_command(['ipa', 'netgroup-add', ng, '--desc=test'])

        # Add members to parent netgroup only
        master.run_command(['ipa', 'netgroup-add-member', INNG_NG_PARENT,
                            f'--users={INNG_USER_MEMBER}',
                            f'--groups={INNG_GRP_MEMBER}',
                            f'--hosts={innghost1}',
                            f'--hostgroups={INNG_HG_MEMBER}',
                            f'--netgroups={INNG_NG_MEMBER}'])

    def test_in_netgroups_across_entities(self, in_netgroups_setup):
        """Test --in-netgroups and --not-in-netgroups for all entity types."""
        master = self.master
        domain = master.domain.name

        entity_tests = [
            ('user-find', INNG_USER_MEMBER, INNG_USER_NONMEMBER),
            ('group-find', INNG_GRP_MEMBER, INNG_GRP_NONMEMBER),
            ('host-find', f'innghost1.{domain}', f'innghost2.{domain}'),
            ('hostgroup-find', INNG_HG_MEMBER, INNG_HG_NONMEMBER),
            ('netgroup-find', INNG_NG_MEMBER, INNG_NG_NONMEMBER),
        ]

        for cmd, member, non_member in entity_tests:
            # Test --in-netgroups
            result = master.run_command(
                ['ipa', cmd, f'--in-netgroups={INNG_NG_PARENT}']
            )
            assert member in result.stdout_text, \
                f"--in-netgroups failed for {cmd}"
            assert non_member not in result.stdout_text

            # Test --not-in-netgroups
            result = master.run_command(
                ['ipa', cmd, f'--not-in-netgroups={INNG_NG_PARENT}']
            )
            assert non_member in result.stdout_text, \
                f"--not-in-netgroups failed for {cmd}"

    def test_removed_member_not_in_netgroups(self):
        """Verify removed member no longer appears in --in-netgroups."""
        master = self.master
        user = 'removal_test_user'
        netgroup = 'removal_test_ng'

        try:
            tasks.user_add(master, user)
            master.run_command(['ipa', 'netgroup-add', netgroup])
            master.run_command([
                'ipa', 'netgroup-add-member', netgroup, f'--users={user}'
            ])

            # Verify user is in netgroup
            result = master.run_command(
                ['ipa', 'user-find', f'--in-netgroups={netgroup}']
            )
            assert user in result.stdout_text

            # Remove user and verify not in netgroup
            master.run_command([
                'ipa', 'netgroup-remove-member', netgroup, f'--users={user}'
            ])
            result = master.run_command(
                ['ipa', 'user-find', f'--in-netgroups={netgroup}'],
                raiseonerr=False
            )
            assert user not in result.stdout_text

        finally:
            master.run_command(
                ['ipa', 'netgroup-del', netgroup], raiseonerr=False)
            tasks.user_del(master, user, raiseonerr=False)

    def test_delete_multiple_netgroups(self):
        """Delete multiple netgroups and verify they're deleted."""
        master = self.master

        try:
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

        finally:
            # Cleanup: ensure netgroups are deleted even if test fails
            for i in range(1, 4):
                master.run_command(
                    ['ipa', 'netgroup-del', f'del_ng{i}'], raiseonerr=False
                )
