#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.tasks import clear_sssd_cache


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
    """
    Test Netgroups
    """

    topology = 'line'

    def check_users_in_netgroups(self):
        """Check if users are in groups, no nested things"""
        master = self.master
        clear_sssd_cache(master)

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
        clear_sssd_cache(master)

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
        clear_sssd_cache(master)

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
        clear_sssd_cache(master)

        result = master.run_command(['getent', 'netgroup',
                                     test_data[2]['netgroup']],
                                    raiseonerr=False)
        assert result.returncode == 0
        assert trinity[0] not in result.stdout_text
        assert trinity[1] not in result.stdout_text
        assert trinity[2] in result.stdout_text
