#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""Tests for member manager feature
"""
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


PASSWORD = "DummyPassword123"
# direct member manager
USER_MM = "mmuser"
# indirect member manager through group membership
USER_INDIRECT = "indirect_mmuser"
GROUP_INDIRECT = "group_indirect"

USER1 = "testuser1"
USER2 = "testuser2"
GROUP1 = "testgroup1"
GROUP2 = "testgroup2"
HOSTGROUP1 = "testhostgroup1"


class TestMemberManager(IntegrationTest):
    """Tests for member manager feature for groups and hostgroups
    """
    topology = "line"

    @classmethod
    def install(cls, mh):
        super(TestMemberManager, cls).install(mh)
        master = cls.master

        tasks.create_active_user(master, USER_MM, PASSWORD)
        tasks.create_active_user(master, USER_INDIRECT, PASSWORD)
        tasks.create_active_user(master, USER1, PASSWORD)

        tasks.kinit_admin(master)
        tasks.group_add(master, GROUP_INDIRECT)
        master.run_command([
            'ipa', 'group-add-member', GROUP_INDIRECT, '--users', USER_INDIRECT
        ])

        tasks.user_add(master, USER2)
        tasks.group_add(master, GROUP1)
        tasks.group_add(master, GROUP2)
        master.run_command(['ipa', 'hostgroup-add', HOSTGROUP1])

        # make mmuser a member manager for group and hostgroup
        master.run_command([
            'ipa', 'group-add-member-manager', GROUP1,
            '--users', USER_MM
        ])
        master.run_command([
            'ipa', 'hostgroup-add-member-manager', HOSTGROUP1,
            '--users', USER_MM
        ])
        # make indirect group member manager for group and hostgroup
        master.run_command([
            'ipa', 'group-add-member-manager', GROUP1,
            '--groups', GROUP_INDIRECT
        ])
        master.run_command([
            'ipa', 'hostgroup-add-member-manager', HOSTGROUP1,
            '--groups', GROUP_INDIRECT
        ])
        tasks.kdestroy_all(master)

    def test_show_member_manager(self):
        master = self.master
        tasks.kinit_admin(master)

        result = master.run_command(['ipa', 'group-show', GROUP1])
        out = result.stdout_text
        assert f"Membership managed by groups: {GROUP_INDIRECT}" in out
        assert f"Membership managed by users: {USER_MM}" in out

        result = master.run_command(['ipa', 'hostgroup-show', HOSTGROUP1])
        out = result.stdout_text
        assert f"Membership managed by groups: {GROUP_INDIRECT}" in out
        assert f"Membership managed by users: {USER_MM}" in out

        tasks.kdestroy_all(master)

    def test_find_by_member_manager(self):
        master = self.master
        tasks.kinit_admin(master)

        result = master.run_command([
            'ipa', 'group-find', '--membermanager-users', USER_MM
        ])
        assert GROUP1 in result.stdout_text

        result = master.run_command([
            'ipa', 'group-find', '--membermanager-groups', GROUP_INDIRECT
        ])
        assert GROUP1 in result.stdout_text

        result = master.run_command(
            [
                'ipa', 'group-find', '--membermanager-users', USER1
            ],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert "0 groups matched" in result.stdout_text

        result = master.run_command([
            'ipa', 'hostgroup-find', '--membermanager-users', USER_MM
        ])
        assert HOSTGROUP1 in result.stdout_text

        result = master.run_command([
            'ipa', 'hostgroup-find', '--membermanager-groups', GROUP_INDIRECT
        ])
        assert HOSTGROUP1 in result.stdout_text

        result = master.run_command(
            [
                'ipa', 'hostgroup-find', '--membermanager-users', USER1
            ],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert "0 hostgroups matched" in result.stdout_text

    def test_group_member_manager_user(self):
        master = self.master
        # mmuser: add user1 to group
        tasks.kinit_as_user(master, USER_MM, PASSWORD)
        master.run_command([
            'ipa', 'group-add-member', GROUP1, '--users', USER1
        ])
        result = master.run_command(['ipa', 'group-show', GROUP1])
        assert USER1 in result.stdout_text

        # indirect: add user2 to group
        tasks.kinit_as_user(master, USER_INDIRECT, PASSWORD)
        master.run_command([
            'ipa', 'group-add-member', GROUP1, '--users', USER2
        ])
        # verify
        master.run_command(['ipa', 'group-show', GROUP1])
        result = master.run_command(['ipa', 'group-show', GROUP1])
        assert USER2 in result.stdout_text

    def test_group_member_manager_group(self):
        master = self.master
        # mmuser: add group2 to group
        tasks.kinit_as_user(master, USER_MM, PASSWORD)
        master.run_command([
            'ipa', 'group-add-member', GROUP1, '--groups', GROUP2
        ])
        result = master.run_command(['ipa', 'group-show', GROUP1])
        assert GROUP2 in result.stdout_text

    def test_group_member_manager_nopermission(self):
        master = self.master
        tasks.kinit_as_user(master, USER1, PASSWORD)
        result = master.run_command(
            [
                'ipa', 'group-add-member-manager', GROUP1, '--users', USER1
            ],
            raiseonerr=False
        )
        assert result.returncode != 0
        expected = (
            f"member user: {USER1}: Insufficient access: Insufficient "
            "'write' privilege to the 'memberManager' attribute of entry"
        )
        assert expected in result.stdout_text

    def test_hostgroup_member_manager_user(self):
        master = self.master
        # mmuser: add a host to host group
        tasks.kinit_as_user(master, USER_MM, PASSWORD)
        master.run_command([
            'ipa', 'hostgroup-add-member', HOSTGROUP1,
            '--hosts', master.hostname
        ])
        result = master.run_command(['ipa', 'hostgroup-show', HOSTGROUP1])
        assert master.hostname in result.stdout_text
        master.run_command([
            'ipa', 'hostgroup-remove-member', HOSTGROUP1,
            '--hosts', master.hostname
        ])
        result = master.run_command(['ipa', 'hostgroup-show', HOSTGROUP1])
        assert master.hostname not in result.stdout_text

        # indirect:
        tasks.kinit_as_user(master, USER_INDIRECT, PASSWORD)
        master.run_command([
            'ipa', 'hostgroup-add-member', HOSTGROUP1,
            '--hosts', master.hostname
        ])
        result = master.run_command(['ipa', 'hostgroup-show', HOSTGROUP1])
        assert master.hostname in result.stdout_text

    def test_hostgroup_member_manager_nopermission(self):
        master = self.master
        tasks.kinit_as_user(master, USER1, PASSWORD)
        result = master.run_command(
            [
                'ipa', 'hostgroup-add-member-manager', HOSTGROUP1,
                '--users', USER1
            ],
            raiseonerr=False
        )
        assert result.returncode != 0
        expected = (
            f"member user: {USER1}: Insufficient access: Insufficient "
            "'write' privilege to the 'memberManager' attribute of entry"
        )
        assert expected in result.stdout_text
