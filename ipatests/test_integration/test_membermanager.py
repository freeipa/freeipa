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

    @tasks.pytest.fixture
    def prepare_mbr_manager_upgrade(self):
        user = "idmuser"
        password = "Secret123"
        group1 = "role-groupmanager"
        group2 = "role-usergroup-A"

        master = self.master

        tasks.kinit_admin(master)
        tasks.group_add(master, group1)
        tasks.group_add(master, group2)
        tasks.create_active_user(master, user, password)

        tasks.kinit_admin(master)
        tasks.group_add_member(master, group1, user)
        master.run_command(["ipa", "group-add-member-manager", "--groups",
                            group1, group2])

        yield user, password, group2

        # cleanup
        tasks.kinit_admin(master)
        tasks.user_del(master, user)
        tasks.group_del(master, group1)
        tasks.group_del(master, group2)

    def test_member_manager_upgrade_scenario(self, prepare_mbr_manager_upgrade):
        """
        Testing if manager whose rights defined by the group membership
        is able to add group members, after upgrade of ipa server.
        Using ACI modification to demonstrate unability before upgrading
        ipa server.

        Related: https://pagure.io/freeipa/issue/9286
        """
        user, password, group2 = prepare_mbr_manager_upgrade

        master = self.master

        base_dn = self.master.domain.basedn
        aci_hostgroup = (
            '(targetattr = "member")(targetfilter = '
            '"(objectclass=ipaHostGroup)")'
            '(version 3.0; acl "Allow member managers '
            'to modify members of host groups"; allow (write) userattr = '
            '"memberManager#USERDN" or userattr = "memberManager#GROUPDN";)'
        )
        aci_usergroup = (
            '(targetattr = "member")(targetfilter = '
            '"(objectclass=ipaUserGroup)")'
            '(version 3.0; acl "Allow member managers '
            'to modify members of user groups"; allow (write) userattr = '
            '"memberManager#USERDN" or userattr = "memberManager#GROUPDN";)'
        )
        ldif_entry = tasks.textwrap.dedent(
            """
            dn: cn=hostgroups,cn=accounts,{base_dn}
            changetype: modify
            delete: aci
            aci: {aci_hostgroup}

            dn: cn=groups,cn=accounts,{base_dn}
            changetype: modify
            delete: aci
            aci: {aci_usergroup}
""").format(base_dn=base_dn,
            aci_hostgroup=aci_hostgroup,
            aci_usergroup=aci_usergroup)
        tasks.ldapmodify_dm(master, ldif_entry)

        tasks.kinit_as_user(master, user, password)
        # in this point this command should fail
        result = tasks.group_add_member(master, group2, "admin",
                                        raiseonerr=False)
        assert result.returncode == 1
        assert "Insufficient access" in result.stdout_text

        master.run_command(['ipa-server-upgrade'])
        tasks.group_add_member(master, group2, "admin")
