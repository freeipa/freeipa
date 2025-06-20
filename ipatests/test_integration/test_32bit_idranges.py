#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class Test32BitIdRanges(IntegrationTest):
    topology = "line"

    def test_remove_subid_range(self):
        """
        Test that allocating subid will fail after disabling global option
        """
        master = self.master
        tasks.kinit_admin(master)

        idrange = f"{master.domain.realm}_subid_range"
        master.run_command(
            ["ipa", "config-mod", "--addattr", "ipaconfigstring=SubID:Disable"]
        )
        master.run_command(["ipa", "idrange-del", idrange])

        tasks.user_add(master, 'subiduser')
        result = master.run_command(
            ["ipa", "subid-generate", "--owner", "subiduser"], raiseonerr=False
        )
        assert result.returncode > 0
        assert "Support for subordinate IDs is disabled" in result.stderr_text
        tasks.user_del(master, 'subiduser')

    def test_invoke_upgrader(self):
        """Test that ipa-server-upgrade does not add subid ranges back"""

        master = self.master
        master.run_command(['ipa-server-upgrade'], raiseonerr=True)
        idrange = f"{master.domain.realm}_subid_range"
        result = master.run_command(
            ["ipa", "idrange-show", idrange], raiseonerr=False
        )
        assert result.returncode > 0
        assert f"{idrange}: range not found" in result.stderr_text

        result = tasks.ldapsearch_dm(
            master,
            'cn=Subordinate IDs,cn=Distributed Numeric Assignment Plugin,'
            'cn=plugins,cn=config',
            ['dnaType'],
            scope='base',
            raiseonerr=False
        )
        assert result.returncode == 32
        output = result.stdout_text.lower()
        assert "dnatype: " not in output

    def test_create_user_with_32bit_id(self):
        """Test that ID range above 2^31 can be used to assign IDs
           to users and groups. Also check that SIDs generated properly.
        """

        master = self.master
        idrange = f"{master.domain.realm}_upper_32bit_range"
        id_base = 1 << 31
        id_length = (1 << 31) - 2
        uid = id_base + 1
        gid = id_base + 1
        master.run_command(
            [
                "ipa",
                "idrange-add",
                idrange,
                "--base-id", str(id_base),
                "--range-size", str(id_length),
                "--rid-base", str(int(id_base >> 3)),
                "--secondary-rid-base", str(int(id_base >> 3) + id_length),
                "--type=ipa-local"
            ]
        )

        # We added new ID range, SIDGEN will only take it after
        # restarting a directory server instance.
        tasks.restart_ipa_server(master)

        # Clear SSSD cache to pick up new ID range
        tasks.clear_sssd_cache(master)

        tasks.user_add(master, "user", extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])

        result = master.run_command(
            ["ipa", "user-show", "user", "--all", "--raw"], raiseonerr=False
        )
        assert result.returncode == 0
        assert "ipaNTSecurityIdentifier:" in result.stdout_text

        result = master.run_command(
            ["id", "user"], raiseonerr=False
        )
        assert result.returncode == 0
        assert str(uid) in result.stdout_text

    def test_ssh_login_with_user(self):
        """
        This testcase checks that 32Bit idrange
        associated user is able to login via ssh
        """
        testuser = 'ipauser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ['ipa', 'user-add', testuser, '--first',
             'ipa', '--last', 's',
             '--uid', '2147483650',
             '--gid', '2147483650',
             '--password'], stdin_text=original_passwd
        )
        tasks.ldappasswd_user_change(testuser, original_passwd,
                                     new_passwd,
                                     self.master)
        tasks.kdestroy_all(self.master)
        tasks.run_ssh_cmd(to_host=self.master.external_hostname,
                          username=testuser,
                          auth_method="password",
                          password=new_passwd,
                          expect_auth_success=True)

    def test_sudo_rule_is_applied_to_user(self):
        """
        This testcase checks that sudo rule is applied to
        newly added user
        """
        testuser = 'ipauser'
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ['ipa', 'sudorule-add', 'readfiles']
        )
        self.master.run_command(
            ['ipa', 'sudocmd-add', '/usr/bin/less']
        )
        self.master.run_command(
            ['ipa', 'sudorule-add-allow-command', 'readfiles',
             '--sudocmds', '/usr/bin/less']
        )
        self.master.run_command(
            ['ipa', 'sudorule-add-user',
             'readfiles', '--users', testuser]
        )
        self.master.run_command(
            ['ipa', 'sudorule-add-runasuser', testuser],
            raiseonerr=False
        )

    def test_check_ipa_idrange_fix(self):
        """
        This testcase checks that ipa-idrange-fix tool
        runs with the newly added 32Bit idrange
        """
        idrange_name = f"{self.master.domain.realm}_upper_32bit_range"
        msg = "The ipa-idrange-fix command was successful"
        cmd = self.master.run_command(
            ['ipa-idrange-fix', '--unattended'],
            raiseonerr=False
        )
        assert msg in cmd.stderr_text
        assert idrange_name in cmd.stderr_text
