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

    def test_create_user_with_32bit_id(self):
        """Test that ID range for 2^31..2^32-1 can be used"""

        master = self.master
        idrange = f"{master.domain.realm}_upper_32bit_range"
        id_base = 2 << 31
        id_length = (2 << 31) - 2
        uid = id_base + 2
        gid = id_base + 2
        master.run_command(
            [
                "ipa",
                "idrange-add",
                idrange,
                "--base-id", str(id_base),
                "--range-size", str(id_length),
                "--rid-base", str(int(id_base >> 1)),
                "--secondary-rid-base", str(id_base + int(id_base >> 1)),
                "--type=ipa-local"
            ]
        )

        tasks.user_add(master, "user", extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])

        result = master.run_command(
            ["ipa", "user-show", "user", "--all", "--raw"], raiseonerr=False
        )
        assert result.returncode == 0
        assert "ipantsecurityidentifier:" in result.stdout_text
