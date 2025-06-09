#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_trust import BaseTestTrust


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


class Test32BitIdrangeInTrustEnv(Test32BitIdRanges, BaseTestTrust):
    """
    Tests to check 32BitIdrange functionality
    in IPA-AD trust enviornment
    """
    topology = 'line'
    num_ad_domains = 1
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        super(BaseTestTrust, cls).install(mh)
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.install_adtrust(cls.master)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)
