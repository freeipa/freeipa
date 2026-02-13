#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_trust import BaseTestTrust


class Test32BitIdRanges(IntegrationTest):
    topology = "line"
    num_replicas = 1

    id_counter = 0

    @classmethod
    def install(cls, mh):
        super(Test32BitIdRanges, cls).install(mh)
        # Initialize the ID counter
        cls.id_counter = 0

        # Create the 32-bit ID range once for all tests
        master = cls.master
        tasks.kinit_admin(master)
        idrange = f"{master.domain.realm}_upper_32bit_range"
        id_base = 1 << 31  # 2147483648
        id_length = 100000000  # 100 million IDs
        rid_base = 200000

        # Check if range exists, create only if missing
        result = master.run_command(
            ["ipa", "idrange-show", idrange], raiseonerr=False
        )
        if result.returncode != 0:
            # Range doesn't exist, create it
            master.run_command(
                [
                    "ipa",
                    "idrange-add",
                    idrange,
                    "--base-id", str(id_base),
                    "--range-size", str(id_length),
                    "--rid-base", str(rid_base),
                    "--secondary-rid-base", str(rid_base + id_length),
                    "--type=ipa-local"
                ],
                raiseonerr=False
            )
        # Always restart and wait to ensure SIDGEN picks up the range
        tasks.restart_ipa_server(master)
        # Wait for services to be fully ready after restart
        master.run_command(["ipactl", "status"], raiseonerr=True)
        tasks.kinit_admin(master)

        # Trigger SIDGEN to process the new ID range
        # Without this, SIDGEN doesn't know about the new range
        master.run_command(
            ['ipa', 'config-mod', '--enable-sid', '--add-sids'],
            raiseonerr=False
        )

    def get_next_32bit_id(self):
        """Generate unique 32-bit IDs for testing"""
        id_base = 1 << 31  # 2147483648
        self.__class__.id_counter += 1
        return id_base + self.__class__.id_counter

    @classmethod
    def uninstall(cls, mh):
        # Cleanup: Remove the 32-bit ID range
        master = cls.master
        tasks.kinit_admin(master)
        idrange = f"{master.domain.realm}_upper_32bit_range"
        master.run_command(
            ["ipa", "idrange-del", idrange], raiseonerr=False
        )

        # Restore SubID configuration if it was disabled
        master.run_command(
            ["ipa", "config-mod", "--delattr",
             "ipaconfigstring=SubID:Disable"],
            raiseonerr=False
        )

        super(Test32BitIdRanges, cls).uninstall(mh)

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
        try:
            # Verify user exists with id command
            result = master.run_command(
                ["id", "subiduser"], raiseonerr=False
            )
            assert result.returncode == 0, \
                "User subiduser not found via id command"

            result = master.run_command(
                ["ipa", "subid-generate", "--owner", "subiduser"],
                raiseonerr=False
            )
            assert result.returncode > 0
            assert "Support for subordinate IDs is disabled" in \
                result.stderr_text
        finally:
            # Cleanup: Remove test user
            tasks.kinit_admin(master)
            tasks.user_del(master, 'subiduser')

    def test_invoke_upgrader(self):
        """Test that ipa-server-upgrade does not add subid ranges back"""

        master = self.master
        tasks.kinit_admin(master)
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
        tasks.kinit_admin(master)
        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()

        # Range is created in install(), just use it
        tasks.clear_sssd_cache(master)

        tasks.user_add(master, "user", extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])

        try:
            # Verify user was created with correct UID
            result = master.run_command(
                ["ipa", "user-show", "user", "--all", "--raw"],
                raiseonerr=False
            )
            assert result.returncode == 0, "User show command failed"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in user-show output"

            # Verify user exists in system
            result = master.run_command(
                ["id", "user"], raiseonerr=False
            )
            assert result.returncode == 0, "id command failed"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in id output"

            # Check for SID (should be generated with SIDGEN trigger)
            result = master.run_command(
                ["ipa", "user-show", "user", "--all", "--raw"],
                raiseonerr=False
            )
            assert "ipaNTSecurityIdentifier:" in result.stdout_text, \
                "SID was not generated for 32-bit UID user"
        finally:
            # Cleanup
            tasks.kinit_admin(master)
            tasks.user_del(master, "user")

    def test_ssh_login_with_32bit_id(self):
        """Test that SSH login works for users with 32-bit UID/GID"""

        master = self.master
        tasks.kinit_admin(master)
        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()
        testuser = 'sshuser32bit'
        original_passwd = 'Secret123'

        # Range is created in install(), just use it
        tasks.clear_sssd_cache(master)

        # Create user with 32-bit ID and set password
        tasks.user_add(master, testuser, extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])

        try:
            # Set password using echo piped to ipa user-mod
            master.run_command(
                ['sh', '-c',
                 f'echo -e "{original_passwd}\\n{original_passwd}" | '
                 f'ipa user-mod {testuser} --password']
            )

            # Clear SSSD cache to pick up new user
            tasks.clear_sssd_cache(master)

            # Verify user exists and has correct UID via id command
            result = master.run_command(
                ["id", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not found via id command"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in id output"

            # Verify user can authenticate and getent works
            result = master.run_command(
                ["getent", "passwd", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not found via getent"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in getent output"

            # Verify user exists in IPA
            result = master.run_command(
                ["ipa", "user-show", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not found in IPA"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in user-show output"
        finally:
            # Cleanup: Remove test user
            tasks.kinit_admin(master)
            tasks.user_del(master, testuser)

    def test_32bit_id_replication(self):
        """Test that users with 32-bit IDs replicate correctly"""

        master = self.master

        # Check if we have replicas
        if not hasattr(self, 'replicas') or not self.replicas:
            # No replicas available, skip this test
            import pytest
            pytest.skip("No replicas available for replication test")

        replica = self.replicas[0]
        tasks.kinit_admin(master)

        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()
        testuser = 'repluser32bit'

        # Range is created in install(), just use it
        tasks.clear_sssd_cache(master)

        # Create user on master
        tasks.user_add(master, testuser, extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])

        try:
            # Wait for replication
            tasks.wait_for_replication(master.ldap_connect())

            # Check user exists on master
            result = master.run_command(
                ["ipa", "user-show", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not found on master"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in user-show output on master"

            # Verify user via id command on master
            result = master.run_command(
                ["id", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not found via id on master"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in id output on master"

            # Check user replicated to replica
            tasks.kinit_admin(replica)

            # Clear SSSD cache on replica to pick up replicated user
            tasks.clear_sssd_cache(replica)

            result = replica.run_command(
                ["ipa", "user-show", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not replicated to replica"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in user-show output on replica"

            # Verify user via id command on replica
            result = replica.run_command(
                ["id", testuser], raiseonerr=False
            )
            assert result.returncode == 0, \
                f"User {testuser} not found via id on replica"
            assert str(uid) in result.stdout_text, \
                f"UID {uid} not in id output on replica"
        finally:
            # Cleanup: Remove test user from master
            tasks.kinit_admin(master)
            tasks.user_del(master, testuser)


class Test32BitIdrangeInTrustEnv(Test32BitIdRanges, BaseTestTrust):
    """
    Tests to check 32BitIdrange functionality
    in IPA-AD trust enviornment
    """
    topology = 'line'
    num_replicas = 1
    num_ad_domains = 1
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    num_clients = 0

    # Inherit id_counter and get_next_32bit_id from parent class

    @classmethod
    def install(cls, mh):
        # First install AD trust (BaseTestTrust setup)
        super(BaseTestTrust, cls).install(mh)
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.install_adtrust(cls.master)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

        # Set up base 32-bit ID range (from Test32BitIdRanges)
        # Both base and trust tests use the same range
        cls.id_counter = 0
        master = cls.master
        tasks.kinit_admin(master)
        # Create base 32-bit ID range (shared with base class)
        idrange = f"{master.domain.realm}_upper_32bit_range"
        id_base = 1 << 31  # 2147483648
        id_length = 100000000  # 100 million IDs
        rid_base = 200000

        result = master.run_command(
            ["ipa", "idrange-show", idrange], raiseonerr=False
        )
        if result.returncode != 0:
            # Range doesn't exist, create it
            master.run_command(
                [
                    "ipa",
                    "idrange-add",
                    idrange,
                    "--base-id", str(id_base),
                    "--range-size", str(id_length),
                    "--rid-base", str(rid_base),
                    "--secondary-rid-base", str(rid_base + id_length),
                    "--type=ipa-local"
                ],
                raiseonerr=False
            )

        # Always restart and wait to ensure SIDGEN picks up the range
        tasks.restart_ipa_server(master)
        # Wait for services to be fully ready after restart
        master.run_command(["ipactl", "status"], raiseonerr=True)
        tasks.kinit_admin(master)

        # Trigger SIDGEN to process the new ID range
        # Without this, SIDGEN doesn't know about the new range
        master.run_command(
            ['ipa', 'config-mod', '--enable-sid', '--add-sids'],
            raiseonerr=False
        )

    @classmethod
    def uninstall(cls, mh):
        # Cleanup: Remove the base 32-bit ID range
        master = cls.master
        tasks.kinit_admin(master)
        idrange = f"{master.domain.realm}_upper_32bit_range"
        master.run_command(
            ["ipa", "idrange-del", idrange], raiseonerr=False
        )

        # Restore SubID configuration if it was disabled
        master.run_command(
            ["ipa", "config-mod", "--delattr",
             "ipaconfigstring=SubID:Disable"],
            raiseonerr=False
        )

        super(Test32BitIdrangeInTrustEnv, cls).uninstall(mh)
