#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import re
import pytest

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_trust import BaseTestTrust

# The tests focus on 32-bit UID/GID creation and replication,
# SID behavior is not covered in the tests.

# Range with First Posix ID >= 2^31 is considered a 32-bit range.
IDRANGE_32BIT_NAME = "{realm}_upper_32bit_range"
IDRANGE_32BIT_BASE_ID = 1 << 31  # 2147483648


def _32bit_idrange_exists(master):
    """
    Return True if an ipa-local range with base ID >= 2^31 already exists.
    """
    result = master.run_command(
        ["ipa", "idrange-find", "--type", "ipa-local"]
    )
    # Parse all "First Posix ID of the range: in the output'
    for match in re.finditer(
        r"First Posix ID of the range:\s*(\d+)",
        result.stdout_text
    ):
        if int(match.group(1)) >= IDRANGE_32BIT_BASE_ID:
            return True
    return False


def _add_32bit_idrange_if_missing(master):
    """
    Create the 32-bit ID range only if it does not already exist.
    Returns True if the range was added, False if it already existed.
    """
    if _32bit_idrange_exists(master):
        return False
    idrange = IDRANGE_32BIT_NAME.format(realm=master.domain.realm)
    id_length = 10000
    rid_base = 300_000_000
    secondary_rid_base = 500_000_000
    master.run_command(
        [
            "ipa",
            "idrange-add",
            idrange,
            "--base-id", str(IDRANGE_32BIT_BASE_ID),
            "--range-size", str(id_length),
            "--rid-base", str(rid_base),
            "--secondary-rid-base", str(secondary_rid_base),
            "--type=ipa-local"
        ]
    )
    return True


class Test32BitIdRanges(IntegrationTest):
    topology = "line"
    num_replicas = 1
    num_clients = 1
    # Counter for 32-bit UID/GID allocation; reset in install() so each
    # test run starts from 0 (install/uninstall gives a fresh environment).
    id_counter = 0

    @classmethod
    def install(cls, mh):
        super(Test32BitIdRanges, cls).install(mh)
        cls.id_counter = 0

        master = cls.master
        tasks.kinit_admin(master)
        # trigger the SIDgen task in order to immediately
        # generate SID for existing users or groups.
        master.run_command(
            ['ipa', 'config-mod', '--enable-sid', '--add-sids'],
            raiseonerr=False
        )

    def get_next_32bit_id(self):
        """
        Generate unique 32-bit IDs for testing
        """
        self.__class__.id_counter += 1
        return IDRANGE_32BIT_BASE_ID + self.__class__.id_counter

    def test_remove_subid_range(self):
        """
        Test that allocating subids will fail after disabling the attribute
        """
        master = self.master
        tasks.kinit_admin(master)

        idrange = f"{master.domain.realm}_subid_range"
        master.run_command(
            ["ipa", "config-mod", "--addattr", "ipaconfigstring=SubID:Disable"]
        )
        master.run_command(
            ["ipa", "idrange-del", idrange], raiseonerr=False
        )
        master.run_command(["systemctl", "restart", "sssd"])

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

    def test_create_user_with_32bit_id(self):
        """
        Test that ID range above 2^31 can assign IDs to users and groups.
        The 32-bit id range is added after disabling subid,
        and deleting subid range.
        """
        master = self.master
        tasks.kinit_admin(master)
        if _add_32bit_idrange_if_missing(master):
            tasks.restart_ipa_server(master)
            master.run_command(["ipactl", "status"], raiseonerr=True)
            tasks.kinit_admin(master)

        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()

        tasks.clear_sssd_cache(master)
        tasks.user_add(master, "user", extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])
        master.run_command(
            ['ipa', 'config-mod', '--add-sids', '--enable-sid']
        )
        try:
            result = master.run_command(
                ["ipa", "user-find", "user", "--all", "--raw"]
            )
            assert result.returncode == 0, (
                f"User not found: {result.stderr_text}"
            )
        finally:
            tasks.kinit_admin(master)
            tasks.user_del(master, "user")

    def test_create_group_with_32bit_gid(self):
        """
        Test that a group can be created with a GID from the 32-bit range.
        """
        master = self.master
        tasks.kinit_admin(master)
        if _add_32bit_idrange_if_missing(master):
            tasks.restart_ipa_server(master)
            master.run_command(["ipactl", "status"], raiseonerr=True)
            tasks.kinit_admin(master)

        groupname = 'grp32bit'
        gid = self.get_next_32bit_id()
        master.run_command(["ipa", "group-del", groupname], raiseonerr=False)
        tasks.group_add(master, groupname, extra_args=["--gid", str(gid)])
        try:
            result = master.run_command(
                ["ipa", "group-show", groupname, "--all", "--raw"]
            )
            assert result.returncode == 0
            assert str(gid) in result.stdout_text, (
                f"GID {gid} not in group entry"
            )
        finally:
            tasks.kinit_admin(master)
            tasks.group_del(master, groupname)

    def test_user_in_group_with_32bit_ids(self):
        """
        Test user with 32-bit UID in a group with 32-bit GID.
        """
        master = self.master
        tasks.kinit_admin(master)
        if _add_32bit_idrange_if_missing(master):
            tasks.restart_ipa_server(master)
            master.run_command(["ipactl", "status"], raiseonerr=True)
            tasks.kinit_admin(master)

        groupname = 'grp32bit2'
        username = 'user32bit'
        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()
        master.run_command(["ipa", "group-del", groupname], raiseonerr=False)
        master.run_command(["ipa", "user-del", username], raiseonerr=False)
        tasks.group_add(master, groupname, extra_args=["--gid", str(gid)])
        tasks.user_add(master, username, extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])
        try:
            tasks.group_add_member(master, groupname, users=username)
            result = master.run_command(
                ["ipa", "group-show", groupname, "--all"]
            )
            assert result.returncode == 0
            assert username in result.stdout_text
            result = master.run_command(
                ["ipa", "user-show", username, "--all", "--raw"]
            )
            assert result.returncode == 0
            assert str(uid) in result.stdout_text
            assert str(gid) in result.stdout_text
        finally:
            tasks.kinit_admin(master)
            master.run_command(
                ["ipa", "group-remove-member", groupname, "--users", username],
                raiseonerr=False
            )
            tasks.user_del(master, username)
            tasks.group_del(master, groupname)

    def test_getent_32bit_user_on_client(self):
        """
        Verify a user with 32-bit UID/GID is resolvable via getent on client.
        """
        master = self.master
        client = self.clients[0]
        tasks.kinit_admin(master)
        if _add_32bit_idrange_if_missing(master):
            tasks.restart_ipa_server(master)
            master.run_command(["ipactl", "status"], raiseonerr=True)
            tasks.kinit_admin(master)

        username = 'getentuser32'
        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()
        master.run_command(["ipa", "user-del", username], raiseonerr=False)
        tasks.clear_sssd_cache(master)
        tasks.user_add(master, username, extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])
        try:
            tasks.clear_sssd_cache(client)
            result = client.run_command(
                ["getent", "passwd", username], raiseonerr=False
            )
            assert result.returncode == 0, (
                f"getent passwd failed: {result.stderr_text}"
            )
            assert str(uid) in result.stdout_text
            assert str(gid) in result.stdout_text
        finally:
            tasks.kinit_admin(master)
            tasks.user_del(master, username)

    def test_ssh_login_with_32bit_id(self):
        """
        Test that a user with 32-bit UID/GID can be created with a password
        and can log in via SSH from the client to the master.
        """
        master = self.master
        client = self.clients[0]
        if not client.transport.file_exists('/usr/bin/sshpass'):
            pytest.skip('sshpass not available on client')

        tasks.kinit_admin(master)
        testuser = 'sshuser32bit'
        password = 'Secret123'
        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()

        tasks.clear_sssd_cache(master)
        tasks.user_add(master, testuser, extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ], password=password)
        master.run_command(
            ['ipa', 'config-mod', '--add-sids', '--enable-sid']
        )
        try:
            result = master.run_command(
                ["ipa", "user-find", testuser, "--all", "--raw"]
            )
            assert result.returncode == 0, (
                f"User {testuser} not found: {result.stderr_text}"
            )

            tasks.clear_sssd_cache(client)
            tasks.clear_sssd_cache(master)
            result = client.run_command([
                'sshpass', '-p', password, 'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'PasswordAuthentication=yes',
                '-l', testuser, master.hostname, 'echo login successful'
            ], raiseonerr=False)
            assert result.returncode == 0, (
                f"SSH from client to master failed: {result.stderr_text}"
            )
            assert 'login successful' in result.stdout_text, (
                "SSH succeeded but expected output missing: "
                f"{result.stdout_text}"
            )
        finally:
            tasks.kinit_admin(master)
            tasks.user_del(master, testuser)

    def test_32bit_id_replication(self):
        """
        Test that users with 32-bit IDs replicate correctly
        """
        master = self.master
        replica = self.replicas[0]
        tasks.kinit_admin(master)
        testuser = 'repluser32bit'
        uid = self.get_next_32bit_id()
        gid = self.get_next_32bit_id()

        tasks.clear_sssd_cache(master)

        # Create user on master
        tasks.user_add(master, testuser, extra_args=[
            "--uid", str(uid), "--gid", str(gid)
        ])
        try:
            tasks.wait_for_replication(master.ldap_connect())

            result = master.run_command(
                ["ipa", "user-show", testuser, "--all", "--raw"],
                raiseonerr=False
            )
            assert result.returncode == 0, (
                f"User {testuser} not found on master"
            )
            assert str(uid) in result.stdout_text, (
                f"UID {uid} not on master"
            )

            tasks.kinit_admin(replica)
            tasks.clear_sssd_cache(replica)

            result = replica.run_command(
                ["ipa", "user-show", testuser, "--all", "--raw"],
                raiseonerr=False
            )
            assert result.returncode == 0, (
                f"User {testuser} not replicated to replica"
            )
            assert str(uid) in result.stdout_text, (
                f"UID {uid} not on replica"
            )
        finally:
            # Cleanup: Remove test user from master
            tasks.kinit_admin(master)
            tasks.user_del(master, testuser)


class Test32BitIdrangeInTrustEnv(Test32BitIdRanges, BaseTestTrust):
    """
    Tests to check 32BitIdrange functionality
    in IPA-AD trust environment
    """
    topology = 'line'
    num_replicas = 1
    num_ad_domains = 1
    num_ad_subdomains = 0
    num_ad_treedomains = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        # First install AD trust (BaseTestTrust setup)
        super(BaseTestTrust, cls).install(mh)
        cls.ad = cls.ads[0]
        cls.ad_domain = cls.ad.domain.name
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.install_adtrust(cls.master)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

        cls.id_counter = 0
        master = cls.master
        tasks.kinit_admin(master)
        # Do not add the 32-bit id range here: the subid range must be
        # disabled first. The range is added in test_create_user_with_32bit_id
        # (after test_remove_subid_range).
        # Trigger SIDGEN task to process the new ID range when it is added
        master.run_command(
            ['ipa', 'config-mod', '--enable-sid', '--add-sids'],
            raiseonerr=False
        )
