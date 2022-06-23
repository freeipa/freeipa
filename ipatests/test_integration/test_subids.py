#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

"""Tests for subordinate ids
"""
import os

from ipalib.constants import (
    SUBID_COUNT, SUBID_RANGE_START, SUBID_RANGE_MAX, SUBID_DNA_THRESHOLD
)
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestSubordinateId(IntegrationTest):
    num_replicas = 0
    num_clients = 1
    topology = "star"

    def _parse_result(self, result):
        # ipa CLI should get an --outform json option
        info = {}
        for line in result.stdout_text.split("\n"):
            line = line.strip()
            if line:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                try:
                    v = int(v, 10)
                except ValueError:
                    if v == "FALSE":
                        v = False
                    elif v == "TRUE":
                        v = True
                info.setdefault(k.lower(), []).append(v)

        for k, v in info.items():
            if len(v) == 1:
                info[k] = v[0]
            else:
                info[k] = set(v)
        return info

    def assert_subid_info(self, uid, info):
        assert info["ipauniqueid"]
        basedn = self.master.domain.basedn
        assert info["ipaowner"] == f"uid={uid},cn=users,cn=accounts,{basedn}"
        assert info["ipasubuidnumber"] == info["ipasubuidnumber"]
        assert info["ipasubuidnumber"] >= SUBID_RANGE_START
        assert info["ipasubuidnumber"] <= SUBID_RANGE_MAX
        assert info["ipasubuidcount"] == SUBID_COUNT
        assert info["ipasubgidnumber"] == info["ipasubgidnumber"]
        assert info["ipasubgidnumber"] == info["ipasubuidnumber"]
        assert info["ipasubgidcount"] == SUBID_COUNT

    def assert_subid(self, uid, *, match):
        cmd = ["ipa", "subid-find", "--raw", "--owner", uid]
        result = self.master.run_command(cmd, raiseonerr=False)
        if not match:
            assert result.returncode >= 1
            if result.returncode == 1:
                assert "0 subordinate ids matched" in result.stdout_text
            elif result.returncode == 2:
                assert "user not found" in result.stderr_text
            return None
        else:
            assert result.returncode == 0
            assert "1 subordinate id matched" in result.stdout_text
            info = self._parse_result(result)
            self.assert_subid_info(uid, info)
            self.master.run_command(
                ["ipa", "subid-show", info["ipauniqueid"]]
            )
            return info

    def subid_generate(self, uid, **kwargs):
        cmd = ["ipa", "subid-generate"]
        if uid is not None:
            cmd.extend(("--owner", uid))
        return self.master.run_command(cmd, **kwargs)

    def test_dna_config(self):
        conn = self.master.ldap_connect()
        dna_cfg = DN(
            "cn=Subordinate IDs,cn=Distributed Numeric Assignment Plugin,"
            "cn=plugins,cn=config"
        )
        entry = conn.get_entry(dna_cfg)

        def single_int(key):
            return int(entry.single_value[key])

        assert single_int("dnaInterval") == SUBID_COUNT
        assert single_int("dnaThreshold") == SUBID_DNA_THRESHOLD
        assert single_int("dnaMagicRegen") == -1
        assert single_int("dnaMaxValue") == SUBID_RANGE_MAX
        assert set(entry["dnaType"]) == {"ipasubgidnumber", "ipasubuidnumber"}

    def test_auto_generate_subid(self):
        uid = "testuser_auto1"
        passwd = "Secret123"
        tasks.create_active_user(self.master, uid, password=passwd)

        tasks.kinit_admin(self.master)
        self.assert_subid(uid, match=False)

        # add subid by name
        self.subid_generate(uid)
        info = self.assert_subid(uid, match=True)

        # second generate fails due to unique index on ipaowner
        result = self.subid_generate(uid, raiseonerr=False)
        assert result.returncode > 0
        assert f'for user "{uid}" already exists' in result.stderr_text

        # check matching
        subuid = info["ipasubuidnumber"]
        for offset in (0, 1, 65535):
            result = self.master.run_command(
                ["ipa", "subid-match", f"--subuid={subuid + offset}", "--raw"]
            )
            match = self._parse_result(result)
            self.assert_subid_info(uid, match)

    def test_ipa_subid_script(self):
        tasks.kinit_admin(self.master)

        tool = os.path.join(paths.LIBEXEC_IPA_DIR, "ipa-subids")
        users = []
        for i in range(1, 11):
            uid = f"testuser_script{i}"
            users.append(uid)
            tasks.user_add(self.master, uid)
            self.assert_subid(uid, match=False)

        cmd = [tool, "--verbose", "--group", "ipausers"]
        self.master.run_command(cmd)

        for uid in users:
            self.assert_subid(uid, match=True)

    def test_subid_selfservice(self):
        uid1 = "testuser_selfservice1"
        uid2 = "testuser_selfservice2"
        password = "Secret123"
        role = "Subordinate ID Selfservice User"

        tasks.create_active_user(self.master, uid1, password=password)
        tasks.create_active_user(self.master, uid2, password=password)

        tasks.kinit_user(self.master, uid1, password=password)
        self.assert_subid(uid1, match=False)
        result = self.subid_generate(uid1, raiseonerr=False)
        assert result.returncode > 0
        result = self.subid_generate(None, raiseonerr=False)
        assert result.returncode > 0

        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "role-add-member", role, "--groups=ipausers"]
        )

        try:
            tasks.kinit_user(self.master, uid1, password)
            self.subid_generate(uid1)
            self.assert_subid(uid1, match=True)

            # add subid from whoami
            tasks.kinit_as_user(self.master, uid2, password=password)
            self.subid_generate(None)
            self.assert_subid(uid2, match=True)
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "role-remove-member", role, "--groups=ipausers"]
            )

    def test_subid_useradmin(self):
        tasks.kinit_admin(self.master)

        uid_useradmin = "testuser_usermgr_mgr1"
        role = "User Administrator"
        uid = "testuser_usermgr_user1"
        password = "Secret123"

        # create user administrator
        tasks.create_active_user(
            self.master, uid_useradmin, password=password
        )
        # add user to user admin group
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "role-add-member", role, f"--users={uid_useradmin}"],
        )
        # kinit as user admin
        tasks.kinit_user(self.master, uid_useradmin, password)

        # create new user as user admin
        tasks.user_add(self.master, uid)
        # assign new subid to user (with useradmin credentials)
        self.subid_generate(uid)

        # test that user admin can preserve and delete users with subids
        self.master.run_command(["ipa", "user-del", "--preserve", uid])
        # XXX does not work, see subordinate-ids.md
        # subid should still exist
        # self.assert_subid(uid, match=True)
        # final delete should remove the user and subid
        self.master.run_command(["ipa", "user-del", uid])
        self.assert_subid(uid, match=False)

    def tset_subid_auto_assign(self):
        tasks.kinit_admin(self.master)
        uid = "testuser_autoassign_user1"

        self.master.run_command(
            ["ipa", "config-mod", "--user-default-subid=true"]
        )

        try:
            tasks.user_add(self.master, uid)
            self.assert_subid(uid, match=True)
        finally:
            self.master.run_command(
                ["ipa", "config-mod", "--user-default-subid=false"]
            )

    def test_idrange_subid(self):
        tasks.kinit_admin(self.master)

        range_name = f"{self.master.domain.realm}_subid_range"

        result = self.master.run_command(
            ["ipa", "idrange-show", range_name, "--raw"]
        )
        info = self._parse_result(result)

        # see https://github.com/SSSD/sssd/issues/5571
        assert info["iparangetype"] == "ipa-ad-trust"
        assert info["ipabaseid"] == SUBID_RANGE_START
        assert info["ipaidrangesize"] == SUBID_RANGE_MAX - SUBID_RANGE_START
        assert info["ipabaserid"] < SUBID_RANGE_START
        assert "ipasecondarybaserid" not in info
        assert info["ipanttrusteddomainsid"].startswith(
            "S-1-5-21-738065-838566-"
        )

    def test_subid_stats(self):
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "subid-stats"])

    def test_sudid_match_shows_uid(self):
        """
        Test if subid-match command shows UID of the owner instead of DN

        https://pagure.io/freeipa/issue/8977
        """
        uid = "admin"
        self.subid_generate(uid)
        info = self.assert_subid(uid, match=True)
        subuid = info["ipasubuidnumber"]
        result = self.master.run_command(["ipa", "subid-match",
                                          f"--subuid={subuid}"])
        owner = self._parse_result(result)["owner"]
        assert owner == uid

    def test_nsswitch_doesnot_contain_subid_entry(self):
        """
        This testcase checks that when ipa-client-install
        is installed without subid option, the nsswitch.conf
        does not contain subid entry or does not use sss as
        source for subid
        """
        cmd = self.clients[0].run_command(
            ["grep", "^subid", "/etc/nsswitch.conf"],
            raiseonerr=False
        )
        # a source is defined for the subid database.
        # Ensure it is not "sss"
        if cmd.returncode == 0:
            assert 'sss' not in cmd.stdout_text
        else:
            # grep command returncode 1 means no matching line
            # was found = no source is defined for the subid database,
            # which is valid other return codes would
            # mean an error occurred
            assert cmd.returncode == 1

    def test_nsswitch_is_updated_with_subid_entry(self):
        """
        This test case checks that when ipa-client-install
        is installed with --subid option, the nsswitch.conf
        file is modified with the entry 'subid: sss'
        """
        tasks.uninstall_client(self.clients[0])
        tasks.install_client(self.master, self.clients[0],
                             extra_args=['--subid'])
        cmd = self.clients[0].run_command(
            ["grep", "^subid", "/etc/nsswitch.conf"]
        )
        subid = cmd.stdout_text.split()
        assert ['subid:', 'sss'] == subid
