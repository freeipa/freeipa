#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

"""Tests for subordinate ids
"""
import os

from ipalib.constants import SUBID_COUNT, SUBID_RANGE_START, SUBID_RANGE_MAX
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestSubordinateId(IntegrationTest):
    num_replicas = 0
    topology = "star"

    def _parse_result(self, result):
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

    def get_user(self, uid):
        cmd = ["ipa", "user-show", "--all", "--raw", uid]
        result = self.master.run_command(cmd)
        return self._parse_result(result)

    def user_auto_subid(self, uid, **kwargs):
        cmd = ["ipa", "user-auto-subid", uid]
        return self.master.run_command(cmd, **kwargs)

    def test_auto_subid(self):
        tasks.kinit_admin(self.master)
        uid = "testuser_auto1"
        tasks.user_add(self.master, uid)
        info = self.get_user(uid)
        assert "ipasubuidcount" not in info

        self.user_auto_subid(uid)
        info = self.get_user(uid)
        assert "ipasubuidcount" in info

        subuid = info["ipasubuidnumber"]
        result = self.master.run_command(
            ["ipa", "user-match-subid", f"--subuid={subuid}", "--raw"]
        )
        match = self._parse_result(result)
        assert match["uid"] == uid
        assert match["ipasubuidnumber"] == info["ipasubuidnumber"]
        assert match["ipasubuidnumber"] >= SUBID_RANGE_START
        assert match["ipasubuidnumber"] <= SUBID_RANGE_MAX
        assert match["ipasubuidcount"] == SUBID_COUNT
        assert match["ipasubgidnumber"] == info["ipasubgidnumber"]
        assert match["ipasubgidnumber"] == match["ipasubuidnumber"]
        assert match["ipasubgidcount"] == SUBID_COUNT

    def test_ipa_subid_script(self):
        tasks.kinit_admin(self.master)

        tool = os.path.join(paths.LIBEXEC_IPA_DIR, "ipa-subids")
        users = []
        for i in range(1, 11):
            uid = f"testuser_script{i}"
            users.append(uid)
            tasks.user_add(self.master, uid)
            info = self.get_user(uid)
            assert "ipasubuidcount" not in info

        cmd = [tool, "--verbose", "--group", "ipausers"]
        self.master.run_command(cmd)

        for uid in users:
            info = self.get_user(uid)
            assert info["ipasubuidnumber"] >= SUBID_RANGE_START
            assert info["ipasubuidnumber"] <= SUBID_RANGE_MAX
            assert info["ipasubuidnumber"] == info["ipasubgidnumber"]
            assert info["ipasubuidcount"] == SUBID_COUNT
            assert info["ipasubuidcount"] == info["ipasubgidcount"]

    def test_subid_selfservice(self):
        tasks.kinit_admin(self.master)

        uid = "testuser_selfservice1"
        password = "Secret123"
        role = "Subordinate ID Selfservice User"

        tasks.user_add(self.master, uid, password=password)
        tasks.kinit_user(
            self.master, uid, f"{password}\n{password}\n{password}\n"
        )
        info = self.get_user(uid)
        assert "ipasubuidcount" not in info
        result = self.user_auto_subid(uid, raiseonerr=False)
        assert result.returncode > 0

        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "role-add-member", role, "--groups=ipausers"]
        )

        try:
            tasks.kinit_user(self.master, uid, password)
            self.user_auto_subid(uid)
            info = self.get_user(uid)
            assert "ipasubuidcount" in info
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
        tasks.user_add(self.master, uid_useradmin, password=password)
        # add user to user admin group
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "role-add-member", role, f"--users={uid_useradmin}"],
        )
        # kinit as user admin
        tasks.kinit_user(
            self.master,
            uid_useradmin,
            f"{password}\n{password}\n{password}\n",
        )
        # create new user as user admin
        tasks.user_add(self.master, uid)
        # assign new subid to user (with useradmin credentials)
        self.user_auto_subid(uid)

    def test_subordinate_default_objclass(self):
        tasks.kinit_admin(self.master)

        result = self.master.run_command(
            ["ipa", "config-show", "--raw", "--all"]
        )
        info = self._parse_result(result)
        usercls = info["ipauserobjectclasses"]
        assert "ipasubordinateid" not in usercls

        cmd = [
            "ipa",
            "config-mod",
            "--addattr",
            "ipaUserObjectClasses=ipasubordinateid",
        ]
        self.master.run_command(cmd)

        uid = "testuser_usercls1"
        tasks.user_add(self.master, uid)
        info = self.get_user(uid)
        assert "ipasubuidcount" in info

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
