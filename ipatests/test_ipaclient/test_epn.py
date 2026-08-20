#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
import os

import pytest
import ipatests.util

ipatests.util.check_ipaclient_unittests()

from ipaclient.install.ipa_epn import drop_privileges
from ipapython import admintool


@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="Must have root privileges to run this test",
)
@pytest.mark.parametrize(
    "user,group", [
        ("unknown_user", "daemon"),
        ("daemon", "unknown_group"),
        ("unknown_user", "unknown_group")])
def test_drop_privileges(user, group):
    """ Test the drop_privileges method with unknown uid/gid"""
    try:
        drop_privileges(user, group)
    except admintool.ScriptError:
        # Raised error as expected
        pass
    else:
        assert False
