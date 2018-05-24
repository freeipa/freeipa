# Copyright (C) 2018  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import tempfile

import pytest

from ipaclient.install.client import check_ldap_conf
from ipapython.admintool import ScriptError


@pytest.mark.parametrize("lines,expected", [
    (["PORT 389"], "PORT"),
    (["HOST example.org"], "HOST"),
    (["HOST example.org", "# PORT 389"], "HOST"),
    (["\tHOST example.org", "# PORT 389"], "HOST"),
    (["HOST example.org", "PORT 389"], "HOST, PORT"),
    (["# HOST example.org", "# PORT 389"], None),
    (["URI PORT"], None),
    ([], None),
])
def test_check_ldap(lines, expected):
    with tempfile.NamedTemporaryFile('w+') as f:
        for line in lines:
            f.write(line)
            f.write('\n')
        f.write('\n')
        f.flush()

        if expected is None:
            assert check_ldap_conf(f.name) is True
        else:
            with pytest.raises(ScriptError) as e:
                check_ldap_conf(f.name)
            msg = e.value.msg
            assert msg.endswith(expected)
