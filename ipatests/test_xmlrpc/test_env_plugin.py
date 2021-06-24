#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""Test `env` plugin
"""

import pytest

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test


@pytest.mark.tier1
class TestEnv(XMLRPC_test):
    """Test `env` plugin
    """
    EXPECTED_KEYS = ("result", "count", "total", "summary")

    def run_env(self, *args, **options):
        cmd = api.Command.env
        cmd_result = cmd(*args, **options)
        return cmd_result

    def assert_result(self, cmd_result):
        assert tuple(cmd_result.keys()) == self.EXPECTED_KEYS
        result = cmd_result["result"]
        assert isinstance(result, dict)

        total_count = cmd_result["total"]
        assert isinstance(total_count, int)

        actual_count = cmd_result["count"]
        assert isinstance(actual_count, int)
        assert actual_count <= total_count
        assert len(result) == actual_count

        if actual_count > 1:
            assert cmd_result["summary"] == f"{actual_count} variables"
        else:
            assert cmd_result["summary"] is None

    @pytest.mark.parametrize(
        "server", [True, False, None], ids=["server", "local", "local_default"]
    )
    def test_env(self, server):
        options = {}
        if server is not None:
            options = {"server": server}
        cmd_result = self.run_env(**options)
        self.assert_result(cmd_result)
        actual_count = cmd_result["count"]
        assert actual_count >= 1
        assert cmd_result["total"] == actual_count
        assert cmd_result["result"]["in_server"] is (server is True)

    @pytest.mark.parametrize(
        "args, kwargs",
        [(("in_server",), {}), ((), {"variables": "in_server"})],
        ids=["var_as_pos_arg", "var_as_known_arg"],
    )
    @pytest.mark.parametrize(
        "server", [True, False], ids=["server", "local"]
    )
    def test_env_with_variables_one(self, args, kwargs, server):
        kwargs["server"] = server
        cmd_result = self.run_env(*args, **kwargs)
        self.assert_result(cmd_result)
        result = cmd_result["result"]
        assert result["in_server"] is server
        assert cmd_result["count"] == 1

    @pytest.mark.parametrize(
        "args, kwargs",
        [
            (("in_server", "version"), {}),
            ((), {"variables": ("in_server", "version")}),
        ],
        ids=["vars_as_pos_args", "vars_as_known_args"],
    )
    @pytest.mark.parametrize(
        "server", [True, False], ids=["server", "local"]
    )
    def test_env_with_variables_several(self, args, kwargs, server):
        kwargs["server"] = server
        cmd_result = self.run_env(*args, **kwargs)
        self.assert_result(cmd_result)
        result = cmd_result["result"]
        assert result["in_server"] is server
        assert cmd_result["count"] == 2

    @pytest.mark.parametrize("server", [True, False], ids=["server", "local"])
    def test_env_with_variables_missing_var(self, server):
        cmd_result = self.run_env("nonexistentvariable", server=server)
        self.assert_result(cmd_result)
        assert cmd_result["count"] == 0

    @pytest.mark.parametrize("server", [True, False], ids=["server", "local"])
    def test_env_with_nonexistent_option(self, server):
        with pytest.raises(errors.OptionError) as e:
            self.run_env(nonexistentoption="nonexistentoption", server=server)
        assert "Unknown option: nonexistentoption" in str(e.value)
