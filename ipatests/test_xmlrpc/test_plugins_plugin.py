#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""Test `plugins` plugin
"""

import pytest

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test


@pytest.mark.tier1
class TestPlugins(XMLRPC_test):
    """Test `plugins` plugin
    """
    EXPECTED_KEYS = ("result", "count", "summary")

    def run_plugins(self, *args, **options):
        cmd = api.Command.plugins
        cmd_result = cmd(*args, **options)
        return cmd_result

    def assert_result(self, cmd_result):
        assert tuple(cmd_result.keys()) == self.EXPECTED_KEYS
        result = cmd_result["result"]
        assert isinstance(result, dict)

        actual_count = cmd_result["count"]
        assert isinstance(actual_count, int)
        assert len(result) == actual_count

        expected_summaries = (
            f"{actual_count} plugin loaded", f"{actual_count} plugins loaded"
        )
        assert cmd_result["summary"] in expected_summaries

    @pytest.mark.parametrize(
        "server", [True, False, None], ids=["server", "local", "local_default"]
    )
    def test_plugins(self, server):
        options = {}
        if server is not None:
            options = {"server": server}
        cmd_result = self.run_plugins(**options)
        self.assert_result(cmd_result)
        assert cmd_result["count"] >= 1

    @pytest.mark.parametrize("server", [True, False], ids=["server", "local"])
    def test_plugins_with_nonexistent_argument(self, server):
        with pytest.raises(errors.ZeroArgumentError):
            self.run_plugins("nonexistentarg", server=server)

    @pytest.mark.parametrize("server", [True, False], ids=["server", "local"])
    def test_plugins_with_nonexistent_option(self, server):
        with pytest.raises(errors.OptionError) as e:
            self.run_plugins(
                nonexistentoption="nonexistentoption", server=server
            )
        assert "Unknown option: nonexistentoption" in str(e.value)
