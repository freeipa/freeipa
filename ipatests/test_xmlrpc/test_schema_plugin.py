#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipaserver/plugins/schema.py` module.
"""

import pytest

from ipalib import api, errors
from ipapython.dnsutil import DNSName
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test


@pytest.mark.tier1
class TestParamFindAndShowCommand(XMLRPC_test):
    """Test functionality of the ipa param-{find,show} command"""
    def run_command(self, command, *args, **options):
        cmd = api.Command[command]
        cmd_result = cmd(*args, **options)
        return cmd_result

    def test_param_find(self):
        """Test param-find command"""
        cmd = "param_find"
        # right command without criteria
        result = self.run_command(cmd, "user-add")
        assert len(result['result']) != 0, result
        assert result['result'][0]['name'] == 'uid', result
        assert result['result'][0]['cli_name'] == 'login', result
        assert result['result'][0]['label'] == 'User login', result

        # right command, right criteria
        criteria = u'postalcode'
        result = self.run_command(cmd, "user-add", criteria)
        assert len(result['result']) != 0, result
        for item in result['result']:
            assert (criteria in item['name'].lower() or
                    criteria in item['doc'].lower()), item

        # right command, wrong criteria
        result = self.run_command(cmd, "user-add", "fake")
        assert len(result['result']) == 0, result

        # wrong command, wrong criteria
        result = self.run_command(cmd, "fake", "fake")
        assert len(result['result']) == 0, result

        # too many args
        with pytest.raises(errors.MaxArgumentError):
            self.run_command(cmd, "arg1", "arg2", "arg3")

    def test_param_show(self):
        """Test param-show command"""
        # right command, right criteria
        criteria = "uid"
        cmd = "param_show"
        result = self.run_command(cmd, "user-add", criteria)
        assert result['result'] is not None, result
        assert result['result']['name'] == 'uid', result
        assert result['result']['cli_name'] == 'login', result
        assert result['result']['label'] == 'User login', result

        # right command without criteria
        with pytest.raises(errors.RequirementError):
            self.run_command(cmd, "user-add")

        # right command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.run_command(cmd, "user-add", "fake")

        # wrong command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.run_command(cmd, "fake", "fake")

        # too many args
        with pytest.raises(errors.MaxArgumentError):
            self.run_command(cmd, "arg1", "arg2", "arg3")


class TestOutputFindAndShowCommand(XMLRPC_test):
    """Test functionality of the ipa output-{find,show} command"""
    def run_command(self, command, *args, **options):
        cmd = api.Command[command]
        cmd_result = cmd(*args, **options)
        return cmd_result

    def test_output_find(self):
        """Test output-find command"""
        cmd = "output_find"
        # right command without criteria
        result = self.run_command(cmd, "user-add")
        assert len(result['result']) != 0, result
        assert result['result'][0]['name'] == 'summary', result
        assert result['result'][0]['doc'] == \
            'User-friendly description of action performed', result

        # right command, right criteria
        criteria = u'result'
        result = self.run_command(cmd, "user-add", criteria)
        assert len(result['result']) == 1, result
        assert criteria in result['result'][0]['name'].lower(), result

        # right command, wrong criteria
        result = self.run_command(cmd, "user-add", "fake")
        assert len(result['result']) == 0, result

        # wrong command, wrong criteria
        result = self.run_command(cmd, "fake", "fake")
        assert len(result['result']) == 0, result

        # too many args
        with pytest.raises(errors.MaxArgumentError):
            self.run_command(cmd, "arg1", "arg2", "arg3")

    def test_output_show(self):
        """Test output-show command"""

        # right command, right criteria
        criteria = "value"
        cmd = "output_show"
        result = self.run_command(cmd, "user-add", criteria)
        assert len(result['result']) != 0, result
        assert criteria in result['result']['name'].lower(), result
        assert result['result']['doc'] == \
            "The primary_key value of the entry, e.g. 'jdoe' for a user", result

        # right command without criteria
        with pytest.raises(errors.RequirementError):
            self.run_command(cmd, "user-add")

        # right command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.run_command(cmd, "user-add", "fake")

        # wrong command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.run_command(cmd, "fake", "fake")

        # too many args
        with pytest.raises(errors.MaxArgumentError):
            self.run_command(cmd, "arg1", "arg2", "arg3")


class TestSchemaCommand(XMLRPC_test):
    """Test functionality of the ipa schema Command(no cli)"""
    expected_keys = {
        "classes", "commands", "fingerprint", "topics", "ttl", "version"
    }

    def run_command(self, command, *args, **options):
        cmd = api.Command[command]
        cmd_result = cmd(*args, **options)
        return cmd_result

    def test_schema_no_args(self):
        """Test schema command without any args"""
        cmd_result = self.run_command("schema")
        result = cmd_result["result"]
        assert result.keys() == self.expected_keys

    def test_schema_known_valid_fp(self):
        """Test schema command with valid fingerprint"""
        # first, fetch current FP to reuse it
        cmd_result = self.run_command("schema")
        result = cmd_result["result"]
        fp_valid = result["fingerprint"]

        with pytest.raises(errors.SchemaUpToDate):
            self.run_command("schema", known_fingerprints=(fp_valid,))

    def test_schema_known_wrong_fp(self):
        """Test schema command with wrong fingerprint"""
        fp_wrong = "wrong FP"
        cmd_result = self.run_command("schema", known_fingerprints=(fp_wrong,))
        result = cmd_result["result"]
        assert result.keys() == self.expected_keys

    def test_schema_too_many_args(self):
        """Test schema with too many args"""
        with pytest.raises(errors.ZeroArgumentError):
            self.run_command("schema", "arg1")


class TestCommandCommand(XMLRPC_test):
    """Test functionality of the ipa 'command' command"""
    expected_keys = {
        "doc",
        "full_name",
        "name",
        "topic_topic",
        "version",
    }

    def run_command(self, command, *args, **options):
        cmd = api.Command[command]
        cmd_result = cmd(*args, **options)
        return cmd_result

    def test_command_find_all(self):
        """Test command-find without any args"""
        cmd_result = self.run_command("command_find")
        result = cmd_result["result"]
        assert len(result) != 0, result
        for item in result:
            assert self.expected_keys.issubset(item.keys()), item

    def test_command_find_existent_command(self):
        """Test 'command' with existent command as arg"""
        criteria = "user_add"
        cmd_result = self.run_command("command_find", criteria)
        result = cmd_result["result"]
        assert len(result) != 0, result
        for item in result:
            assert self.expected_keys.issubset(item.keys()), item
            name = item["name"].lower()
            doc = item.get("doc", "").lower()
            assert criteria in name or criteria in doc, item

    def test_command_find_nonexistent_command(self):
        """Test command-find with nonexistent command as arg"""
        cmd_result = self.run_command("command_find", "nonextentcommand")
        result = cmd_result["result"]
        assert len(result) == 0, result

    def test_command_find_too_many_args(self):
        """Test command-find with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("command_find", "arg1", "arg2")

    def test_command_show_no_args(self):
        """Test command-show without args"""
        with pytest.raises(errors.RequirementError):
            self.run_command("command_show")

    def test_command_show_existent_command(self):
        """Test command-show with existent command as arg"""
        criteria = "user_add"
        cmd_result = self.run_command("command_show", criteria)
        result = cmd_result["result"]
        assert self.expected_keys.issubset(result.keys()), result
        assert result["name"] == criteria

    def test_command_show_nonexistent_command(self):
        """Test command-show with nonexistent command as arg"""
        with pytest.raises(errors.NotFound):
            self.run_command("command_show", "nonextentcommand")

    def test_command_show_too_many_args(self):
        """Test command-show with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("command_show", "arg1", "arg2")

    def test_command_defaults_no_args(self):
        """Test command_defaults without args"""
        with pytest.raises(errors.RequirementError):
            self.run_command("command_defaults")

    def test_command_defaults_existent_command(self):
        """Test command_defaults with existent command as arg"""
        criteria = "user_add"
        cmd_result = self.run_command("command_defaults", criteria)
        # 9c19dd350: do not validate unrequested params in command_defaults
        result = cmd_result["result"]
        assert len(result) == 0, result

    def test_command_defaults_existent_command_params(self):
        """Test command_defaults with existent command as arg with params"""
        criteria = "user_add"
        params = ["all"]
        cmd_result = self.run_command(
            "command_defaults", criteria, params=params
        )
        result = cmd_result["result"]
        assert len(result) == len(params), result
        assert isinstance(result["all"], bool)

    def test_command_defaults_existent_command_several_params(self):
        """
        Test command_defaults with existent command as arg with several params
        """
        criteria = "user_add"
        params = ["all", "raw"]
        cmd_result = self.run_command(
            "command_defaults", criteria, params=params
        )
        result = cmd_result["result"]
        assert len(result) == len(params), result
        assert isinstance(result["all"], bool), result
        assert isinstance(result["raw"], bool), result

    def test_command_defaults_existent_command_kw(self):
        """Test command_defaults with existent command as arg with kw"""
        criteria = "dnszone_add"
        params = ["idnsname"]
        kw = {"name_from_ip": "127.0.0.1"}
        cmd_result = self.run_command(
            "command_defaults", criteria, params=params
        )
        result = cmd_result["result"]
        assert len(result) == 0, result

        cmd_result = self.run_command(
            "command_defaults", criteria, params=params, kw=kw
        )
        result = cmd_result["result"]
        assert len(result) == len(params), result
        assert isinstance(result["idnsname"], DNSName)

    def test_command_defaults_nonexistent_command(self):
        """Test command-show with nonexistent command as arg"""
        with pytest.raises(errors.NotFound):
            self.run_command("command_defaults", "nonextentcommand")

    def test_command_defaults_too_many_args(self):
        """Test command-show with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("command_defaults", "arg1", "arg2")


class TestClassCommand(XMLRPC_test):
    """Test functionality of the ipa 'class' command"""
    expected_keys = {
        "name",
        "full_name",
        "version",
    }

    def run_command(self, command, *args, **options):
        cmd = api.Command[command]
        cmd_result = cmd(*args, **options)
        return cmd_result

    def test_class_find_all(self):
        """Test class-find without any args"""
        cmd_result = self.run_command("class_find")
        result = cmd_result["result"]
        assert len(result) != 0, result
        for item in result:
            assert item.keys() == self.expected_keys, item

    def test_class_find_existent_class(self):
        """Test class-find with existent class as arg"""
        criteria = "user"
        cmd_result = self.run_command("class_find", criteria)
        result = cmd_result["result"]
        assert len(result) != 0, result
        for item in result:
            assert item.keys() == self.expected_keys, item
            name = item["name"].lower()
            doc = item.get("doc", "").lower()
            assert criteria in name or criteria in doc, item

    def test_class_find_nonexistent_class(self):
        """Test class-find with nonexistent class as arg"""
        cmd_result = self.run_command("class_find", "nonextentclass")
        result = cmd_result["result"]
        assert len(result) == 0, result

    def test_class_find_too_many_args(self):
        """Test class-find with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("class_find", "arg1", "arg2")

    def test_class_show_no_args(self):
        """Test class-show without args"""
        with pytest.raises(errors.RequirementError):
            self.run_command("class_show")

    def test_class_show_existent_class(self):
        """Test class-show with existent class as arg"""
        criteria = "user"
        cmd_result = self.run_command("class_show", criteria)
        result = cmd_result["result"]
        assert result.keys() == self.expected_keys, result
        assert result["name"] == criteria

    def test_class_show_nonexistent_class(self):
        """Test class-show with nonexistent class as arg"""
        with pytest.raises(errors.NotFound):
            self.run_command("class_show", "nonextentclass")

    def test_class_show_too_many_args(self):
        """Test class-show with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("class_show", "arg1", "arg2")


class TestTopicCommand(XMLRPC_test):
    """Test functionality of the ipa 'topic' command"""
    expected_keys = {
        "name",
        "full_name",
        "version",
        "doc",
    }

    def run_command(self, command, *args, **options):
        cmd = api.Command[command]
        cmd_result = cmd(*args, **options)
        return cmd_result

    def test_topic_find_all(self):
        """Test topic-find without any args"""
        cmd_result = self.run_command("topic_find")
        result = cmd_result["result"]
        assert len(result) != 0, result
        for item in result:
            assert self.expected_keys.issubset(item.keys()), item

    def test_topic_find_existent_topic(self):
        """Test topic-find with existent topic as arg"""
        criteria = "user"
        cmd_result = self.run_command("topic_find", criteria)
        result = cmd_result["result"]
        assert len(result) != 0, result
        for item in result:
            assert self.expected_keys.issubset(item.keys()), item
            name = item["name"].lower()
            doc = item.get("doc", "").lower()
            assert criteria in name or criteria in doc, item

    def test_topic_find_nonexistent_topic(self):
        """Test topic-find with nonexistent topic as arg"""
        cmd_result = self.run_command("topic_find", "nonextenttopic")
        result = cmd_result["result"]
        assert len(result) == 0, result

    def test_topic_find_too_many_args(self):
        """Test topic-find with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("topic_find", "arg1", "arg2")

    def test_topic_show_no_args(self):
        """Test topic-show without args"""
        with pytest.raises(errors.RequirementError):
            self.run_command("topic_show")

    def test_topic_show_existent_topic(self):
        """Test topic-show with existent topic as arg"""
        criteria = "user"
        cmd_result = self.run_command("topic_show", criteria)
        result = cmd_result["result"]
        assert self.expected_keys.issubset(result.keys()), result
        assert result["name"] == criteria

    def test_topic_show_nonexistent_topic(self):
        """Test topic-show with nonexistent topic as arg"""
        with pytest.raises(errors.NotFound):
            self.run_command("topic_show", "nonextenttopic")

    def test_topic_show_too_many_args(self):
        """Test topic-show with too many args"""
        with pytest.raises(errors.MaxArgumentError):
            self.run_command("topic_show", "arg1", "arg2")
