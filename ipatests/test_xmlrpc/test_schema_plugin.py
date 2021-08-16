#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipaserver/plugins/schema.py` module.
"""

import pytest

from ipalib import api, errors
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test


@pytest.mark.tier1
class TestParamFindAndShowCommand(XMLRPC_test):
    """Test functionality of the ipa param-{find,show} command"""

    tracker = Tracker()

    def test_param_find(self):
        """Test param-find command"""

        # right command without criteria
        result = self.tracker.run_command('param_find', u'user-add')
        assert len(result['result']) != 0, result
        assert result['result'][0]['name'] == 'uid', result
        assert result['result'][0]['cli_name'] == 'login', result
        assert result['result'][0]['label'] == 'User login', result

        # right command, right criteria
        criteria = u'postalcode'
        result = self.tracker.run_command('param_find', u'user-add', criteria)
        assert len(result['result']) != 0, result
        for item in result['result']:
            assert (criteria in item['name'].lower() or
                    criteria in item['doc'].lower()), item

        # right command, wrong criteria
        result = self.tracker.run_command('param_find', u'user-add', u'fake')
        assert len(result['result']) == 0, result

        # wrong command, wrong criteria
        result = self.tracker.run_command('param_find', u'fake', u'fake')
        assert len(result['result']) == 0, result

    def test_param_show(self):
        """Test param-show command"""

        # right command, right criteria
        criteria = u'uid'
        result = self.tracker.run_command('param_show', u'user-add', criteria)
        assert result['result'] is not None, result
        assert result['result']['name'] == 'uid', result
        assert result['result']['cli_name'] == 'login', result
        assert result['result']['label'] == 'User login', result

        # right command without criteria
        with pytest.raises(errors.RequirementError):
            self.tracker.run_command('param_show', u'user-add')

        # right command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.tracker.run_command('param_show', u'user-add', u'fake')

        # wrong command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.tracker.run_command('param_show', u'fake', u'fake')


class TestOutputFindAndShowCommand(XMLRPC_test):
    """Test functionality of the ipa output-{find,show} command"""
    tracker = Tracker()

    def test_output_find(self):
        """Test output-find command"""

        # right command without criteria
        result = self.tracker.run_command('output_find', u'user-add')
        assert len(result['result']) != 0, result
        assert result['result'][0]['name'] == 'summary', result
        assert result['result'][0]['doc'] == \
            'User-friendly description of action performed', result

        # right command, right criteria
        criteria = u'result'
        result = self.tracker.run_command('output_find', u'user-add', criteria)
        assert len(result['result']) == 1, result
        assert criteria in result['result'][0]['name'].lower(), result

        # right command, wrong criteria
        result = self.tracker.run_command('output_find', u'user-add', u'fake')
        assert len(result['result']) == 0, result

        # wrong command, wrong criteria
        result = self.tracker.run_command('output_find', u'fake', u'fake')
        assert len(result['result']) == 0, result

    def test_output_show(self):
        """Test output-show command"""

        # right command, right criteria
        criteria = u'value'
        result = self.tracker.run_command('output_show', u'user-add', criteria)
        assert len(result['result']) != 0, result
        assert criteria in result['result']['name'].lower(), result
        assert result['result']['doc'] == \
            "The primary_key value of the entry, e.g. 'jdoe' for a user", result

        # right command without criteria
        with pytest.raises(errors.RequirementError):
            self.tracker.run_command('output_show', u'user-add')

        # right command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.tracker.run_command('output_show', u'user-add', u'fake')

        # wrong command, wrong criteria
        with pytest.raises(errors.NotFound):
            self.tracker.run_command('output_show', u'fake', u'fake')


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
