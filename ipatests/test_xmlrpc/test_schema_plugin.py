#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipaserver/plugins/schema.py` module.
"""

import pytest

from ipalib import errors
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
