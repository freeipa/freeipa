#
# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information

from ipalib import api, errors
from ipapython.dn import DN

from ipatests.test_xmlrpc.xmlrpc_test import (fuzzy_set_optional_oc,
                                              fuzzy_string)
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal


class SysaccountTracker(Tracker):
    """Class for sysaccount plugin tests"""

    retrieve_keys = {
        'dn', 'uid', 'description', 'memberof', 'nsaccountlock', 'has_password'
    }

    retrieve_all_keys = retrieve_keys | {
        'objectclass', 'ipauniqueid', 'privileged'
    }

    create_keys = retrieve_all_keys | {
        'randompassword', 'userpassword'
    }
    create_keys = create_keys - {'has_password', 'ipauniqueid'}

    update_keys = retrieve_keys - {'dn'}

    find_keys = retrieve_keys - {'has_password'}
    find_all_keys = retrieve_all_keys - {'has_password'}

    primary_keys = {'uid', 'dn'}

    def __init__(self, name, description=None, **kwargs):
        super(SysaccountTracker, self).__init__(default_version=None)
        self.uid = name
        self.description = description
        self.dn = DN(('uid', self.uid), api.env.container_sysaccounts,
                     api.env.basedn)
        self.kwargs = kwargs

    def make_create_command(self, random=True, **kwargs):
        """Make function that creates a sysaccount using sysaccount_add"""
        options = dict(random=random, **self.kwargs)
        options.update(kwargs)
        if self.description:
            options['description'] = self.description
        return self.make_command('sysaccount_add', self.uid, **options)

    def make_delete_command(self):
        """Make function that deletes a sysaccount using sysaccount_del"""
        return self.make_command('sysaccount_del', self.uid)

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves a sysaccount using sysaccount_show"""
        return self.make_command('sysaccount_show', self.uid, all=all)

    def make_find_command(self, *args, **kwargs):
        """Make function that searches for sysaccounts using sysaccount_find"""
        return self.make_command('sysaccount_find', *args, **kwargs)

    def make_update_command(self, updates):
        """Make function that updates a sysaccount using sysaccount_mod"""
        return self.make_command('sysaccount_mod', self.uid, **updates)

    def create(self, force=False):
        """Helper function to create an entry and check the result"""
        if force:
            # If force is True, ensure the entry doesn't exist first
            self.ensure_missing()
        elif self.exists:
            # If we think it exists, verify it actually exists
            try:
                retrieve_cmd = self.make_retrieve_command(all=True)
                retrieve_cmd()
                # Entry exists, don't try to create it again
                return
            except errors.NotFound:
                # Entry doesn't actually exist, reset our state
                self.exists = False

        self.track_create()
        command = self.make_create_command()
        try:
            result = command()
            self.check_create(result)
        except errors.DuplicateEntry:
            # Entry already exists, update our state to reflect this
            self.exists = True
            # Retrieve the entry to update our attrs
            retrieve_cmd = self.make_retrieve_command(all=True)
            retrieve_result = retrieve_cmd()
            # Update attrs from the retrieved entry
            for key, value in retrieve_result['result'].items():
                if key in self.create_keys:
                    if isinstance(value, tuple):
                        self.attrs[key] = list(value)
                    else:
                        self.attrs[key] = [value] if not isinstance(
                            value, list) else value

    def _normalize_result_dict(self, result_dict):
        """Normalize a result dictionary to match expected format"""
        normalized = {}
        for key, value in result_dict.items():
            if key == 'dn':
                # DN is handled by assert_deepequal
                normalized[key] = value
            elif isinstance(value, tuple):
                normalized[key] = list(value)
            elif isinstance(value, bool):
                # Convert boolean to list for consistency with expected format
                normalized[key] = [value]
            elif key == 'randompassword' and isinstance(value, str):
                # randompassword comes as a string but we expect it in a list
                # The Fuzzy matcher will handle the actual value
                normalized[key] = [value]
            else:
                normalized[key] = value
        return normalized

    def track_create(self):
        """Updates expected state for sysaccount creation"""
        self.attrs = dict(
            dn=self.dn,
            uid=[self.uid],
            objectclass=fuzzy_set_optional_oc(
                ['top', 'account', 'simplesecurityobject'],
                'nsmemberof'),
            nsaccountlock=[False],
            privileged=[False],
            randompassword=[fuzzy_string],
        )
        if self.description:
            self.attrs['description'] = [self.description]
        self.exists = True

    def check_create(self, result):
        """Checks 'sysaccount_add' command result"""
        # Filter out messages if present (SystemAccountUsage message)
        result_copy = dict(result)
        if 'messages' in result_copy:
            del result_copy['messages']

        # Filter the actual result to only include keys we expect
        expected_result = dict(
            value=self.uid,
            summary=u'Added system account "%s"' % self.uid,
            result=self.filter_attrs(self.create_keys)
        )

        # Normalize and filter the actual result
        actual_result = result_copy.get('result', {})
        filtered_result = {
            'value': result_copy.get('value'),
            'summary': result_copy.get('summary'),
            'result': self._normalize_result_dict({
                k: v for k, v in actual_result.items()
                if k in self.create_keys
            })
        }

        assert_deepequal(expected_result, filtered_result)

    def check_delete(self, result):
        """Checks 'sysaccount_del' command result"""
        assert_deepequal(dict(
            value=[self.uid],
            summary=u'Deleted system account "%s"' % self.uid,
            result=dict(failed=[])
        ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """Checks 'sysaccount_show' command result"""
        if all:
            expected_keys = self.retrieve_all_keys
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected_keys = self.retrieve_keys
            expected = self.filter_attrs(self.retrieve_keys)

        # Filter the actual result to only include keys we expect
        filtered_result = {
            'value': result.get('value'),
            'summary': result.get('summary'),
            'result': {
                k: v for k, v in result.get('result', {}).items()
                if k in expected_keys
            }
        }

        assert_deepequal(dict(
            value=self.uid,
            summary=None,
            result=expected
        ), filtered_result)

    def check_find(self, result, all=False, raw=False):
        """Checks 'sysaccount_find' command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        # Find can return multiple results, so we check if our entry is in list
        found = False
        for entry in result['result']:
            uid_value = entry.get('uid')
            # Handle both tuple and list formats
            if isinstance(uid_value, tuple):
                uid_value = list(uid_value)
            if uid_value == [self.uid]:
                found = True
                assert_deepequal(expected, entry)
                break
        assert found, f"Sysaccount {self.uid} not found in result"

    def check_update(self, result, extra_keys={}):
        """Checks 'sysaccount_mod' command result"""
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Modified system account "%s"' % self.uid,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)
