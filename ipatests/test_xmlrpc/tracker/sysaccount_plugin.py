#
# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information

from ipalib import api
from ipapython.dn import DN

from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_set_optional_oc, fuzzy_uuid
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
    create_keys = create_keys - {'has_password'}

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

    def track_create(self):
        """Updates expected state for sysaccount creation"""
        self.attrs = dict(
            dn=self.dn,
            uid=[self.uid],
            ipauniqueid=[fuzzy_uuid],
            objectclass=fuzzy_set_optional_oc(
                ['top', 'account', 'simplesecurityobject'],
                'nsmemberof'),
            nsaccountlock=[False],
            has_password=[True],
        )
        if self.description:
            self.attrs['description'] = [self.description]
        self.exists = True

    def check_create(self, result):
        """Checks 'sysaccount_add' command result"""
        assert_deepequal(dict(
            value=self.uid,
            summary=u'Added system account "%s"' % self.uid,
            result=self.filter_attrs(self.create_keys)
        ), result)

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
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.uid,
            summary=None,
            result=expected
        ), result)

    def check_find(self, result, all=False, raw=False):
        """Checks 'sysaccount_find' command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        # Find can return multiple results, so we check if our entry is in list
        found = False
        for entry in result['result']:
            if entry.get('uid') == [self.uid]:
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
