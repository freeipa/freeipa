#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.tracker.base import Tracker


class LocationTracker(Tracker):
    """Tracker for IPA Location tests"""
    retrieve_keys = {'idnsname', 'description', 'dn'}
    retrieve_all_keys = retrieve_keys | {'objectclass'}
    create_keys = retrieve_keys | {'objectclass'}
    find_keys = retrieve_keys
    find_all_keys = retrieve_all_keys
    update_keys = {'idnsname', 'description'}

    def __init__(self, name, description=u"Location description"):
        super(LocationTracker, self).__init__(default_version=None)
        # ugly hack to allow testing invalid inputs
        try:
            self.idnsname_obj = DNSName(name)
        except Exception:
            self.idnsname_obj = DNSName(u"placeholder-for-invalid-value")

        self.idnsname = name
        self.description = description
        self.dn = DN(
            ('idnsname', self.idnsname_obj.ToASCII()),
            'cn=locations',
            'cn=etc', self.api.env.basedn
        )

    def make_create_command(self, force=None):
        """Make function that creates this location using location-add"""
        return self.make_command(
            'location_add', self.idnsname, description=self.description,
        )

    def make_delete_command(self):
        """Make function that removes this location using location-del"""
        return self.make_command('location_del', self.idnsname)

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves this location using location-show"""
        return self.make_command(
            'location_show', self.idnsname, all=all, raw=raw
        )

    def make_find_command(self, *args, **kwargs):
        """Make function that finds locations using location-find"""
        return self.make_command('location_find', *args, **kwargs)

    def make_update_command(self, updates):
        """Make function that modifies the location using location-mod"""
        return self.make_command('location_mod', self.idnsname, **updates)

    def track_create(self):
        """Update expected state for location creation"""

        self.attrs = dict(
            dn=self.dn,
            idnsname=[self.idnsname_obj],
            description=[self.description],
            objectclass=[u'top', u'ipaLocationObject'],
        )
        self.exists = True

    def check_create(self, result):
        """Check `location-add` command result"""
        assert_deepequal(dict(
            value=self.idnsname_obj,
            summary=u'Added IPA location "{loc}"'.format(loc=self.idnsname),
            result=self.filter_attrs(self.create_keys)
        ), result)

    def check_delete(self, result):
        """Check `location-del` command result"""
        assert_deepequal(dict(
            value=[self.idnsname_obj],
            summary=u'Deleted IPA location "{loc}"'.format(loc=self.idnsname),
            result=dict(failed=[]),
        ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """Check `location-show` command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(dict(
            value=self.idnsname_obj,
            summary=None,
            result=expected,
        ), result)

    def check_find(self, result, all=False, raw=False):
        """Check `location-find` command result"""
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 IPA location matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys=()):
        """Check `location-update` command result"""
        assert_deepequal(dict(
            value=self.idnsname_obj,
            summary=u'Modified IPA location "{loc}"'.format(loc=self.idnsname),
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)
