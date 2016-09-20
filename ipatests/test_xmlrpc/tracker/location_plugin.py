#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import six

from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.tracker.base import Tracker


if six.PY3:
    unicode = str


class LocationTracker(Tracker):
    """Tracker for IPA Location tests"""
    retrieve_keys = {
        'idnsname', 'description', 'dn', 'servers_server', 'dns_server'}
    retrieve_all_keys = retrieve_keys | {'objectclass'}
    create_keys = {'idnsname', 'description', 'dn', 'objectclass'}
    find_keys = {'idnsname', 'description', 'dn',}
    find_all_keys = find_keys | {'objectclass'}
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

        self.servers = {}

    def make_create_command(self):
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
            servers=self.servers,
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

    def add_server_to_location(
            self, server_name, weight=100, relative_weight=u"100.0%"):
        self.attrs.setdefault('servers_server', []).append(server_name)
        self.attrs.setdefault('dns_server', []).append(server_name)
        self.servers[server_name] = {
            'cn': [server_name],
            'ipaserviceweight': [unicode(weight)],
            'service_relative_weight': [relative_weight],
            'enabled_role_servrole': lambda other: True
        }

    def remove_server_from_location(self, server_name):
        if 'servers_server' in self.attrs:
            try:
                self.attrs['servers_server'].remove(server_name)
                self.attrs['dns_server'].remove(server_name)
            except ValueError:
                pass
            else:
                if not self.attrs['servers_server']:
                    del self.attrs['servers_server']
                if not self.attrs['dns_server']:
                    del self.attrs['dns_server']
        try:
            del self.servers[server_name]
        except KeyError:
            pass
