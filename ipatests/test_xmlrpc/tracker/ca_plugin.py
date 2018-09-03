#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import six

from ipapython.dn import DN
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.xmlrpc_test import (
    fuzzy_issuer,
    fuzzy_caid,
    fuzzy_base64,
    fuzzy_sequence_of,
    fuzzy_bytes,
)
from ipatests.test_xmlrpc import objectclasses


if six.PY3:
    unicode = str


class CATracker(Tracker):
    """Implementation of a Tracker class for CA plugin."""

    ldap_keys = {
        'dn', 'cn', 'ipacaid', 'ipacasubjectdn', 'ipacaissuerdn', 'description'
    }
    cert_keys = {
        'certificate',
    }
    cert_all_keys = {
        'certificate_chain',
    }
    find_keys = ldap_keys
    find_all_keys = {'objectclass'} | ldap_keys
    retrieve_keys = ldap_keys | cert_keys
    retrieve_all_keys = {'objectclass'} | retrieve_keys | cert_all_keys
    create_keys = {'objectclass'} | retrieve_keys
    update_keys = ldap_keys - {'dn'}

    def __init__(self, name, subject, desc=u"Test generated CA",
                 default_version=None):
        super(CATracker, self).__init__(default_version=default_version)
        self.attrs = {}
        self.ipasubjectdn = subject
        self.description = desc

        self.dn = DN(('cn', name),
                     self.api.env.container_ca,
                     self.api.env.basedn)

    def make_create_command(self):
        """Make function that creates the plugin entry object."""
        return self.make_command(
            'ca_add', self.name, ipacasubjectdn=self.ipasubjectdn,
            description=self.description
        )

    def check_create(self, result):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Created CA "{}"'.format(self.name),
            result=dict(self.filter_attrs(self.create_keys))
        ), result)

    def track_create(self):
        self.attrs = dict(
            dn=unicode(self.dn),
            cn=[self.name],
            description=[self.description],
            ipacasubjectdn=[self.ipasubjectdn],
            ipacaissuerdn=[fuzzy_issuer],
            ipacaid=[fuzzy_caid],
            certificate=fuzzy_base64,
            certificate_chain=fuzzy_sequence_of(fuzzy_bytes),
            objectclass=objectclasses.ca
        )
        self.exists = True

    def make_delete_command(self):
        """Make function that deletes the plugin entry object."""
        return self.make_command('ca_del', self.name)

    def check_delete(self, result):
        assert_deepequal(dict(
            value=[self.name],
            summary=u'Deleted CA "{}"'.format(self.name),
            result=dict(failed=[])
        ), result)

    def make_retrieve_command(self, all=False, raw=False, **options):
        """Make function that retrieves the entry using ${CMD}_show"""
        return self.make_command('ca_show', self.name, all=all, raw=raw,
                                 **options)

    def check_retrieve(self, result, all=False, raw=False):
        """Check the plugin's `show` command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.name,
            summary=None,
            result=expected
        ), result)

    def make_find_command(self, *args, **kwargs):
        """Make function that finds the entry using ${CMD}_find

        Note that the name (or other search terms) needs to be specified
        in arguments.
        """
        return self.make_command('ca_find', *args, **kwargs)

    def check_find(self, result, all=False, raw=False):
        """Check the plugin's `find` command result"""
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 CA matched',
            result=[expected]
        ), result)

    def make_update_command(self, updates):
        """Make function that modifies the entry using ${CMD}_mod"""
        return self.make_command('ca_mod', self.name, **updates)

    def check_update(self, result, extra_keys=()):
        """Check the plugin's `find` command result"""
        assert_deepequal(dict(
            value=self.name,
            summary=u'Modified CA "{}"'.format(self.name),
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)
