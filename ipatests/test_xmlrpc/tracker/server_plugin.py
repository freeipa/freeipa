#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

from ipapython.dn import DN
from ipatests.util import assert_deepequal
from ipatests.test_xmlrpc.tracker.base import Tracker


class ServerTracker(Tracker):
    """Tracker for IPA Location tests"""
    retrieve_keys = {
        'cn', 'dn', 'ipamaxdomainlevel', 'ipamindomainlevel',
        'iparepltopomanagedsuffix_topologysuffix', 'ipalocation_location',
        'ipaserviceweight',
    }
    retrieve_all_keys = retrieve_keys | {'objectclass'}
    create_keys = retrieve_keys | {'objectclass'}
    find_keys = {
        'cn', 'dn', 'ipamaxdomainlevel', 'ipamindomainlevel',
        'ipaserviceweight',
    }
    find_all_keys = retrieve_all_keys
    update_keys = {
        'cn', 'ipamaxdomainlevel', 'ipamindomainlevel',
        'ipalocation_location', 'ipaserviceweight',
    }

    def __init__(self, name):
        super(ServerTracker, self).__init__(default_version=None)
        self.server_name = name
        self.dn = DN(
            ('cn', self.server_name),
            'cn=masters,cn=ipa,cn=etc',
            self.api.env.basedn
        )
        self.exists = True  # we cannot add server manually using server-add
        self.attrs = dict(
            dn=self.dn,
            cn=[self.server_name],
            iparepltopomanagedsuffix_topologysuffix=[u'domain', u'ca'],
            objectclass=[
                u"ipalocationmember",
                u"ipaReplTopoManagedServer",
                u"top",
                u"ipaConfigObject",
                u"nsContainer",
                u"ipaSupportedDomainLevelConfig"
            ],
            ipamaxdomainlevel=[u"1"],
            ipamindomainlevel=[u"0"],
        )
        self.exists = True

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves this server using server-show"""
        return self.make_command(
            'server_show', self.name, all=all, raw=raw
        )

    def make_find_command(self, *args, **kwargs):
        """Make function that finds servers using server-find"""
        return self.make_command('server_find', *args, **kwargs)

    def make_update_command(self, updates):
        """Make function that modifies the server using server-mod"""
        return self.make_command('server_mod', self.name, **updates)

    def check_retrieve(self, result, all=False, raw=False):
        """Check `server-show` command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(dict(
            value=self.server_name,
            summary=None,
            result=expected,
        ), result)

    def check_find(self, result, all=False, raw=False):
        """Check `server-find` command result"""
        if all:
            expected = self.filter_attrs(self.find_all_keys)
        else:
            expected = self.filter_attrs(self.find_keys)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 IPA server matched',
            result=[expected],
        ), result)

    def check_find_nomatch(self, result):
        """ Check 'server-find' command result when no match is expected """
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 IPA servers matched',
            result=[],
        ), result)

    def check_update(self, result, extra_keys=()):
        """Check `server-update` command result"""
        assert_deepequal(dict(
            value=self.server_name,
            summary=u'Modified IPA server "{server}"'.format(server=self.name),
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)
