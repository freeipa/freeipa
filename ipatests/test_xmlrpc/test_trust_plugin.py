# Authors:
#   Martin Kosek <mkosek@redhat.com>
#
# Copyright (C) 2010  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test the `ipaserver/plugins/trust.py` module.
"""

import unittest

import six

from ipalib import api, errors
from ipapython.dn import DN
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (
    Declarative, fuzzy_guid, fuzzy_domain_sid, fuzzy_string, fuzzy_uuid,
    fuzzy_digits)
import pytest

if six.PY3:
    unicode = str


trustconfig_ad_config = DN(('cn', api.env.domain),
        api.env.container_cifsdomains, api.env.basedn)
testgroup = u'adtestgroup'
testgroup_dn = DN(('cn', testgroup), api.env.container_group, api.env.basedn)

default_group = u'Default SMB Group'
default_group_dn = DN(('cn', default_group), api.env.container_group, api.env.basedn)


@pytest.mark.tier1
class test_trustconfig(Declarative):
    @pytest.fixture(autouse=True, scope="class")
    def trustconfig_setup(self, declarative_setup):
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()
        try:
           api.Command['trustconfig_show'](trust_type=u'ad')
        except errors.NotFound:
            raise unittest.SkipTest('Trusts are not configured')

    cleanup_commands = [
        ('group_del', [testgroup], {}),
        ('trustconfig_mod', [], {'trust_type': u'ad',
            'ipantfallbackprimarygroup': default_group}),
    ]

    tests = [

        dict(
            desc='Retrieve trust configuration for AD domains',
            command=('trustconfig_show', [], {'trust_type': u'ad'}),
            expected={
                'value': u'ad',
                'summary': None,
                'result': {
                    'dn': trustconfig_ad_config,
                    'cn': [api.env.domain],
                    'ipantdomainguid': [fuzzy_guid],
                    'ipantfallbackprimarygroup': [default_group],
                    'ipantflatname': [fuzzy_string],
                    'ipantsecurityidentifier': [fuzzy_domain_sid],
                    'ad_trust_agent_server': [api.env.host],
                    'ad_trust_controller_server': [api.env.host]
                },
            },
        ),

        dict(
            desc='Retrieve trust configuration for AD domains with --raw',
            command=('trustconfig_show', [], {'trust_type': u'ad', 'raw': True}),
            expected={
                'value': u'ad',
                'summary': None,
                'result': {
                    'dn': trustconfig_ad_config,
                    'cn': [api.env.domain],
                    'ipantdomainguid': [fuzzy_guid],
                    'ipantfallbackprimarygroup': [default_group_dn],
                    'ipantflatname': [fuzzy_string],
                    'ipantsecurityidentifier': [fuzzy_domain_sid]
                },
            },
        ),

        dict(
            desc='Create auxiliary group %r' % testgroup,
            command=(
                'group_add', [testgroup], dict(description=u'Test group')
            ),
            expected=dict(
                value=testgroup,
                summary=u'Added group "%s"' % testgroup,
                result=dict(
                    cn=[testgroup],
                    description=[u'Test group'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=testgroup_dn,
                ),
            ),
        ),

        dict(
            desc='Try to change primary fallback group to nonexistent group',
            command=('trustconfig_mod', [],
                {'trust_type': u'ad', 'ipantfallbackprimarygroup': u'doesnotexist'}),
            expected=errors.NotFound(reason=u'%s: group not found' % 'doesnotexist')
        ),

        dict(
            desc='Try to change primary fallback group to nonexistent group DN',
            command=('trustconfig_mod', [], {'trust_type': u'ad',
                'ipantfallbackprimarygroup': u'cn=doesnotexist,dc=test'}),
            expected=errors.NotFound(reason=u'%s: group not found' % 'cn=doesnotexist,dc=test')
        ),

        dict(
            desc='Change primary fallback group to "%s"' % testgroup,
            command=('trustconfig_mod', [], {'trust_type': u'ad',
                'ipantfallbackprimarygroup': testgroup}),
            expected={
                'value': u'ad',
                'summary': u'Modified "ad" trust configuration',
                'result': {
                    'cn': [api.env.domain],
                    'ipantdomainguid': [fuzzy_guid],
                    'ipantfallbackprimarygroup': [testgroup],
                    'ipantflatname': [fuzzy_string],
                    'ipantsecurityidentifier': [fuzzy_domain_sid],
                    'ad_trust_agent_server': [api.env.host],
                    'ad_trust_controller_server': [api.env.host]
                },
            },
        ),

        dict(
            desc='Change primary fallback group back to "%s" using DN' % default_group,
            command=('trustconfig_mod', [], {'trust_type': u'ad',
                 'ipantfallbackprimarygroup': unicode(default_group_dn)}),
            expected={
                'value': u'ad',
                'summary': u'Modified "ad" trust configuration',
                'result': {
                    'cn': [api.env.domain],
                    'ipantdomainguid': [fuzzy_guid],
                    'ipantfallbackprimarygroup': [default_group],
                    'ipantflatname': [fuzzy_string],
                    'ipantsecurityidentifier': [fuzzy_domain_sid],
                    'ad_trust_agent_server': [api.env.host],
                    'ad_trust_controller_server': [api.env.host]
                },
            },
        ),
    ]
