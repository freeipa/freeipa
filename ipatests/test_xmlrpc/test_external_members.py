# Authors:
#   Ana Krivokapic <akrivoka@redhat.com>
#
# Copyright (C) 2013  Red Hat
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
Test adding/removing external members (trusted domain objects) to IPA groups.
These tests are skipped if trust is not established.
"""

import unittest

from ipalib import api
from ipapython.dn import DN
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, fuzzy_uuid,
                                              fuzzy_user_or_group_sid)
import pytest

group_name = u'external_group'
group_desc = u'Test external group'
group_dn = DN(('cn', group_name), api.env.container_group, api.env.basedn)


def get_trusted_group_name():
    trusts = api.Command['trust_find']()
    if trusts['count'] == 0:
        return None

    ad_netbios = trusts['result'][0]['ipantflatname']
    return r'%s\Domain Admins' % ad_netbios


@pytest.mark.tier1
class test_external_members(Declarative):
    @pytest.fixture(autouse=True, scope="class")
    def ext_member_setup(self, declarative_setup):
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        trusts = api.Command['trust_find']()
        if trusts['count'] == 0:
            raise unittest.SkipTest('Trust is not established')

    cleanup_commands = [
        ('group_del', [group_name], {}),
    ]

    tests = [
        dict(
            desc='Create external group "%s"' % group_name,
            command=(
                'group_add', [group_name], dict(description=group_desc, external=True)
                ),
            expected=dict(
                value=group_name,
                summary=u'Added group "%s"' % group_name,
                result=dict(
                    cn=[group_name],
                    description=[group_desc],
                    objectclass=objectclasses.externalgroup,
                    ipauniqueid=[fuzzy_uuid],
                    dn=group_dn,
                ),
            ),
        ),
        dict(
            desc='Add external member "%s" to group "%s"' % (get_trusted_group_name(), group_name),
            command=(
                'group_add_member', [group_name], dict(ipaexternalmember=get_trusted_group_name())
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result=dict(
                        dn=group_dn,
                        ipaexternalmember=[fuzzy_user_or_group_sid],
                        cn=[group_name],
                        description=[group_desc],
                ),
            ),
        ),
        dict(
            desc='Try to add duplicate external member "%s" to group "%s"' % (get_trusted_group_name(), group_name),
            command=(
                'group_add_member', [group_name], dict(ipaexternalmember=get_trusted_group_name())
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        group=[(fuzzy_user_or_group_sid, u'This entry is already a member')],
                        user=tuple(),
                    ),
                ),
                result=dict(
                        dn=group_dn,
                        ipaexternalmember=[fuzzy_user_or_group_sid],
                        cn=[group_name],
                        description=[group_desc],
                ),
            ),
        ),
        dict(
            desc='Remove external member "%s" from group "%s"' % (get_trusted_group_name(), group_name),
            command=(
                'group_remove_member', [group_name], dict(ipaexternalmember=get_trusted_group_name())
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                ),
                result=dict(
                    dn=group_dn,
                    cn=[group_name],
                    ipaexternalmember=[],
                    description=[group_desc],
                ),
            ),
        ),
        dict(
            desc='Try to remove external entry "%s" which is not a member of group "%s" from group "%s"' % (get_trusted_group_name(), group_name, group_name),
            command=(
                'group_remove_member', [group_name], dict(ipaexternalmember=get_trusted_group_name())
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        group=[(fuzzy_user_or_group_sid, u'This entry is not a member')],
                        user=tuple(),
                    ),
                ),
                result=dict(
                        dn=group_dn,
                        cn=[group_name],
                        description=[group_desc],
                ),
            ),
        ),
    ]
