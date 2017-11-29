# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
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
Test the `ipaserver/plugins/batch.py` module.
"""

from ipalib import api
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import Fuzzy, assert_deepequal
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, fuzzy_digits,
                                              fuzzy_uuid)
from ipapython.dn import DN
import pytest

group1 = u'testgroup1'
first1 = u'John'


def deepequal_list(*expected):
    """Factory for a function that checks a list

    The created function asserts items of a list are "deepequal" to the given
    argument. Unlike using assert_deepequal directly, the order matters.
    """
    def checker(got):
        if len(expected) != len(got):
            raise AssertionError('Expected %s entries, got %s\n\n%s\n%s' %
                (len(expected), len(got), expected, got))
        for e, g in zip(expected, got):
            assert_deepequal(e, g)
        return True
    return checker


@pytest.mark.tier1
class test_batch(Declarative):

    cleanup_commands = [
        ('group_del', [group1], {}),
    ]

    tests = [

        dict(
            desc='Batch ping',
            command=('batch', [dict(method=u'ping', params=([], {}))], {}),
            expected=dict(
                count=1,
                results=[
                    dict(summary=Fuzzy('IPA server version .*'), error=None),
                ]
            ),
        ),

        dict(
            desc='Batch two pings',
            command=('batch', [dict(method=u'ping', params=([], {}))] * 2, {}),
            expected=dict(
                count=2,
                results=[
                    dict(summary=Fuzzy('IPA server version .*'), error=None),
                    dict(summary=Fuzzy('IPA server version .*'), error=None),
                ]
            ),
        ),

        dict(
            desc='Create and deleting a group',
            command=('batch', [
                dict(method=u'group_add',
                    params=([group1], dict(description=u'Test desc 1'))),
                dict(method=u'group_del', params=([group1], dict())),
            ], {}),
            expected=dict(
                count=2,
                results=deepequal_list(
                    dict(
                        value=group1,
                        summary=u'Added group "testgroup1"',
                        result=dict(
                            cn=[group1],
                            description=[u'Test desc 1'],
                            objectclass=objectclasses.group + [u'posixgroup'],
                            ipauniqueid=[fuzzy_uuid],
                            gidnumber=[fuzzy_digits],
                            dn=DN(('cn', 'testgroup1'),
                                  ('cn', 'groups'),
                                  ('cn', 'accounts'),
                                  api.env.basedn),
                            ),
                        error=None),
                    dict(
                        summary=u'Deleted group "%s"' % group1,
                        result=dict(failed=[]),
                        value=[group1],
                        error=None),
                ),
            ),
        ),

        dict(
            desc='Try to delete nonexistent group twice',
            command=('batch', [
                dict(method=u'group_del', params=([group1], dict())),
                dict(method=u'group_del', params=([group1], dict())),
            ], {}),
            expected=dict(
                count=2,
                results=[
                    dict(
                        error=u'%s: group not found' % group1,
                        error_name=u'NotFound',
                        error_code=4001,
                        error_kw=dict(
                            reason=u'%s: group not found' % group1,
                        ),
                    ),
                    dict(
                        error=u'%s: group not found' % group1,
                        error_name=u'NotFound',
                        error_code=4001,
                        error_kw=dict(
                            reason=u'%s: group not found' % group1,
                        ),
                    ),
                ],
            ),
        ),

        dict(
            desc='Try to delete non-existent group first, then create it',
            command=('batch', [
                dict(method=u'group_del', params=([group1], dict())),
                dict(method=u'group_add',
                    params=([group1], dict(description=u'Test desc 1'))),
            ], {}),
            expected=dict(
                count=2,
                results=deepequal_list(
                    dict(
                        error=u'%s: group not found' % group1,
                        error_name=u'NotFound',
                        error_code=4001,
                        error_kw=dict(
                            reason=u'%s: group not found' % group1,
                        ),
                    ),
                    dict(
                        value=group1,
                        summary=u'Added group "testgroup1"',
                        result=dict(
                            cn=[group1],
                            description=[u'Test desc 1'],
                            objectclass=objectclasses.group + [u'posixgroup'],
                            ipauniqueid=[fuzzy_uuid],
                            gidnumber=[fuzzy_digits],
                            dn=DN(('cn', 'testgroup1'),
                                  ('cn', 'groups'),
                                  ('cn', 'accounts'),
                                  api.env.basedn),
                            ),
                        error=None),
                ),
            ),
        ),

        dict(
            desc='Try bad command invocations',
            command=('batch', [
                # bad command name
                dict(method=u'nonexistent_ipa_command', params=([], dict())),
                # dash, not underscore, in command name
                dict(method=u'user-del', params=([], dict())),
                # missing command name
                dict(params=([group1], dict())),
                # missing params
                dict(method=u'user_del'),
                # missing required argument
                dict(method=u'user_add', params=([], dict())),
                # missing required option
                dict(method=u'user_add', params=([], dict(givenname=first1))),
                # bad type
                dict(method=u'group_add', params=([group1], dict(
                        description=u't', gidnumber=u'bad'))),
            ], {}),
            expected=dict(
                count=7,
                results=deepequal_list(
                    dict(
                        error=u"unknown command 'nonexistent_ipa_command'",
                        error_name=u'CommandError',
                        error_code=905,
                        error_kw=dict(
                            name=u'nonexistent_ipa_command',
                        ),
                    ),
                    dict(
                        error=u"unknown command 'user-del'",
                        error_name=u'CommandError',
                        error_code=905,
                        error_kw=dict(
                            name=u'user-del',
                        ),
                    ),
                    dict(
                        error=u"'method' is required",
                        error_name=u'RequirementError',
                        error_code=3007,
                        error_kw=dict(
                            name=u'method',
                        ),
                    ),
                    dict(
                        error=u"'params' is required",
                        error_name=u'RequirementError',
                        error_code=3007,
                        error_kw=dict(
                            name=u'params',
                        ),
                    ),
                    dict(
                        error=u"'givenname' is required",
                        error_name=u'RequirementError',
                        error_code=3007,
                        error_kw=dict(
                            name=u'givenname',
                        ),
                    ),
                    dict(
                        error=u"'sn' is required",
                        error_name=u'RequirementError',
                        error_code=3007,
                        error_kw=dict(
                            name=u'sn',
                        ),
                    ),
                    dict(
                        error=Fuzzy(u"invalid 'gid'.*"),
                        error_name=u'ConversionError',
                        error_code=3008,
                        error_kw=dict(
                            name=u'gid',
                            error=Fuzzy(u'.*'),
                        ),
                    ),
                ),
            ),
        ),

    ]
