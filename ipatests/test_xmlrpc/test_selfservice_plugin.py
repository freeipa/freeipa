# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Test the `ipaserver/plugins/selfservice.py` module.
"""

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
import pytest

selfservice1 = u'testself'
invalid_selfservice1 = u'bad+name'

selfservice_bz1 = u'selfservice_bz_1'
selfservice_bz2 = u'selfservice_bz_2'
selfservice_bz3 = u'selfservice_bz_3'
selfservice_bz4 = u'selfservice_bz_4'
selfservice_bz5 = u'selfservice_bz_5'


@pytest.mark.tier1
class test_selfservice(Declarative):

    cleanup_commands = [
        ('selfservice_del', [selfservice1], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Try to update non-existent %r' % selfservice1,
            command=('selfservice_mod', [selfservice1],
                dict(permissions=u'write')),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Try to delete non-existent %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=errors.NotFound(
                reason=u'ACI with name "%s" not found' % selfservice1),
        ),


        dict(
            desc='Search for non-existent %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 selfservices matched',
                result=[],
            ),
        ),


        # Note that we add postalCode but expect postalcode. This tests
        # the attrs normalizer.
        dict(
            desc='Create %r' % selfservice1,
            command=(
                'selfservice_add', [selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                )
            ),
            expected=dict(
                value=selfservice1,
                summary=u'Added selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % selfservice1,
            command=(
                'selfservice_add', [selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                ),
            ),
            expected=errors.DuplicateEntry(),
        ),


        dict(
            desc='Retrieve %r' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                    'permissions': [u'write'],
                    'selfaci': True,
                    'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Retrieve %r with --raw' % selfservice1,
            command=('selfservice_show', [selfservice1], {'raw':True}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                    'aci': u'(targetattr = "street || c || l || st || postalcode")(version 3.0;acl "selfservice:testself";allow (write) userdn = "ldap:///self";)',
                },
            ),
        ),


        dict(
            desc='Search for %r' % selfservice1,
            command=('selfservice_find', [selfservice1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),

        dict(
            desc='Search for %r with --pkey-only' % selfservice1,
            command=('selfservice_find', [selfservice1], {'pkey_only' : True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with empty attrs and permissions' % selfservice1,
            command=('selfservice_find', [selfservice1], {'attrs' : None, 'permissions' : None}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'write'],
                        'selfaci': True,
                        'aciname': selfservice1,
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw' % selfservice1,
            command=('selfservice_find', [selfservice1], {'raw':True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aci': u'(targetattr = "street || c || l || st || postalcode")(version 3.0;acl "selfservice:testself";allow (write) userdn = "ldap:///self";)'
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % selfservice1,
            command=(
                'selfservice_mod', [selfservice1], dict(permissions=u'read')
            ),
            expected=dict(
                value=selfservice1,
                summary=u'Modified selfservice "%s"' % selfservice1,
                result=dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=[u'read'],
                    selfaci=True,
                    aciname=selfservice1,
                ),
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'read'],
                        'selfaci': True,
                        'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Try to update %r with empty permissions' % selfservice1,
            command=(
                'selfservice_mod', [selfservice1], dict(permissions=None)
            ),
            expected=errors.RequirementError(name='permissions'),
        ),


        dict(
            desc='Retrieve %r to verify invalid update' % selfservice1,
            command=('selfservice_show', [selfservice1], {}),
            expected=dict(
                value=selfservice1,
                summary=None,
                result={
                        'attrs': [u'street', u'c', u'l', u'st', u'postalcode'],
                        'permissions': [u'read'],
                        'selfaci': True,
                        'aciname': selfservice1,
                },
            ),
        ),


        dict(
            desc='Delete %r' % selfservice1,
            command=('selfservice_del', [selfservice1], {}),
            expected=dict(
                result=True,
                value=selfservice1,
                summary=u'Deleted selfservice "%s"' % selfservice1,
            )
        ),

        dict(
            desc='Create invalid %r' % invalid_selfservice1,
            command=(
                'selfservice_add', [invalid_selfservice1], dict(
                    attrs=[u'street', u'c', u'l', u'st', u'postalcode'],
                    permissions=u'write',
                )
            ),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, and space'),
        ),

    ]


@pytest.mark.tier1
class TestSelfserviceMisc(Declarative):
    """Bugzilla regression tests for selfservice plugin."""

    cleanup_commands = [
        ('selfservice_del', [selfservice_bz1], {}),
        ('selfservice_del', [selfservice_bz2], {}),
        ('selfservice_del', [selfservice_bz3], {}),
        ('selfservice_del', [selfservice_bz4], {}),
        ('selfservice_del', [selfservice_bz5], {}),
    ]

    tests = [

        # BZ 772106: selfservice-add with --raw must not return internal error

        dict(
            desc='Create %r with --raw for BZ 772106' % selfservice_bz1,
            command=(
                'selfservice_add', [selfservice_bz1],
                dict(attrs=[u'l'], raw=True),
            ),
            expected=dict(
                value=selfservice_bz1,
                summary=u'Added selfservice "%s"' % selfservice_bz1,
                result={
                    'aci': u'(targetattr = "l")(version 3.0;acl '
                           u'"selfservice:%s";allow (write) '
                           u'userdn = "ldap:///self";)'
                           % selfservice_bz1,
                },
            ),
        ),

        dict(
            desc='Delete %r' % selfservice_bz1,
            command=('selfservice_del', [selfservice_bz1], {}),
            expected=dict(
                result=True,
                value=selfservice_bz1,
                summary=u'Deleted selfservice "%s"' % selfservice_bz1,
            ),
        ),


        # BZ 772675: selfservice-mod with --raw must not return internal error

        dict(
            desc='Create %r for BZ 772675' % selfservice_bz2,
            command=(
                'selfservice_add', [selfservice_bz2],
                dict(attrs=[u'l']),
            ),
            expected=dict(
                value=selfservice_bz2,
                summary=u'Added selfservice "%s"' % selfservice_bz2,
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice_bz2,
                ),
            ),
        ),

        dict(
            desc='Modify %r with --raw for BZ 772675' % selfservice_bz2,
            command=(
                'selfservice_mod', [selfservice_bz2],
                dict(attrs=[u'mobile'], raw=True),
            ),
            expected=dict(
                value=selfservice_bz2,
                summary=u'Modified selfservice "%s"' % selfservice_bz2,
                result={
                    'aci': u'(targetattr = "mobile")(version 3.0;acl '
                           u'"selfservice:%s";allow (write) '
                           u'userdn = "ldap:///self";)'
                           % selfservice_bz2,
                },
            ),
        ),

        dict(
            desc='Delete %r' % selfservice_bz2,
            command=('selfservice_del', [selfservice_bz2], {}),
            expected=dict(
                result=True,
                value=selfservice_bz2,
                summary=u'Deleted selfservice "%s"' % selfservice_bz2,
            ),
        ),


        # BZ 747730: selfservice-mod --permissions="" must not delete the entry

        dict(
            desc='Create %r for BZ 747730' % selfservice_bz3,
            command=(
                'selfservice_add', [selfservice_bz3],
                dict(attrs=[u'l']),
            ),
            expected=dict(
                value=selfservice_bz3,
                summary=u'Added selfservice "%s"' % selfservice_bz3,
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice_bz3,
                ),
            ),
        ),

        dict(
            desc='Modify %r with empty permissions for BZ 747730'
                 % selfservice_bz3,
            command=(
                'selfservice_mod', [selfservice_bz3],
                dict(permissions=u''),
            ),
            # mod may succeed or fail; the only requirement is that the
            # entry must not be deleted (callable accepts any outcome)
            expected=lambda got, output: True,
        ),

        dict(
            desc='Verify %r still exists after BZ 747730' % selfservice_bz3,
            command=('selfservice_show', [selfservice_bz3], {}),
            # entry must still be retrievable (not deleted by the mod)
            expected=lambda got, output: (
                got is None
                and output.get('result', {}).get('aciname')
                == selfservice_bz3
            ),
        ),

        dict(
            desc='Delete %r' % selfservice_bz3,
            command=('selfservice_del', [selfservice_bz3], {}),
            expected=dict(
                result=True,
                value=selfservice_bz3,
                summary=u'Deleted selfservice "%s"' % selfservice_bz3,
            ),
        ),


        # BZ 747741: selfservice-mod --attrs=badattrs must not delete the entry

        dict(
            desc='Create %r for BZ 747741' % selfservice_bz4,
            command=(
                'selfservice_add', [selfservice_bz4],
                dict(attrs=[u'l']),
            ),
            expected=dict(
                value=selfservice_bz4,
                summary=u'Added selfservice "%s"' % selfservice_bz4,
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice_bz4,
                ),
            ),
        ),

        dict(
            desc='Modify %r with bad attrs for BZ 747741'
                 % selfservice_bz4,
            command=(
                'selfservice_mod', [selfservice_bz4],
                dict(attrs=[u'badattrs']),
            ),
            # mod may succeed or fail; the only requirement is that the
            # entry must not be deleted (callable accepts any outcome)
            expected=lambda got, output: True,
        ),

        dict(
            desc='Verify %r still exists after BZ 747741' % selfservice_bz4,
            command=('selfservice_show', [selfservice_bz4], {}),
            # entry must still be retrievable (not deleted by the mod)
            expected=lambda got, output: (
                got is None
                and output.get('result', {}).get('aciname')
                == selfservice_bz4
            ),
        ),

        dict(
            desc='Delete %r' % selfservice_bz4,
            command=('selfservice_del', [selfservice_bz4], {}),
            expected=dict(
                result=True,
                value=selfservice_bz4,
                summary=u'Deleted selfservice "%s"' % selfservice_bz4,
            ),
        ),


        # BZ 747693: selfservice-find with --raw must not return internal error

        dict(
            desc='Create %r for BZ 747693' % selfservice_bz5,
            command=(
                'selfservice_add', [selfservice_bz5],
                dict(attrs=[u'l']),
            ),
            expected=dict(
                value=selfservice_bz5,
                summary=u'Added selfservice "%s"' % selfservice_bz5,
                result=dict(
                    attrs=[u'l'],
                    permissions=[u'write'],
                    selfaci=True,
                    aciname=selfservice_bz5,
                ),
            ),
        ),

        dict(
            desc='Find %r with --raw for BZ 747693' % selfservice_bz5,
            command=('selfservice_find', [selfservice_bz5],
                dict(raw=True)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 selfservice matched',
                result=[
                    {
                        'aci': u'(targetattr = "l")(version 3.0;acl '
                               u'"selfservice:%s";allow (write) '
                               u'userdn = "ldap:///self";)'
                               % selfservice_bz5,
                    },
                ],
            ),
        ),

        dict(
            desc='Delete %r' % selfservice_bz5,
            command=('selfservice_del', [selfservice_bz5], {}),
            expected=dict(
                result=True,
                value=selfservice_bz5,
                summary=u'Deleted selfservice "%s"' % selfservice_bz5,
            ),
        ),


        # BZ 747720: selfservice-find --permissions="" must not return
        # internal error

        dict(
            desc='BZ 747720: selfservice-find with empty permissions',
            command=('selfservice_find', [], dict(permissions=u'')),
            # must succeed and return a result list, not an internal error
            expected=lambda got, output: (
                got is None
                and isinstance(output.get('result'), (list, tuple))
            ),
        ),


        # BZ 747722: selfservice-find --attrs="" must not return
        # internal error

        dict(
            desc='BZ 747722: selfservice-find with empty attrs',
            command=('selfservice_find', [], dict(attrs=u'')),
            # must succeed and return a result list, not an internal error
            expected=lambda got, output: (
                got is None
                and isinstance(output.get('result'), (list, tuple))
            ),
        ),

    ]
