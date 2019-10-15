# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Test the `ipaserver/plugins/netgroup.py` module.
"""

from ipalib import api
from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, fuzzy_digits,
                                              fuzzy_uuid, fuzzy_netgroupdn)
from ipatests.test_xmlrpc import objectclasses
from ipapython.dn import DN
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
import pytest

# Global so we can save the value between tests
netgroup_dn = None

netgroup1 = u'netgroup1'
netgroup2 = u'netgroup2'
netgroup_single = u'a'

host1 = u'ipatesthost.%s' % api.env.domain
host_dn1 = DN(('fqdn',host1),('cn','computers'),('cn','accounts'),
              api.env.basedn)

unknown_host = u'unknown'

unknown_host2 = u'unknown2'

hostgroup1 = u'hg1'
hostgroup_dn1 = DN(('cn',hostgroup1),('cn','hostgroups'),('cn','accounts'),
                   api.env.basedn)

user1 = u'jexample'

# user2 is a member of testgroup
user2 = u'pexample'

group1 = u'testgroup'

invalidnetgroup1=u'+badnetgroup'
invalidnisdomain1=u'domain1,domain2'
invalidnisdomain2=u'+invalidnisdomain'
invalidhost=u'+invalid&host'


@pytest.mark.tier1
class test_netgroup(Declarative):
    """
    Test the `netgroup` plugin.
    """

    cleanup_commands = [
        ('netgroup_del', [netgroup1], {}),
        ('netgroup_del', [netgroup2], {}),
        ('host_del', [host1], {}),
        ('hostgroup_del', [hostgroup1], {}),
        ('user_del', [user1], {}),
        ('user_del', [user2], {}),
        ('group_del', [group1], {}),
    ]

    tests=[

        dict(
            desc='Try to retrieve non-existent %r' % netgroup1,
            command=('netgroup_show', [netgroup1], {}),
            expected=errors.NotFound(
                reason=u'%s: netgroup not found' % netgroup1),
        ),


        dict(
            desc='Try to update non-existent %r' % netgroup1,
            command=('netgroup_mod', [netgroup1],
                dict(description=u'Updated hostgroup 1')
            ),
            expected=errors.NotFound(
                reason=u'%s: netgroup not found' % netgroup1),
        ),


        dict(
            desc='Try to delete non-existent %r' % netgroup1,
            command=('netgroup_del', [netgroup1], {}),
            expected=errors.NotFound(
                reason=u'%s: netgroup not found' % netgroup1),
        ),


        dict(
            desc='Test an invalid netgroup name %r' % invalidnetgroup1,
            command=('netgroup_add', [invalidnetgroup1], dict(description=u'Test')),
            expected=errors.ValidationError(name='name',
                error=u'may only include letters, numbers, _, -, and .'),
        ),


        dict(
            desc='Test an invalid nisdomain1 name %r' % invalidnisdomain1,
            command=('netgroup_add', [netgroup1],
                dict(description=u'Test',nisdomainname=invalidnisdomain1)),
            expected=errors.ValidationError(name='nisdomain',
                error='may only include letters, numbers, _, -, and .'),
        ),


        dict(
            desc='Test an invalid nisdomain2 name %r' % invalidnisdomain2,
            command=('netgroup_add', [netgroup1],
                dict(description=u'Test',nisdomainname=invalidnisdomain2)),
            expected=errors.ValidationError(name='nisdomain',
                error='may only include letters, numbers, _, -, and .'),
        ),


        dict(
            desc='Create %r' % netgroup1,
            command=('netgroup_add', [netgroup1],
                dict(description=u'Test netgroup 1')
            ),
            expected=dict(
                value=netgroup1,
                summary=u'Added netgroup "%s"' % netgroup1,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup1],
                    objectclass=objectclasses.netgroup,
                    description=[u'Test netgroup 1'],
                    nisdomainname=['%s' % api.env.domain],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Create %r' % netgroup2,
            command=('netgroup_add', [netgroup2],
                dict(description=u'Test netgroup 2')
            ),
            expected=dict(
                value=netgroup2,
                summary=u'Added netgroup "%s"' % netgroup2,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup2],
                    objectclass=objectclasses.netgroup,
                    description=[u'Test netgroup 2'],
                    nisdomainname=['%s' % api.env.domain],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Create netgroup with name containing only one letter: %r' % netgroup_single,
            command=('netgroup_add', [netgroup_single],
                dict(description=u'Test netgroup_single')
            ),
            expected=dict(
                value=netgroup_single,
                summary=u'Added netgroup "%s"' % netgroup_single,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_single],
                    objectclass=objectclasses.netgroup,
                    description=[u'Test netgroup_single'],
                    nisdomainname=['%s' % api.env.domain],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Delete %r' % netgroup_single,
            command=('netgroup_del', [netgroup_single], {}),
            expected=dict(
                value=[netgroup_single],
                summary=u'Deleted netgroup "%s"' % netgroup_single,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % netgroup1,
            command=('netgroup_add', [netgroup1],
                dict(description=u'Test netgroup 1')
            ),
            expected=errors.DuplicateEntry(
                message=u'netgroup with name "%s" already exists' % netgroup1),
        ),


        dict(
            desc='Create host %r' % host1,
            command=('host_add', [host1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=host1,
                summary=u'Added host "%s"' % host1,
                result=dict(
                    dn=host_dn1,
                    fqdn=[host1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (host1, api.env.realm)],
                    krbcanonicalname=[u'host/%s@%s' % (host1, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[host1],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup1,
            command=('hostgroup_add', [hostgroup1],
                dict(description=u'Test hostgroup 1')
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added hostgroup "%s"' % hostgroup1,
                result=dict(
                    dn=hostgroup_dn1,
                    cn=[hostgroup1],
                    objectclass=objectclasses.hostgroup,
                    description=[u'Test hostgroup 1'],
                    mepmanagedentry=[DN(('cn',hostgroup1),('cn','ng'),('cn','alt'),
                                        api.env.basedn)],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),


        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),

        dict(
            desc='Create %r' % user2,
            command=(
                'user_add', [user2], dict(givenname=u'Test', sn=u'User2')
            ),
            expected=dict(
                value=user2,
                summary=u'Added user "%s"' % user2,
                result=get_user_result(user2, u'Test', u'User2', 'add'),
            ),
        ),


        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc 1')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc 1'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn',group1),('cn','groups'),('cn','accounts'),
                          api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Add user %r to group %r' % (user2, group1),
            command=(
                'group_add_member', [group1], dict(user=user2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        group=tuple(),
                        user=tuple(),
                        service=tuple(),
                    ),
                ),
                result={
                        'dn': DN(('cn',group1),('cn','groups'),('cn','accounts'),
                                 api.env.basedn),
                        'member_user': (user2,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'Test desc 1'],
                },
            ),
        ),


        dict(
            desc='Add invalid host %r to netgroup %r' % (invalidhost, netgroup1),
            command=('netgroup_add_member', [netgroup1], dict(host=invalidhost)),
            expected=errors.ValidationError(name='host',
             error=u"only letters, numbers, '_', '-' are allowed. " +
                    u"DNS label may not start or end with '-'"),
        ),


        dict(
            desc='Add host %r to netgroup %r' % (host1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(host=host1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add hostgroup %r to netgroup %r' % (hostgroup1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(hostgroup=hostgroup1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Search for netgroups using no_user with members',
            command=('netgroup_find', [], dict(
                no_user=user1, no_members=False)),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 netgroups matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup2],
                        'description': [u'Test netgroup 2'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for netgroups using no_user',
            command=('netgroup_find', [], dict(no_user=user1)),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 netgroups matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup2],
                        'description': [u'Test netgroup 2'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                ],
            ),
        ),


        dict(
            desc="Check %r doesn't match when searching for %s" % (netgroup1, user1),
            command=('netgroup_find', [], dict(user=user1)),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Add user %r to netgroup %r' % (user1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(user=user1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),

        dict(
            desc="Check %r doesn't match when searching for no %s" % (netgroup1, user1),
            command=('netgroup_find', [], dict(no_user=user1)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup2],
                        'description': [u'Test netgroup 2'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                ],
            ),
        ),

        dict(
            desc='Add group %r to netgroup %r' % (group1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(group=group1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add netgroup %r to netgroup %r' % (netgroup2, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(netgroup=netgroup2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add non-existent netgroup to netgroup %r' % (netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(netgroup=u'notfound')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=[(u'notfound', u'no such entry')],
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add duplicate user %r to netgroup %r' % (user1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(user=user1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=[('%s' % user1, u'This entry is already a member')],
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),

        dict(
            desc='Add duplicate group %r to netgroup %r' % (group1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(group=group1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=[('%s' % group1, u'This entry is already a member')],
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add duplicate host %r to netgroup %r' % (host1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(host=host1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=[('%s' % host1, u'This entry is already a member')],
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add duplicate hostgroup %r to netgroup %r' % (hostgroup1, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(hostgroup=hostgroup1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=[('%s' % hostgroup1, u'This entry is already a member')],
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add unknown host %r to netgroup %r' % (unknown_host, netgroup1),
            command=(
                'netgroup_add_member', [netgroup1], dict(host=unknown_host)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),

        dict(
            desc='Add invalid host %r to netgroup %r using setattr' %
                (invalidhost, netgroup1),
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr='externalhost=%s' % invalidhost)
            ),
            expected=errors.ValidationError(name='externalhost',
                error=u"only letters, numbers, '_', '-' are allowed. " +
                    u"DNS label may not start or end with '-'"),
        ),

        dict(
            desc='Add unknown host %r to netgroup %r using addattr' %
                (unknown_host2, netgroup1),
            command=(
                'netgroup_mod', [netgroup1],
                dict(addattr='externalhost=%s' % unknown_host2)
            ),
            expected=dict(
                value=u'netgroup1',
                summary=u'Modified netgroup "netgroup1"',
                result={
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host, unknown_host2],
                },
            )
        ),

        dict(
            desc='Remove unknown host %r from netgroup %r using delattr' %
                (unknown_host2, netgroup1),
            command=(
                'netgroup_mod', [netgroup1],
                dict(delattr='externalhost=%s' % unknown_host2)
            ),
            expected=dict(
                value=u'netgroup1',
                summary=u'Modified netgroup "netgroup1"',
                result={
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            )
        ),

        dict(
            desc='Retrieve %r' % netgroup1,
            command=('netgroup_show', [netgroup1], {}),
            expected=dict(
                value=netgroup1,
                summary=None,
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),

        dict(
            desc='Search for %r with members' % netgroup1,
            command=('netgroup_find', [], dict(
                cn=netgroup1, no_members=False)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % netgroup1,
            command=('netgroup_find', [], dict(cn=netgroup1)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using user with members' % netgroup1,
            command=('netgroup_find', [], dict(
                user=user1, no_members=False)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using user' % netgroup1,
            command=('netgroup_find', [], dict(user=user1)),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                ],
            ),
        ),


        dict(
            desc=('Search for all netgroups using empty member user with '
                  'members'),
            command=('netgroup_find', [], dict(user=None, no_members=False)),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 netgroups matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                    {
                        'dn': fuzzy_netgroupdn,
                        'memberof_netgroup': (netgroup1,),
                        'cn': [netgroup2],
                        'description': [u'Test netgroup 2'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for all netgroups using empty member user',
            command=('netgroup_find', [], dict(user=None)),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 netgroups matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Test netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup2],
                        'description': [u'Test netgroup 2'],
                        'nisdomainname': [u'%s' % api.env.domain],
                    },
                ],
            ),
        ),


        dict(
            desc='Update %r' % netgroup1,
            command=('netgroup_mod', [netgroup1],
                dict(description=u'Updated netgroup 1')
            ),
            expected=dict(
                value=netgroup1,
                summary=u'Modified netgroup "%s"' % netgroup1,
                result={
                        'memberhost_host': (host1,),
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove host %r from netgroup %r' % (host1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(host=host1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberhost_hostgroup': (hostgroup1,),
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove hostgroup %r from netgroup %r' % (hostgroup1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(hostgroup=hostgroup1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberuser_user': (user1,),
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove user %r from netgroup %r' % (user1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(user=user1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'memberuser_group': (group1,),
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove group %r from netgroup %r' % (group1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(group=group1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'member_netgroup': (netgroup2,),
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove netgroup %r from netgroup %r' % (netgroup2, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(netgroup=netgroup2)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove host %r from netgroup %r again' % (host1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(host=host1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=[('%s' % host1, u'This entry is not a member')]
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove hostgroup %r from netgroup %r again' % (hostgroup1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(hostgroup=hostgroup1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=[('%s' % hostgroup1, u'This entry is not a member')],
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove user %r from netgroup %r again' % (user1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(user=user1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=[('%s' % user1, u'This entry is not a member')],
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove group %r from netgroup %r again' % (group1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(group=group1)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group= [('%s' % group1, u'This entry is not a member')],
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Remove netgroup %r from netgroup %r again' % (netgroup2, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(netgroup=netgroup2)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=[('%s' % netgroup2, u'This entry is not a member')],
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=tuple(),
                    ),
                    memberhost=dict(
                        hostgroup=tuple(),
                        host=tuple(),
                    ),
                ),
                result={
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': [u'Updated netgroup 1'],
                        'nisdomainname': [u'%s' % api.env.domain],
                        'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Delete %r' % netgroup1,
            command=('netgroup_del', [netgroup1], {}),
            expected=dict(
                value=[netgroup1],
                summary=u'Deleted netgroup "%s"' % netgroup1,
                result=dict(failed=[]),
            ),
        ),

    ]

# No way to convert this test just yet.

#    def test_6b_netgroup_show(self):
#        """
#        Confirm the underlying triples
#        """
#        # Do an LDAP query to the compat area and verify that the entry
#        # is correct
#        conn = ldap2(api)
#        conn.connect()
#        try:
#            entries = conn.find_entries('cn=%s' % self.ng_cn,
#                      base_dn='cn=ng,cn=compat,%s' % api.env.basedn)
#        except errors.NotFound:
#            pytest.skip(
#                'compat and nis are not enabled, skipping test'
#            )
#        finally:
#            conn.disconnect()
#        triples = entries[0][0]['nisnetgrouptriple']
#
#        # This may not prove to be reliable since order is not guaranteed
#        # and even which user gets into which triple can be random.
#        assert '(nosuchhost,jexample,example.com)' in triples
#        assert '(ipatesthost.%s,pexample,example.com)' % api.env.domain in triples
