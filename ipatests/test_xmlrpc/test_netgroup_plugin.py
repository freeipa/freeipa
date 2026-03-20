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
                                              fuzzy_set_optional_oc,
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

netgroup_nisdomain = 'netgroup_nisdomain'
netgroup_usercat = 'netgroup_usercat'
netgroup_hostcat = 'netgroup_hostcat'
netgroup_usercat_hostcat = 'netgroup_usercat_hostcat'
netgroup_exthost = 'netgroup_exthost'
netgroup_usercat_mod = 'netgroup_usercat_mod'
netgroup_hostcat_mod = 'netgroup_hostcat_mod'
custom_nisdomain = 'testnis.dom'
external_host = 'ipaqatesthost'

# Entities for netgroup-find tests
fnd_ng1 = 'fndng1'
fnd_ng2 = 'fndng2'
fnd_ng3 = 'fndng3'
fnd_user1 = 'fnduser1'
fnd_user2 = 'fnduser2'
fnd_group = 'fndgroup'
fnd_host = 'fndhost1.%s' % api.env.domain
fnd_hostgroup = 'fndhostgroup'
fnd_nisdomain = 'testdomain'


@pytest.mark.tier1
class test_netgroup(Declarative):
    """
    Test the `netgroup` plugin.
    """

    cleanup_commands = [
        ('netgroup_del', [netgroup1], {}),
        ('netgroup_del', [netgroup2], {}),
        ('netgroup_del', [netgroup_single], {}),
        ('netgroup_del', [netgroup_nisdomain], {}),
        ('netgroup_del', [netgroup_usercat], {}),
        ('netgroup_del', [netgroup_hostcat], {}),
        ('netgroup_del', [netgroup_usercat_hostcat], {}),
        ('netgroup_del', [netgroup_exthost], {}),
        ('netgroup_del', [netgroup_usercat_mod], {}),
        ('netgroup_del', [netgroup_hostcat_mod], {}),
        ('host_del', [host1], {}),
        ('hostgroup_del', [hostgroup1], {}),
        ('user_del', [user1], {}),
        ('user_del', [user2], {}),
        ('group_del', [group1], {}),
        # Cleanup for netgroup-find tests
        ('netgroup_del', [fnd_ng1], {}),
        ('netgroup_del', [fnd_ng2], {}),
        ('netgroup_del', [fnd_ng3], {}),
        ('hostgroup_del', [fnd_hostgroup], {}),
        ('host_del', [fnd_host], {}),
        ('group_del', [fnd_group], {}),
        ('user_del', [fnd_user1], {}),
        ('user_del', [fnd_user2], {}),
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
            desc='Test netgroup add with space in nisdomain',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', nisdomainname=' ')
            ),
            expected=errors.ValidationError(
                name='nisdomain',
                error='may only include letters, numbers, _, -, and .'),
        ),


        dict(
            desc='Test netgroup add with space in description',
            command=(
                'netgroup_add', [netgroup1],
                dict(description=' ')
            ),
            expected=errors.ValidationError(
                name='desc',
                error='Leading and trailing spaces are not allowed'),
        ),


        dict(
            desc='Test netgroup add with invalid usercat',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', usercategory='badcat')
            ),
            expected=errors.ValidationError(
                name='usercat', error="must be 'all'"),
        ),


        dict(
            desc='Test netgroup add with space for usercat',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', usercategory=' ')
            ),
            expected=errors.ValidationError(
                name='usercat', error="must be 'all'"),
        ),


        dict(
            desc='Test netgroup add with invalid hostcat',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', hostcategory='badcat')
            ),
            expected=errors.ValidationError(
                name='hostcat', error="must be 'all'"),
        ),


        dict(
            desc='Test netgroup add with space for hostcat',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', hostcategory=' ')
            ),
            expected=errors.ValidationError(
                name='hostcat', error="must be 'all'"),
        ),


        dict(
            desc='Test netgroup add with both desc and addattr description',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', addattr='description=duplicate')
            ),
            expected=errors.OnlyOneValueAllowed(attr='description'),
        ),


        dict(
            desc='Test netgroup add with invalid setattr attribute',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', setattr='badattr=somevalue')
            ),
            expected=errors.ObjectclassViolation(
                info='attribute "badattr" not allowed'),
        ),


        dict(
            desc='Test netgroup add with invalid addattr attribute',
            command=(
                'netgroup_add', [netgroup1],
                dict(description='Test', addattr='badattr=somevalue')
            ),
            expected=errors.ObjectclassViolation(
                info='attribute "badattr" not allowed'),
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
            desc='Create netgroup %r with custom nisdomain' % (
                netgroup_nisdomain),
            command=(
                'netgroup_add', [netgroup_nisdomain],
                dict(description='Test with custom nisdomain',
                     nisdomainname=custom_nisdomain)
            ),
            expected=dict(
                value=netgroup_nisdomain,
                summary='Added netgroup "%s"' % netgroup_nisdomain,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_nisdomain],
                    objectclass=objectclasses.netgroup,
                    description=['Test with custom nisdomain'],
                    nisdomainname=[custom_nisdomain],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete %r' % netgroup_nisdomain,
            command=('netgroup_del', [netgroup_nisdomain], {}),
            expected=dict(
                value=[netgroup_nisdomain],
                summary='Deleted netgroup "%s"' % netgroup_nisdomain,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Create netgroup %r with usercat=all' % netgroup_usercat,
            command=(
                'netgroup_add', [netgroup_usercat],
                dict(description='Test with usercat all',
                     nisdomainname=custom_nisdomain, usercategory='all')
            ),
            expected=dict(
                value=netgroup_usercat,
                summary='Added netgroup "%s"' % netgroup_usercat,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_usercat],
                    objectclass=objectclasses.netgroup,
                    description=['Test with usercat all'],
                    nisdomainname=[custom_nisdomain],
                    usercategory=['all'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete %r' % netgroup_usercat,
            command=('netgroup_del', [netgroup_usercat], {}),
            expected=dict(
                value=[netgroup_usercat],
                summary='Deleted netgroup "%s"' % netgroup_usercat,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Create netgroup %r with hostcat=all' % netgroup_hostcat,
            command=(
                'netgroup_add', [netgroup_hostcat],
                dict(description='Test with hostcat all',
                     nisdomainname=custom_nisdomain, hostcategory='all')
            ),
            expected=dict(
                value=netgroup_hostcat,
                summary='Added netgroup "%s"' % netgroup_hostcat,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_hostcat],
                    objectclass=objectclasses.netgroup,
                    description=['Test with hostcat all'],
                    nisdomainname=[custom_nisdomain],
                    hostcategory=['all'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete %r' % netgroup_hostcat,
            command=('netgroup_del', [netgroup_hostcat], {}),
            expected=dict(
                value=[netgroup_hostcat],
                summary='Deleted netgroup "%s"' % netgroup_hostcat,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Create netgroup %r with usercat/hostcat=all' % (
                netgroup_usercat_hostcat),
            command=(
                'netgroup_add', [netgroup_usercat_hostcat],
                dict(description='Test with usercat and hostcat all',
                     nisdomainname=custom_nisdomain,
                     usercategory='all', hostcategory='all')
            ),
            expected=dict(
                value=netgroup_usercat_hostcat,
                summary='Added netgroup "%s"' % netgroup_usercat_hostcat,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_usercat_hostcat],
                    objectclass=objectclasses.netgroup,
                    description=['Test with usercat and hostcat all'],
                    nisdomainname=[custom_nisdomain],
                    usercategory=['all'],
                    hostcategory=['all'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete %r' % netgroup_usercat_hostcat,
            command=('netgroup_del', [netgroup_usercat_hostcat], {}),
            expected=dict(
                value=[netgroup_usercat_hostcat],
                summary='Deleted netgroup "%s"' % netgroup_usercat_hostcat,
                result=dict(failed=[]),
            ),
        ),


        dict(
            desc='Create netgroup %r with externalHost' % netgroup_exthost,
            command=(
                'netgroup_add', [netgroup_exthost],
                dict(description='Test with externalHost',
                     nisdomainname=custom_nisdomain,
                     usercategory='all', hostcategory='all',
                     addattr='externalHost=%s' % external_host)
            ),
            expected=dict(
                value=netgroup_exthost,
                summary='Added netgroup "%s"' % netgroup_exthost,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_exthost],
                    objectclass=objectclasses.netgroup,
                    description=['Test with externalHost'],
                    nisdomainname=[custom_nisdomain],
                    usercategory=['all'],
                    hostcategory=['all'],
                    externalhost=[external_host],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Delete %r' % netgroup_exthost,
            command=('netgroup_del', [netgroup_exthost], {}),
            expected=dict(
                value=[netgroup_exthost],
                summary='Deleted netgroup "%s"' % netgroup_exthost,
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
                    objectclass=fuzzy_set_optional_oc(
                        objectclasses.posixgroup, 'ipantgroupattrs'),
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
                        idoverrideuser=tuple(),
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
            desc='Add non-existent user to netgroup %r' % netgroup1,
            command=(
                'netgroup_add_member', [netgroup1],
                dict(user=u'notfounduser')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=tuple(),
                        user=[(u'notfounduser', u'no such entry')],
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
                    'description': ['Test netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add non-existent group to netgroup %r' % netgroup1,
            command=(
                'netgroup_add_member', [netgroup1],
                dict(group=u'notfoundgroup')
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=tuple(),
                    ),
                    memberuser=dict(
                        group=[(u'notfoundgroup', u'no such entry')],
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
                    'description': ['Test netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add non-existent hostgroup to netgroup %r' % netgroup1,
            command=(
                'netgroup_add_member', [netgroup1],
                dict(hostgroup=u'notfoundhg')
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
                        hostgroup=[(u'notfoundhg', u'no such entry')],
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
                    'description': ['Test netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Add member to non-existent netgroup',
            command=(
                'netgroup_add_member', ['notfoundnetgroup'], dict(user=user1)
            ),
            expected=errors.NotFound(
                reason=u'notfoundnetgroup: netgroup not found'),
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
            desc='Search for %r by description' % netgroup1,
            command=(
                'netgroup_find', [],
                dict(description='Test netgroup 1')
            ),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': ['Test netgroup 1'],
                        'nisdomainname': ['%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for netgroups by nisdomain',
            command=(
                'netgroup_find', [],
                dict(nisdomainname='%s' % api.env.domain)
            ),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 netgroups matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup1],
                        'description': ['Test netgroup 1'],
                        'nisdomainname': ['%s' % api.env.domain],
                        'externalhost': [unknown_host],
                    },
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [netgroup2],
                        'description': ['Test netgroup 2'],
                        'nisdomainname': ['%s' % api.env.domain],
                    },
                ],
            ),
        ),


        dict(
            desc='Search with non-existent criteria returns zero',
            command=('netgroup_find', [u'doesnotexist'], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 netgroups matched',
                result=[],
            ),
        ),


        dict(
            desc='Search with non-existent description returns zero',
            command=('netgroup_find', [], dict(description=u'baddesc')),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 netgroups matched',
                result=[],
            ),
        ),


        dict(
            desc='Search with non-existent nisdomain returns zero',
            command=('netgroup_find', [], dict(nisdomainname=u'baddomain')),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 netgroups matched',
                result=[],
            ),
        ),


        dict(
            desc='Update %r' % netgroup1,
            command=('netgroup_mod', [netgroup1],
                     dict(description=u'Updated netgroup 1')),
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
            desc='Modify nisdomain of %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(nisdomainname=u'newnisdom1')
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': [u'newnisdom1'],
                    'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Restore nisdomain of %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(nisdomainname='%s' % api.env.domain)
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Modify description using setattr for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'description=setattr description')
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
                    'description': [u'setattr description'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Modify nisdomain using setattr for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'nisdomainname=setattrnisdom')
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
                    'description': [u'setattr description'],
                    'nisdomainname': [u'setattrnisdom'],
                    'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Restore description and nisdomain for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(description='Updated netgroup 1',
                     nisdomainname='%s' % api.env.domain)
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Set externalhost using setattr for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'externalhost=setattr_exthost')
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': ['setattr_exthost'],
                },
            ),
        ),


        dict(
            desc='Add externalhost using addattr for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(addattr=u'externalhost=addattr_exthost')
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': ['addattr_exthost', 'setattr_exthost'],
                },
            ),
        ),


        dict(
            desc='Delete one externalhost using delattr for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(delattr=u'externalhost=setattr_exthost')
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': ['addattr_exthost'],
                },
            ),
        ),


        dict(
            desc='Clear all externalhosts using setattr for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'externalhost=')
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                },
            ),
        ),


        dict(
            desc='Restore externalhost for %r' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(addattr=u'externalhost=%s' % unknown_host)
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
                    'description': ['Updated netgroup 1'],
                    'nisdomainname': ['%s' % api.env.domain],
                    'externalhost': [unknown_host],
                },
            ),
        ),


        dict(
            desc='Modify %r invalid usercat' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(usercategory=u'badcat')
            ),
            expected=errors.ValidationError(
                name='usercat', error="must be 'all'"),
        ),


        dict(
            desc='Modify %r invalid hostcat' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(hostcategory=u'badcat')
            ),
            expected=errors.ValidationError(
                name='hostcat', error="must be 'all'"),
        ),


        dict(
            desc='Modify %r with invalid addattr on nisDomainName' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(addattr=u'nisdomainname=seconddomain')
            ),
            expected=errors.OnlyOneValueAllowed(attr='nisdomainname'),
        ),


        dict(
            desc='Modify %r with invalid setattr on ipauniqueid' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'ipauniqueid=mynew-unique-id')
            ),
            expected=errors.ValidationError(
                name='ipauniqueid', error=u'attribute is not configurable'),
        ),


        dict(
            desc='Modify %r with invalid setattr on dn' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'dn=cn=newdn')
            ),
            expected=errors.ObjectclassViolation(
                info=u'attribute "distinguishedName" not allowed'),
        ),


        dict(
            desc='Modify %r with invalid membergroup attribute' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'membergroup=%s' % group1)
            ),
            expected=errors.ObjectclassViolation(
                info=u'attribute "membergroup" not allowed'),
        ),


        dict(
            desc='Modify %r with invalid memberhostgroup attr' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'memberhostgroup=%s' % hostgroup1)
            ),
            expected=errors.ObjectclassViolation(
                info=u'attribute "memberhostgroup" not allowed'),
        ),


        dict(
            desc='Modify %r with invalid membernetgroup attribute' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'membernetgroup=%s' % netgroup2)
            ),
            expected=errors.ObjectclassViolation(
                info=u'attribute "membernetgroup" not allowed'),
        ),


        dict(
            desc='Modify %r with invalid addattr on description' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(addattr=u'description=newdesc')
            ),
            expected=errors.OnlyOneValueAllowed(attr='description'),
        ),


        dict(
            desc='Modify %r with invalid nisdomain commas' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(nisdomainname=u'test1,test2')
            ),
            expected=errors.ValidationError(
                name='nisdomain',
                error=u'may only include letters, numbers, _, -, and .'),
        ),


        dict(
            desc='Modify %r with invalid setattr nisdomain commas' % netgroup1,
            command=(
                'netgroup_mod', [netgroup1],
                dict(setattr=u'nisdomainname=test1,test2')
            ),
            expected=errors.ValidationError(
                name='nisdomainname',
                error=u'may only include letters, numbers, _, -, and .'),
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
            desc='Remove hostgroup %r from netgroup %r' % (
                hostgroup1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1],
                dict(hostgroup=hostgroup1)
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
            desc='Remove hostgroup %r from netgroup %r again' % (
                hostgroup1, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1],
                dict(hostgroup=hostgroup1)
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
                        hostgroup=[(
                            '%s' % hostgroup1,
                            u'This entry is not a member')],
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
                        group=[('%s' % group1, u'This entry is not a member')],
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
            desc='Remove netgroup %r from netgroup %r again' % (
                netgroup2, netgroup1),
            command=(
                'netgroup_remove_member', [netgroup1], dict(netgroup=netgroup2)
            ),
            expected=dict(
                completed=0,
                failed=dict(
                    member=dict(
                        netgroup=[(
                            '%s' % netgroup2,
                            u'This entry is not a member')],
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
            desc='Remove member from non-existent netgroup',
            command=(
                'netgroup_remove_member', ['notfoundnetgroup'],
                dict(user=user1)
            ),
            expected=errors.NotFound(
                reason=u'notfoundnetgroup: netgroup not found'),
        ),


        dict(
            desc='Create %r with usercat=all' % netgroup_usercat_mod,
            command=(
                'netgroup_add', [netgroup_usercat_mod],
                dict(description='Test usercat mod',
                     nisdomainname=custom_nisdomain, usercategory='all')
            ),
            expected=dict(
                value=netgroup_usercat_mod,
                summary='Added netgroup "%s"' % netgroup_usercat_mod,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_usercat_mod],
                    objectclass=objectclasses.netgroup,
                    description=['Test usercat mod'],
                    nisdomainname=[custom_nisdomain],
                    usercategory=['all'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Clear usercat via setattr for %r' % netgroup_usercat_mod,
            command=(
                'netgroup_mod', [netgroup_usercat_mod],
                dict(setattr='usercategory=')
            ),
            expected=dict(
                value=netgroup_usercat_mod,
                summary='Modified netgroup "%s"' % netgroup_usercat_mod,
                result={
                    'cn': [netgroup_usercat_mod],
                    'description': ['Test usercat mod'],
                    'nisdomainname': [custom_nisdomain],
                },
            ),
        ),

        dict(
            desc='Create %r with hostcat=all' % netgroup_hostcat_mod,
            command=(
                'netgroup_add', [netgroup_hostcat_mod],
                dict(description='Test hostcat mod',
                     nisdomainname=custom_nisdomain, hostcategory='all')
            ),
            expected=dict(
                value=netgroup_hostcat_mod,
                summary='Added netgroup "%s"' % netgroup_hostcat_mod,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[netgroup_hostcat_mod],
                    objectclass=objectclasses.netgroup,
                    description=['Test hostcat mod'],
                    nisdomainname=[custom_nisdomain],
                    hostcategory=['all'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Clear hostcat via setattr for %r' % netgroup_hostcat_mod,
            command=(
                'netgroup_mod', [netgroup_hostcat_mod],
                dict(setattr='hostcategory=')
            ),
            expected=dict(
                value=netgroup_hostcat_mod,
                summary='Modified netgroup "%s"' % netgroup_hostcat_mod,
                result={
                    'cn': [netgroup_hostcat_mod],
                    'description': ['Test hostcat mod'],
                    'nisdomainname': [custom_nisdomain],
                },
            ),
        ),


        # ===== netgroup-find tests =====
        # Setup: Create test entities for find tests
        dict(
            desc='Create user %r for find tests' % fnd_user1,
            command=(
                'user_add', [fnd_user1],
                dict(givenname='Find', sn='User1')
            ),
            expected=dict(
                value=fnd_user1,
                summary='Added user "%s"' % fnd_user1,
                result=get_user_result(fnd_user1, 'Find', 'User1', 'add'),
            ),
        ),

        dict(
            desc='Create user %r for find tests' % fnd_user2,
            command=(
                'user_add', [fnd_user2],
                dict(givenname='Find', sn='User2')
            ),
            expected=dict(
                value=fnd_user2,
                summary='Added user "%s"' % fnd_user2,
                result=get_user_result(fnd_user2, 'Find', 'User2', 'add'),
            ),
        ),

        dict(
            desc='Create group %r for find tests' % fnd_group,
            command=(
                'group_add', [fnd_group],
                dict(description='test')
            ),
            expected=dict(
                value=fnd_group,
                summary='Added group "%s"' % fnd_group,
                result=dict(
                    cn=[fnd_group],
                    description=['test'],
                    gidnumber=[fuzzy_digits],
                    objectclass=fuzzy_set_optional_oc(
                        objectclasses.posixgroup, 'ipantgroupattrs'),
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(
                        ('cn', fnd_group), ('cn', 'groups'),
                        ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),

        dict(
            desc='Create host %r for find tests' % fnd_host,
            command=(
                'host_add', [fnd_host],
                dict(
                    description='Test host for find',
                    l='Undisclosed location',
                    force=True,
                )
            ),
            expected=dict(
                value=fnd_host,
                summary='Added host "%s"' % fnd_host,
                result=dict(
                    dn=DN(
                        ('fqdn', fnd_host), ('cn', 'computers'),
                        ('cn', 'accounts'), api.env.basedn),
                    fqdn=[fnd_host],
                    description=['Test host for find'],
                    l=['Undisclosed location'],
                    krbprincipalname=[
                        'host/%s@%s' % (fnd_host, api.env.realm)],
                    krbcanonicalname=[
                        'host/%s@%s' % (fnd_host, api.env.realm)],
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fnd_host],
                    has_keytab=False,
                    has_password=False,
                ),
            ),
        ),

        dict(
            desc='Create hostgroup %r for find tests' % fnd_hostgroup,
            command=(
                'hostgroup_add', [fnd_hostgroup],
                dict(description='test')
            ),
            expected=dict(
                value=fnd_hostgroup,
                summary='Added hostgroup "%s"' % fnd_hostgroup,
                result=dict(
                    dn=DN(
                        ('cn', fnd_hostgroup), ('cn', 'hostgroups'),
                        ('cn', 'accounts'), api.env.basedn),
                    cn=[fnd_hostgroup],
                    objectclass=objectclasses.hostgroup,
                    description=['test'],
                    mepmanagedentry=[DN(
                        ('cn', fnd_hostgroup), ('cn', 'ng'), ('cn', 'alt'),
                        api.env.basedn)],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        # Create netgroups with various attributes for find tests
        dict(
            desc='Create netgroup %r with nisdomain for find tests' % fnd_ng1,
            command=(
                'netgroup_add', [fnd_ng1],
                dict(description='findtest', nisdomainname=fnd_nisdomain)
            ),
            expected=dict(
                value=fnd_ng1,
                summary='Added netgroup "%s"' % fnd_ng1,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[fnd_ng1],
                    objectclass=objectclasses.netgroup,
                    description=['findtest'],
                    nisdomainname=[fnd_nisdomain],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Create netgroup %r with usercat/hostcat=all' % fnd_ng2,
            command=(
                'netgroup_add', [fnd_ng2],
                dict(description='findtest2',
                     usercategory='all', hostcategory='all')
            ),
            expected=dict(
                value=fnd_ng2,
                summary='Added netgroup "%s"' % fnd_ng2,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[fnd_ng2],
                    objectclass=objectclasses.netgroup,
                    description=['findtest2'],
                    nisdomainname=['%s' % api.env.domain],
                    usercategory=['all'],
                    hostcategory=['all'],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        dict(
            desc='Create netgroup %r for find tests' % fnd_ng3,
            command=(
                'netgroup_add', [fnd_ng3],
                dict(description='findtest3')
            ),
            expected=dict(
                value=fnd_ng3,
                summary='Added netgroup "%s"' % fnd_ng3,
                result=dict(
                    dn=fuzzy_netgroupdn,
                    cn=[fnd_ng3],
                    objectclass=objectclasses.netgroup,
                    description=['findtest3'],
                    nisdomainname=['%s' % api.env.domain],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ),
        ),

        # Add members to fnd_ng1
        dict(
            desc='Add user %r to netgroup %r' % (fnd_user1, fnd_ng1),
            command=(
                'netgroup_add_member', [fnd_ng1],
                dict(user=fnd_user1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(netgroup=tuple()),
                    memberuser=dict(group=tuple(), user=tuple()),
                    memberhost=dict(hostgroup=tuple(), host=tuple()),
                ),
                result={
                    'dn': fuzzy_netgroupdn,
                    'memberuser_user': (fnd_user1,),
                    'cn': [fnd_ng1],
                    'description': ['findtest'],
                    'nisdomainname': [fnd_nisdomain],
                },
            ),
        ),

        dict(
            desc='Add group %r to netgroup %r' % (fnd_group, fnd_ng1),
            command=(
                'netgroup_add_member', [fnd_ng1],
                dict(group=fnd_group)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(netgroup=tuple()),
                    memberuser=dict(group=tuple(), user=tuple()),
                    memberhost=dict(hostgroup=tuple(), host=tuple()),
                ),
                result={
                    'dn': fuzzy_netgroupdn,
                    'memberuser_user': (fnd_user1,),
                    'memberuser_group': (fnd_group,),
                    'cn': [fnd_ng1],
                    'description': ['findtest'],
                    'nisdomainname': [fnd_nisdomain],
                },
            ),
        ),

        dict(
            desc='Add host %r to netgroup %r' % (fnd_host, fnd_ng1),
            command=(
                'netgroup_add_member', [fnd_ng1],
                dict(host=fnd_host)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(netgroup=tuple()),
                    memberuser=dict(group=tuple(), user=tuple()),
                    memberhost=dict(hostgroup=tuple(), host=tuple()),
                ),
                result={
                    'dn': fuzzy_netgroupdn,
                    'memberuser_user': (fnd_user1,),
                    'memberuser_group': (fnd_group,),
                    'memberhost_host': (fnd_host,),
                    'cn': [fnd_ng1],
                    'description': ['findtest'],
                    'nisdomainname': [fnd_nisdomain],
                },
            ),
        ),

        dict(
            desc='Add hostgroup %r to netgroup %r' % (fnd_hostgroup, fnd_ng1),
            command=(
                'netgroup_add_member', [fnd_ng1],
                dict(hostgroup=fnd_hostgroup)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(netgroup=tuple()),
                    memberuser=dict(group=tuple(), user=tuple()),
                    memberhost=dict(hostgroup=tuple(), host=tuple()),
                ),
                result={
                    'dn': fuzzy_netgroupdn,
                    'memberuser_user': (fnd_user1,),
                    'memberuser_group': (fnd_group,),
                    'memberhost_host': (fnd_host,),
                    'memberhost_hostgroup': (fnd_hostgroup,),
                    'cn': [fnd_ng1],
                    'description': ['findtest'],
                    'nisdomainname': [fnd_nisdomain],
                },
            ),
        ),

        # Add fnd_ng1 as member of fnd_ng3 (nested netgroup)
        dict(
            desc='Add netgroup %r to netgroup %r' % (fnd_ng1, fnd_ng3),
            command=(
                'netgroup_add_member', [fnd_ng3],
                dict(netgroup=fnd_ng1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(netgroup=tuple()),
                    memberuser=dict(group=tuple(), user=tuple()),
                    memberhost=dict(hostgroup=tuple(), host=tuple()),
                ),
                result={
                    'dn': fuzzy_netgroupdn,
                    'member_netgroup': (fnd_ng1,),
                    'cn': [fnd_ng3],
                    'description': ['findtest3'],
                    'nisdomainname': ['%s' % api.env.domain],
                },
            ),
        ),

        # Find tests - positive scenarios
        dict(
            desc='Find netgroup by exact name %r' % fnd_ng1,
            command=('netgroup_find', [], dict(cn=fnd_ng1)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by description findtest',
            command=('netgroup_find', [], dict(description='findtest')),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by nisdomain %r' % fnd_nisdomain,
            command=('netgroup_find', [], dict(nisdomainname=fnd_nisdomain)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by usercat=all',
            command=('netgroup_find', [], dict(usercategory='all')),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng2],
                        'description': ['findtest2'],
                        'nisdomainname': ['%s' % api.env.domain],
                        'usercategory': ['all'],
                        'hostcategory': ['all'],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by hostcat=all',
            command=('netgroup_find', [], dict(hostcategory='all')),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng2],
                        'description': ['findtest2'],
                        'nisdomainname': ['%s' % api.env.domain],
                        'usercategory': ['all'],
                        'hostcategory': ['all'],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by user %r' % fnd_user1,
            command=('netgroup_find', [], dict(user=fnd_user1)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by group %r' % fnd_group,
            command=('netgroup_find', [], dict(group=fnd_group)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by host %r' % fnd_host,
            command=('netgroup_find', [], dict(host=fnd_host)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by hostgroup %r' % fnd_hostgroup,
            command=('netgroup_find', [], dict(hostgroup=fnd_hostgroup)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by member netgroup %r' % fnd_ng1,
            command=('netgroup_find', [], dict(netgroup=fnd_ng1)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng3],
                        'description': ['findtest3'],
                        'nisdomainname': ['%s' % api.env.domain],
                    },
                ],
            ),
        ),

        dict(
            desc='Find netgroup by in_netgroup %r' % fnd_ng3,
            command=('netgroup_find', [], dict(in_netgroup=fnd_ng3)),
            expected=dict(
                count=1,
                truncated=False,
                summary='1 netgroup matched',
                result=[
                    {
                        'dn': fuzzy_netgroupdn,
                        'cn': [fnd_ng1],
                        'description': ['findtest'],
                        'nisdomainname': [fnd_nisdomain],
                    },
                ],
            ),
        ),

        # Find tests - negative scenarios (0 matches)
        dict(
            desc='Find netgroup with nonexistent name returns 0',
            command=('netgroup_find', ['nonexistent_fnd'], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with bad user returns 0',
            command=('netgroup_find', [], dict(user='baduser_fnd')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with bad group returns 0',
            command=('netgroup_find', [], dict(group='badgroup_fnd')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with bad host returns 0',
            command=('netgroup_find', [], dict(host='badhost_fnd')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with bad hostgroup returns 0',
            command=('netgroup_find', [], dict(hostgroup='badhg_fnd')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with bad netgroup returns 0',
            command=('netgroup_find', [], dict(netgroup='badng_fnd')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        # Invalid parameter type tests
        dict(
            desc='Find netgroup with invalid timelimit type',
            command=('netgroup_find', [], dict(timelimit='bad')),
            expected=errors.ConversionError(
                name='timelimit',
                error='must be an integer'),
        ),

        dict(
            desc='Find netgroup with invalid sizelimit type',
            command=('netgroup_find', [], dict(sizelimit='bad')),
            expected=errors.ConversionError(
                name='sizelimit',
                error='must be an integer'),
        ),

        # Space input tests (bz798792)
        dict(
            desc='Find netgroup with space in netgroup param (bz798792)',
            command=('netgroup_find', [], dict(netgroup=' ')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with space in user param (bz798792)',
            command=('netgroup_find', [], dict(user=' ')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with space in group param (bz798792)',
            command=('netgroup_find', [], dict(group=' ')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with space in host param (bz798792)',
            command=('netgroup_find', [], dict(host=' ')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with space in hostgroup param (bz798792)',
            command=('netgroup_find', [], dict(hostgroup=' ')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
            ),
        ),

        dict(
            desc='Find netgroup with space in in_netgroup param (bz798792)',
            command=('netgroup_find', [], dict(in_netgroup=' ')),
            expected=dict(
                count=0,
                truncated=False,
                summary='0 netgroups matched',
                result=[],
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
