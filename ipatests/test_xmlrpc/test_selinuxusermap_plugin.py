# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2011  Red Hat
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
Test the `ipaserver/plugins/selinuxusermap.py` module.
"""

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import (Declarative, fuzzy_digits,
                                              fuzzy_uuid)
from ipapython.dn import DN
from ipatests.util import Fuzzy
from ipatests.test_xmlrpc.test_user_plugin import get_user_result
import pytest

rule1 = u'selinuxrule1'
selinuxuser1 = u'guest_u:s0'
selinuxuser2 = u'xguest_u:s0'

user1 = u'tuser1'
group1 = u'testgroup1'
host1 = u'testhost1.%s' % api.env.domain
hostdn1 = DN(('fqdn', host1), ('cn', 'computers'), ('cn', 'accounts'),
             api.env.basedn)
hbacrule1 = u'testhbacrule1'
hbacrule2 = u'testhbacrule12'

# Note (?i) at the beginning of the regexp is the ingnore case flag
fuzzy_selinuxusermapdn = Fuzzy(
    '(?i)ipauniqueid=[0-9a-f]{8}-[0-9a-f]{4}'
    '-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12},%s,%s'
    % (api.env.container_selinux, api.env.basedn)
)
fuzzy_hbacruledn = Fuzzy(
    '(?i)ipauniqueid=[0-9a-f]{8}-[0-9a-f]{4}'
    '-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12},%s,%s'
    % (api.env.container_hbac, api.env.basedn)
)

allow_all_rule_dn = api.Command['hbacrule_show'](u'allow_all')['result']['dn']


@pytest.mark.tier1
class test_selinuxusermap(Declarative):
    cleanup_commands = [
        ('selinuxusermap_del', [rule1], {}),
        ('group_del', [group1], {}),
        ('user_del', [user1], {}),
        ('host_del', [host1], {}),
        ('hbacrule_del', [hbacrule1], {}),
        ('hbacrule_del', [hbacrule2], {}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent %r' % rule1,
            command=('selinuxusermap_show', [rule1], {}),
            expected=errors.NotFound(
                reason=u'%s: SELinux User Map rule not found' % rule1),
        ),


        dict(
            desc='Try to update non-existent %r' % rule1,
            command=('selinuxusermap_mod', [rule1], dict(description=u'Foo')),
            expected=errors.NotFound(
                reason=u'%s: SELinux User Map rule not found' % rule1),
        ),


        dict(
            desc='Try to delete non-existent %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=errors.NotFound(
                reason=u'%s: SELinux User Map rule not found' % rule1),
        ),


        dict(
            desc='Create rule %r' % rule1,
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1)
            ),
            expected=dict(
                value=rule1,
                summary=u'Added SELinux User Map "%s"' % rule1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser1],
                    objectclass=objectclasses.selinuxusermap,
                    ipauniqueid=[fuzzy_uuid],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
            ),
        ),


        dict(
            desc='Try to create duplicate %r' % rule1,
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1)
            ),
            expected=errors.DuplicateEntry(message=u'SELinux User Map rule ' +
                u'with name "%s" already exists' % rule1),
        ),


        dict(
            desc='Retrieve rule %r' % rule1,
            command=('selinuxusermap_show', [rule1], {}),
            expected=dict(
                value=rule1,
                summary=None,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser1],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
            ),
        ),


        dict(
            desc='Update rule %r' % rule1,
            command=(
                'selinuxusermap_mod', [rule1],
                    dict(ipaselinuxuser=selinuxuser2)
            ),
            expected=dict(
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                ),
                summary=u'Modified SELinux User Map "%s"' % rule1,
                value=rule1,
            ),
        ),


        dict(
            desc='Retrieve %r to verify update' % rule1,
            command=('selinuxusermap_show', [rule1], {}),
            expected=dict(
                value=rule1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for rule %r' % rule1,
            command=('selinuxusermap_find', [], dict(cn=rule1)),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                        cn=[rule1],
                        ipaselinuxuser=[selinuxuser2],
                        ipaenabledflag=[u'TRUE'],
                        dn=fuzzy_selinuxusermapdn,
                    ),
                ],
                summary=u'1 SELinux User Map matched',
            ),
        ),


        ###############
        # Create additional entries needed for testing
        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [], dict(givenname=u'Test', sn=u'User1')
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "%s"' % user1,
                result=get_user_result(user1, u'Test', u'User1', 'add'),
            ),
        ),

        dict(
            desc='Create group %r' % group1,
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
                    dn=DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'),
                          api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Add member %r to %r' % (user1, group1),
            command=(
                'group_add_member', [group1], dict(user=user1)
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
                        'dn': DN(('cn', group1), ('cn', 'groups'),
                            ('cn', 'accounts'), api.env.basedn),
                        'member_user': (user1,),
                        'gidnumber': [fuzzy_digits],
                        'cn': [group1],
                        'description': [u'Test desc 1'],
                },
            ),
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
                    dn=hostdn1,
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
            desc='Create HBAC rule %r' % hbacrule1,
            command=(
                'hbacrule_add', [hbacrule1], {}
            ),
            expected=dict(
                value=hbacrule1,
                summary=u'Added HBAC rule "%s"' % hbacrule1,
                result=dict(
                    cn=[hbacrule1],
                    objectclass=objectclasses.hbacrule,
                    ipauniqueid=[fuzzy_uuid],
                    accessruletype=[u'allow'],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_hbacruledn,
                ),
            ),
        ),


        dict(
            desc='Create HBAC rule %r' % hbacrule2,
            command=(
                'hbacrule_add', [hbacrule2], {}
            ),
            expected=dict(
                value=hbacrule2,
                summary=u'Added HBAC rule "%s"' % hbacrule2,
                result=dict(
                    cn=[hbacrule2],
                    objectclass=objectclasses.hbacrule,
                    ipauniqueid=[fuzzy_uuid],
                    accessruletype=[u'allow'],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_hbacruledn,
                ),
            ),
        ),


        ###############
        # Fill out rule with members and/or pointers to HBAC rules
        dict(
            desc='Add user to %r' % rule1,
            command=('selinuxusermap_add_user', [rule1], dict(user=user1)),
            expected=dict(
                failed=dict(memberuser=dict(group=[], user=[])),
                completed=1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    memberuser_user=[user1],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Add non-existent user to %r' % rule1,
            command=('selinuxusermap_add_user', [rule1],
                dict(user=u'notfound')),
            expected=dict(
                failed=dict(
                    memberuser=dict(group=[],
                                    user=[(u'notfound', u'no such entry')])
                        ),
                completed=0,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    memberuser_user=[user1],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Remove user from %r' % rule1,
            command=('selinuxusermap_remove_user', [rule1], dict(user=user1)),
            expected=dict(
                failed=dict(memberuser=dict(group=[], user=[])),
                completed=1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Remove non-existent user to %r' % rule1,
            command=('selinuxusermap_remove_user', [rule1],
                dict(user=u'notfound')),
            expected=dict(
                failed=dict(
                    memberuser=dict(group=[],
                        user=[(u'notfound', u'This entry is not a member')]
                            )
                        ),
                completed=0,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Add group to %r' % rule1,
            command=('selinuxusermap_add_user', [rule1], dict(group=group1)),
            expected=dict(
                failed=dict(memberuser=dict(group=[], user=[])),
                completed=1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    memberuser_group=[group1],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Add host to %r' % rule1,
            command=('selinuxusermap_add_host', [rule1], dict(host=host1)),
            expected=dict(
                failed=dict(memberhost=dict(hostgroup=[], host=[])),
                completed=1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    memberhost_host=[host1],
                    memberuser_group=[group1],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        ###############
        # Test enabling and disabling
        dict(
            desc='Disable %r' % rule1,
            command=('selinuxusermap_disable', [rule1], {}),
            expected=dict(
                result=True,
                value=rule1,
                summary=u'Disabled SELinux User Map "%s"' % rule1,
            )
        ),


        dict(
            desc='Disable %r again' % rule1,
            command=('selinuxusermap_disable', [rule1], {}),
            expected=errors.AlreadyInactive(),
        ),


        dict(
            desc='Enable %r' % rule1,
            command=('selinuxusermap_enable', [rule1], {}),
            expected=dict(
                result=True,
                value=rule1,
                summary=u'Enabled SELinux User Map "%s"' % rule1,
            )
        ),


        dict(
            desc='Re-enable %r again' % rule1,
            command=('selinuxusermap_enable', [rule1], {}),
            expected=errors.AlreadyActive(),
        ),


        # Point to an HBAC Rule
        dict(
            desc='Add an HBAC rule to %r that has other members' % rule1,
            command=(
                'selinuxusermap_mod', [rule1], dict(seealso=hbacrule1)
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),


        dict(
            desc='Remove host from %r' % rule1,
            command=('selinuxusermap_remove_host', [rule1], dict(host=host1)),
            expected=dict(
                failed=dict(memberhost=dict(hostgroup=[], host=[])),
                completed=1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    memberuser_group=[group1],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Remove group from %r' % rule1,
            command=('selinuxusermap_remove_user', [rule1],
                dict(group=group1)),
            expected=dict(
                failed=dict(memberuser=dict(group=[], user=[])),
                completed=1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
            )
        ),


        dict(
            desc='Add non-existent HBAC rule to %r' % rule1,
            command=(
                'selinuxusermap_mod', [rule1], dict(seealso=u'notfound')
            ),
            expected=errors.NotFound(
                reason=u'HBAC rule notfound not found'),
        ),


        dict(
            desc='Add an HBAC rule to %r' % rule1,
            command=(
                'selinuxusermap_mod', [rule1], dict(seealso=hbacrule1)
            ),
            expected=dict(
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser2],
                    ipaenabledflag=[u'TRUE'],
                    seealso=hbacrule1,
                ),
                summary=u'Modified SELinux User Map "%s"' % rule1,
                value=rule1,
            ),
        ),


        dict(
            desc='Add user to %r that has HBAC' % rule1,
            command=('selinuxusermap_add_user', [rule1], dict(user=user1)),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),


        dict(
            desc='Add host to %r that has HBAC' % rule1,
            command=('selinuxusermap_add_host', [rule1], dict(host=host1)),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),


        dict(
            desc='Try to delete HBAC rule pointed to by %r' % rule1,
            command=('hbacrule_del', [hbacrule1], {}),
            expected=errors.DependentEntry(key=hbacrule1,
                label=u'SELinux User Map', dependent=rule1)
        ),


        # This tests selinuxusermap-find --hbacrule=<foo> returns an
        # exact match
        dict(
            desc='Try to delete similarly named HBAC rule %r' % hbacrule2,
            command=('hbacrule_del', [hbacrule2], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[hbacrule2],
                summary=u'Deleted HBAC rule "%s"' % hbacrule2,
            )
        ),


        # Test clean up
        dict(
            desc='Delete %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[rule1],
                summary=u'Deleted SELinux User Map "%s"' % rule1,
            )
        ),


        dict(
            desc='Try to delete non-existent %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=errors.NotFound(
                reason=u'%s: SELinux User Map rule not found' % rule1),
        ),


        # Some negative tests
        dict(
            desc='Create rule with unknown user %r' % rule1,
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=u'notfound:s0:c0')
            ),
            expected=errors.NotFound(reason=u'SELinux user notfound:s0:c0 ' +
                u'not found in ordering list (in config)'),
        ),


        dict(
            desc='Create rule with invalid user bad+user',
            command=(
                'selinuxusermap_add', [rule1], dict(ipaselinuxuser=u'bad+user')
            ),
            expected=errors.ValidationError(
                name='selinuxuser',
                error=u'Invalid SELinux user name, only a-Z, _ '
                      'and . are allowed'
            ),
        ),


        dict(
            desc='Create rule with invalid MCS xguest_u:s999',
            command=(
                'selinuxusermap_add', [rule1],
                     dict(ipaselinuxuser=u'xguest_u:s999')
            ),
            expected=errors.ValidationError(name='selinuxuser',
                error=u'Invalid MLS value, must match s[0-15](-s[0-15])'),
        ),


        dict(
            desc='Create rule with invalid MLS xguest_u:s0:p88',
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=u'xguest_u:s0:p88')
            ),
            expected=errors.ValidationError(name='selinuxuser',
                error=u'Invalid MCS value, must match c[0-1023].c[0-1023] ' +
                    u'and/or c[0-1023]-c[0-c0123]'),
        ),


        dict(
            desc='Create rule with invalid MLS xguest_u:s0:c0.c1028',
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=u'xguest_u:s0-s0:c0.c1028')
            ),
            expected=errors.ValidationError(name='selinuxuser',
                error=u'Invalid MCS value, must match c[0-1023].c[0-1023] ' +
                    u'and/or c[0-1023]-c[0-c0123]'),
        ),


        dict(
            desc='Create rule with invalid user via setattr',
            command=(
                'selinuxusermap_mod', [rule1],
                    dict(setattr=u'ipaselinuxuser=deny')
            ),
            expected=errors.ValidationError(name='ipaselinuxuser',
                error=u'Invalid MLS value, must match s[0-15](-s[0-15])'),
        ),

        dict(
            desc='Create rule with both --hbacrule and --usercat set',
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1,
                         seealso=hbacrule1,
                         usercategory=u'all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Create rule with both --hbacrule and --hostcat set',
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1,
                         seealso=hbacrule1,
                         hostcategory=u'all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Create rule with both --hbacrule '
                 'and --usercat set via setattr',
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1,
                         seealso=hbacrule1,
                         setattr=u'usercategory=all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Create rule with both --hbacrule '
                 'and --hostcat set via setattr',
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1,
                         seealso=hbacrule1,
                         setattr=u'hostcategory=all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Create rule %r with --hbacrule' % rule1,
            command=(
                'selinuxusermap_add', [rule1],
                dict(ipaselinuxuser=selinuxuser1, seealso=hbacrule1)
            ),
            expected=dict(
                value=rule1,
                summary=u'Added SELinux User Map "%s"' % rule1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser1],
                    objectclass=objectclasses.selinuxusermap,
                    ipauniqueid=[fuzzy_uuid],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                    seealso=hbacrule1
                ),
            ),
        ),

        dict(
            desc='Add an --usercat to %r that has HBAC set' % rule1,
            command=(
                'selinuxusermap_mod', [rule1], dict(usercategory=u'all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Add an --hostcat to %r that has HBAC set' % rule1,
            command=(
                'selinuxusermap_mod', [rule1], dict(hostcategory=u'all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Add an usercat via setattr to %r that has HBAC set' % rule1,
            command=(
                'selinuxusermap_mod', [rule1],
                dict(setattr=u'usercategory=all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Add an hostcat via setattr to %r that has HBAC set' % rule1,
            command=(
                'selinuxusermap_mod', [rule1],
                dict(setattr=u'hostcategory=all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Delete %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[rule1],
                summary=u'Deleted SELinux User Map "%s"' % rule1,
            )
        ),

        dict(
            desc='Create rule %r with usercat and hostcat set' % rule1,
            command=(
                'selinuxusermap_add', [rule1],
                    dict(ipaselinuxuser=selinuxuser1,
                         usercategory=u'all',
                         hostcategory=u'all')
            ),
            expected=dict(
                value=rule1,
                summary=u'Added SELinux User Map "%s"' % rule1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser1],
                    objectclass=objectclasses.selinuxusermap,
                    ipauniqueid=[fuzzy_uuid],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                    usercategory=[u'all'],
                    hostcategory=[u'all']
                ),
            ),
        ),

        dict(
            desc='Add HBAC rule to %r that has usercat and hostcat' % rule1,
            command=(
                'selinuxusermap_mod', [rule1], dict(seealso=hbacrule1)
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Delete %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[rule1],
                summary=u'Deleted SELinux User Map "%s"' % rule1,
            )
        ),

        dict(
            desc='Create rule %r' % rule1,
            command=(
                'selinuxusermap_add', [rule1],
                dict(ipaselinuxuser=selinuxuser1)
            ),
            expected=dict(
                value=rule1,
                summary=u'Added SELinux User Map "%s"' % rule1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser1],
                    objectclass=objectclasses.selinuxusermap,
                    ipauniqueid=[fuzzy_uuid],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                ),
            ),
        ),

        dict(
            desc='Add HBAC rule, hostcat and usercat to %r' % rule1,
            command=(
                'selinuxusermap_mod', [rule1],
                    dict(seealso=hbacrule1,
                         usercategory=u'all',
                         hostcategory=u'all')
            ),
            expected=errors.MutuallyExclusiveError(
                reason=u'HBAC rule and local members cannot both be set'),
        ),

        dict(
            desc='Delete %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[rule1],
                summary=u'Deleted SELinux User Map "%s"' % rule1,
            )
        ),

       dict(
            desc='Create rule %r with '
                 '--setattr=seealso=<allow_all rule DN>' % rule1,
            command=(
                'selinuxusermap_add',
                [rule1],
                dict(ipaselinuxuser=selinuxuser1,
                     setattr=u'seealso=%s' % allow_all_rule_dn)
            ),
            expected=dict(
                value=rule1,
                summary=u'Added SELinux User Map "%s"' % rule1,
                result=dict(
                    cn=[rule1],
                    ipaselinuxuser=[selinuxuser1],
                    objectclass=objectclasses.selinuxusermap,
                    ipauniqueid=[fuzzy_uuid],
                    ipaenabledflag=[u'TRUE'],
                    dn=fuzzy_selinuxusermapdn,
                    seealso=u'allow_all',
                ),
            ),
        ),

        dict(
            desc='Delete %r' % rule1,
            command=('selinuxusermap_del', [rule1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[rule1],
                summary=u'Deleted SELinux User Map "%s"' % rule1,
            )
        ),
    ]
