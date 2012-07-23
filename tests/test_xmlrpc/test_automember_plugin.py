# Authors:
#   Jr Aquino <jr.aquino@citrix.com>
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
Test the `ipalib/plugins/automember.py` module.
"""

from ipalib import api, errors
from ipapython.dn import DN
from tests.test_xmlrpc import objectclasses
from xmlrpc_test import Declarative, fuzzy_digits, fuzzy_uuid


user1=u'tuser1'
manager1=u'mscott'
fqdn1 = u'web1.%s' % api.env.domain
short1 = u'web1'
fqdn2 = u'dev1.%s' % api.env.domain
short2 = u'dev1'
fqdn3 = u'web5.%s' % api.env.domain
short3 = u'web5'
fqdn4 = u'www5.%s' % api.env.domain
short4 = u'www5'
fqdn5 = u'webserver5.%s' % api.env.domain
short5 = u'webserver5'

group1=u'group1'
defaultgroup1=u'defaultgroup1'
hostgroup1=u'hostgroup1'
hostgroup2=u'hostgroup2'
hostgroup3=u'hostgroup3'
hostgroup4=u'hostgroup4'
defaulthostgroup1=u'defaulthostgroup1'

group_include_regex = u'mscott'
hostgroup_include_regex = u'^web[1-9]'
hostgroup_include_regex2 = u'^www[1-9]'
hostgroup_include_regex3 = u'webserver[1-9]'
hostgroup_exclude_regex = u'^web5'
hostgroup_exclude_regex2 = u'^www5'
hostgroup_exclude_regex3 = u'^webserver5'


class test_automember(Declarative):

    cleanup_commands = [
        ('user_del', [user1, manager1], {}),
        ('group_del', [group1, defaultgroup1], {}),
        ('host_del', [fqdn1, fqdn2, fqdn3, fqdn4, fqdn5], {}),
        ('hostgroup_del', [hostgroup1, hostgroup2, hostgroup3, hostgroup4, defaulthostgroup1], {}),
        ('automember_del', [group1], {'type': u'group'}),
        ('automember_del', [hostgroup1], {'type': u'hostgroup'}),
        ('automember_del', [hostgroup2], {'type': u'hostgroup'}),
        ('automember_del', [hostgroup3], {'type': u'hostgroup'}),
        ('automember_del', [hostgroup4], {'type': u'hostgroup'}),
        ('automember_default_group_remove', [], {'type': u'hostgroup'}),
        ('automember_default_group_remove', [], {'type': u'group'}),

    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent group rule %r' % group1,
            command=('automember_add', [group1],
                dict(description=u'Test desc', type=u'group')),
            expected=errors.NotFound(reason=u'Group: %s not found!' % group1),
        ),

        dict(
            desc='Try to update non-existent group rule %r' % group1,
            command=('automember_add', [group1], dict(type=u'group')),
            expected=errors.NotFound(reason=u'Group: %s not found!' % group1),
        ),

        dict(
            desc='Try to delete non-existent group rule %r' % group1,
            command=('automember_del', [group1], dict(type=u'group')),
            expected=errors.NotFound(reason=u': auto_member_rule not found'),
        ),


        dict(
            desc='Try to retrieve non-existent hostgroup rule %r' % hostgroup1,
            command=('automember_add', [hostgroup1],
                dict(description=u'Test desc', type=u'hostgroup')),
            expected=errors.NotFound(
                reason=u'Group: %s not found!' % hostgroup1),
        ),

        dict(
            desc='Try to update non-existent hostgroup rule %r' % hostgroup1,
            command=('automember_add', [hostgroup1], dict(type=u'hostgroup')),
            expected=errors.NotFound(
                reason=u'Group: %s not found!' % hostgroup1),
        ),

        dict(
            desc='Try to delete non-existent hostgroup rule %r' % hostgroup1,
            command=('automember_del', [hostgroup1], dict(type=u'hostgroup')),
            expected=errors.NotFound(reason=u': auto_member_rule not found'),
        ),



        dict(
            desc='Create %r' % group1,
            command=(
                'group_add', [group1], dict(description=u'Test desc')
            ),
            expected=dict(
                value=group1,
                summary=u'Added group "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup1,
            command=(
                'hostgroup_add', [hostgroup1], dict(description=u'Test desc')
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added hostgroup "%s"' % hostgroup1,
                result=dict(
                    cn=[hostgroup1],
                    description=[u'Test desc'],
                    objectclass=objectclasses.hostgroup,
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn', hostgroup1), ('cn', 'ng'), ('cn', 'alt'), api.env.basedn)],
                    dn=DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup2,
            command=(
                'hostgroup_add', [hostgroup2], dict(description=u'Test desc')
            ),
            expected=dict(
                value=hostgroup2,
                summary=u'Added hostgroup "%s"' % hostgroup2,
                result=dict(
                    cn=[hostgroup2],
                    description=[u'Test desc'],
                    objectclass=objectclasses.hostgroup,
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn', hostgroup2), ('cn', 'ng'), ('cn', 'alt'), api.env.basedn)],
                    dn=DN(('cn', hostgroup2), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup3,
            command=(
                'hostgroup_add', [hostgroup3], dict(description=u'Test desc')
            ),
            expected=dict(
                value=hostgroup3,
                summary=u'Added hostgroup "%s"' % hostgroup3,
                result=dict(
                    cn=[hostgroup3],
                    description=[u'Test desc'],
                    objectclass=objectclasses.hostgroup,
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn', hostgroup3), ('cn', 'ng'), ('cn', 'alt'), api.env.basedn)],
                    dn=DN(('cn', hostgroup3), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % hostgroup4,
            command=(
                'hostgroup_add', [hostgroup4], dict(description=u'Test desc')
            ),
            expected=dict(
                value=hostgroup4,
                summary=u'Added hostgroup "%s"' % hostgroup4,
                result=dict(
                    cn=[hostgroup4],
                    description=[u'Test desc'],
                    objectclass=objectclasses.hostgroup,
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn', hostgroup4), ('cn', 'ng'), ('cn', 'alt'), api.env.basedn)],
                    dn=DN(('cn', hostgroup4), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % defaultgroup1,
            command=(
                'group_add', [defaultgroup1], dict(description=u'Default test desc')
            ),
            expected=dict(
                value=defaultgroup1,
                summary=u'Added group "%s"' % defaultgroup1,
                result=dict(
                    cn=[defaultgroup1],
                    description=[u'Default test desc'],
                    gidnumber=[fuzzy_digits],
                    objectclass=objectclasses.group + [u'posixgroup'],
                    ipauniqueid=[fuzzy_uuid],
                    dn=DN(('cn', defaultgroup1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % defaulthostgroup1,
            command=(
                'hostgroup_add', [defaulthostgroup1], dict(description=u'Default test desc')
            ),
            expected=dict(
                value=defaulthostgroup1,
                summary=u'Added hostgroup "%s"' % defaulthostgroup1,
                result=dict(
                    cn=[defaulthostgroup1],
                    description=[u'Default test desc'],
                    objectclass=objectclasses.hostgroup,
                    ipauniqueid=[fuzzy_uuid],
                    mepmanagedentry=[DN(('cn', defaulthostgroup1), ('cn', 'ng'), ('cn', 'alt'), api.env.basedn)],
                    dn=DN(('cn', defaulthostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create automember %r' % group1,
            command=(
                'automember_add', [group1], dict(description=u'Test desc', type=u'group')
            ),
            expected=dict(
                value=group1,
                summary=u'Added automember rule "%s"' % group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                    objectclass=objectclasses.automember,
                    dn=DN(('cn', group1), ('cn', 'group'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create automember condition %r' % group1,
            command=(
                'automember_add_condition', [group1], dict(
                    key=u'manager', type=u'group',
                    automemberinclusiveregex=[group_include_regex],
                )
            ),
            expected=dict(
                value=group1,
                summary=u'Added condition(s) to "%s"' % group1,
                completed=1,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'manager=%s' % group_include_regex],
                    automembertargetgroup=[DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc='Create automember %r' % hostgroup1,
            command=(
                'automember_add', [hostgroup1], dict(
                    description=u'Test desc', type=u'hostgroup',
                )
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added automember rule "%s"' % hostgroup1,
                result=dict(
                    cn=[hostgroup1],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    objectclass=objectclasses.automember,
                    dn=DN(('cn', hostgroup1), ('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create automember condition %r' % hostgroup1,
            command=(
                'automember_add_condition', [hostgroup1], dict(
                    key=u'fqdn', type=u'hostgroup',
                    automemberinclusiveregex=[hostgroup_include_regex],
                )
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added condition(s) to "%s"' % hostgroup1,
                completed=1,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    cn=[hostgroup1],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex],
                    automembertargetgroup=[DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc='Create duplicate automember condition %r' % hostgroup1,
            command=(
                'automember_add_condition', [hostgroup1], dict(
                    key=u'fqdn', type=u'hostgroup',
                    automemberinclusiveregex=[hostgroup_include_regex],
                )
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added condition(s) to "%s"' % hostgroup1,
                completed=0,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex],
                ),
            ),
        ),


        dict(
            desc='Create additional automember conditions %r' % hostgroup1,
            command=(
                'automember_add_condition', [hostgroup1], dict(
                    key=u'fqdn', type=u'hostgroup',
                    automemberinclusiveregex=[hostgroup_include_regex2, hostgroup_include_regex3],
                    automemberexclusiveregex=[hostgroup_exclude_regex, hostgroup_exclude_regex2, hostgroup_exclude_regex3],
                )
            ),
            expected=dict(
                value=hostgroup1,
                summary=u'Added condition(s) to "%s"' % hostgroup1,
                completed=5,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    cn=[hostgroup1],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex,
                                              u'fqdn=%s' % hostgroup_include_regex3,
                                              u'fqdn=%s' % hostgroup_include_regex2,
                    ],
                    automemberexclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex2,
                                              u'fqdn=%s' % hostgroup_exclude_regex3,
                                              u'fqdn=%s' % hostgroup_exclude_regex,
                    ],
                ),
            ),
        ),


        dict(
            desc='Create automember %r' % hostgroup2,
            command=(
                'automember_add', [hostgroup2], dict(
                    description=u'Test desc', type=u'hostgroup',
                )
            ),
            expected=dict(
                value=hostgroup2,
                summary=u'Added automember rule "%s"' % hostgroup2,
                result=dict(
                    cn=[hostgroup2],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup2), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    objectclass=objectclasses.automember,
                    dn=DN(('cn', hostgroup2), ('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create automember condition %r' % hostgroup2,
            command=(
                'automember_add_condition', [hostgroup2], dict(
                    key=u'fqdn', type=u'hostgroup',
                    automemberinclusiveregex=[hostgroup_exclude_regex],
                )
            ),
            expected=dict(
                value=hostgroup2,
                summary=u'Added condition(s) to "%s"' % hostgroup2,
                completed=1,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    cn=[hostgroup2],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex],
                    automembertargetgroup=[DN(('cn', hostgroup2), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc='Create automember %r' % hostgroup3,
            command=(
                'automember_add', [hostgroup3], dict(
                    description=u'Test desc', type=u'hostgroup',
                )
            ),
            expected=dict(
                value=hostgroup3,
                summary=u'Added automember rule "%s"' % hostgroup3,
                result=dict(
                    cn=[hostgroup3],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup3), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    objectclass=objectclasses.automember,
                    dn=DN(('cn', hostgroup3), ('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create automember condition %r' % hostgroup3,
            command=(
                'automember_add_condition', [hostgroup3], dict(
                    key=u'fqdn', type=u'hostgroup',
                    automemberinclusiveregex=[hostgroup_exclude_regex2],
                )
            ),
            expected=dict(
                value=hostgroup3,
                summary=u'Added condition(s) to "%s"' % hostgroup3,
                completed=1,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    cn=[hostgroup3],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex2],
                    automembertargetgroup=[DN(('cn', hostgroup3), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc='Create automember %r' % hostgroup4,
            command=(
                'automember_add', [hostgroup4], dict(
                    description=u'Test desc', type=u'hostgroup',
                )
            ),
            expected=dict(
                value=hostgroup4,
                summary=u'Added automember rule "%s"' % hostgroup4,
                result=dict(
                    cn=[hostgroup4],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup4), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    objectclass=objectclasses.automember,
                    dn=DN(('cn', hostgroup4), ('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create automember condition %r' % hostgroup4,
            command=(
                'automember_add_condition', [hostgroup4], dict(
                    key=u'fqdn', type=u'hostgroup',
                    automemberinclusiveregex=[hostgroup_exclude_regex3],
                )
            ),
            expected=dict(
                value=hostgroup4,
                summary=u'Added condition(s) to "%s"' % hostgroup4,
                completed=1,
                failed=dict(
                    failed = dict(
                        automemberinclusiveregex=tuple(),
                        automemberexclusiveregex=tuple(),
                    )
                ),
                result=dict(
                    cn=[hostgroup4],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex3],
                    automembertargetgroup=[DN(('cn', hostgroup4), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                ),
            ),
        ),


        dict(
            desc="Retrieve automember rule for group %s" % group1,
            command=('automember_show', [group1], dict(
                type=u'group',
                )
            ),
            expected=dict(
                value=group1,
                result=dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'manager=%s' % group_include_regex],
                    automembertargetgroup=[DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                    dn=DN(('cn', group1), ('cn', 'group'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r' % group1,
            command=('automember_find', [group1], dict(
                type=u'group'
                )
            ),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                    cn=[group1],
                    description=[u'Test desc'],
                    automemberinclusiveregex=[u'manager=%s' % group_include_regex],
                    automembertargetgroup=[DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                    dn=DN(('cn', group1), ('cn', 'group'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                    ),
                ],
                summary=u'1 rules matched',
            ),
        ),


        dict(
            desc='Updated automember rule %r' % group1,
            command=(
                'automember_mod', [group1], dict(
                    type=u'group',
                    description=u'New desc 1',
                )
            ),
            expected=dict(
                result=dict(
                    cn=[group1],
                    description=[u'New desc 1'],
                    automemberinclusiveregex=[u'manager=%s' % group_include_regex],
                    automembertargetgroup=[DN(('cn', group1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                ),
                summary=u'Modified automember rule "%s"' % group1,
                value=group1,
            ),
        ),


        dict(
            desc="Retrieve automember rule for hostgroup %s" % hostgroup1,
            command=('automember_show', [hostgroup1], dict(
                type=u'hostgroup',
                )
            ),
            expected=dict(
                value=hostgroup1,
                result=dict(
                    cn=[hostgroup1],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex,
                                              u'fqdn=%s' % hostgroup_include_regex3,
                                              u'fqdn=%s' % hostgroup_include_regex2,
                    ],
                    automemberexclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex2,
                                              u'fqdn=%s' % hostgroup_exclude_regex3,
                                              u'fqdn=%s' % hostgroup_exclude_regex,
                    ],
                    dn=DN(('cn', hostgroup1), ('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                ),
                summary=None,
            ),
        ),


        dict(
            desc='Search for %r' % hostgroup1,
            command=('automember_find', [hostgroup1], dict(
                type=u'hostgroup'
                )
            ),
            expected=dict(
                count=1,
                truncated=False,
                result=[
                    dict(
                    cn=[hostgroup1],
                    description=[u'Test desc'],
                    automembertargetgroup=[DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex,
                                              u'fqdn=%s' % hostgroup_include_regex3,
                                              u'fqdn=%s' % hostgroup_include_regex2,
                    ],
                    automemberexclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex2,
                                              u'fqdn=%s' % hostgroup_exclude_regex3,
                                              u'fqdn=%s' % hostgroup_exclude_regex,
                    ],
                    dn=DN(('cn', hostgroup1), ('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                    ),
                ],
                summary=u'1 rules matched',
            ),
        ),


        dict(
            desc='Updated automember rule %r' % hostgroup1,
            command=(
                'automember_mod', [hostgroup1], dict(
                    type=u'hostgroup',
                    description=u'New desc 1',
                )
            ),
            expected=dict(
                result=dict(
                    cn=[hostgroup1],
                    description=[u'New desc 1'],
                    automembertargetgroup=[DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                    automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex,
                                              u'fqdn=%s' % hostgroup_include_regex3,
                                              u'fqdn=%s' % hostgroup_include_regex2,
                    ],
                    automemberexclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex2,
                                              u'fqdn=%s' % hostgroup_exclude_regex3,
                                              u'fqdn=%s' % hostgroup_exclude_regex,
                    ],
                ),
                summary=u'Modified automember rule "%s"' % hostgroup1,
                value=hostgroup1,
            ),
        ),


        dict(
            desc='Set default automember group for groups',
            command=(
                'automember_default_group_set', [], dict(
                    type=u'group',
                    automemberdefaultgroup=defaultgroup1
                    )
            ),
            expected=dict(
                result=dict(
                    cn=[u'Group'],
                    automemberdefaultgroup=[DN(('cn', defaultgroup1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                ),
                value=u'group',
                summary=u'Set default (fallback) group for automember "group"',
            ),
        ),


        dict(
            desc='Retrieve default automember group for groups',
            command=(
                'automember_default_group_show', [], dict(type=u'group')
            ),
            expected=dict(
                result=dict(
                    dn=DN(('cn', 'group'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                    cn=[u'Group'],
                    automemberdefaultgroup=[DN(('cn', defaultgroup1), ('cn', 'groups'), ('cn', 'accounts'), api.env.basedn)],
                ),
                value=u'group',
                summary=None,
            ),
        ),


        dict(
            desc='Set default (fallback) automember group for hostgroups',
            command=(
                'automember_default_group_set', [], dict(
                    type=u'hostgroup',
                    automemberdefaultgroup=defaulthostgroup1,
                )
            ),
            expected=dict(
                result=dict(
                    cn=[u'Hostgroup'],
                    automemberdefaultgroup=[DN(('cn', defaulthostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                ),
                value=u'hostgroup',
                summary=u'Set default (fallback) group for automember "hostgroup"',
            ),
        ),


        dict(
            desc='Retrieve default automember group for hostgroups',
            command=(
                'automember_default_group_show', [], dict(
                    type=u'hostgroup',
                )
            ),
            expected=dict(
                result=dict(
                    dn=DN(('cn', 'hostgroup'), ('cn', 'automember'), ('cn', 'etc'), api.env.basedn),
                    cn=[u'Hostgroup'],
                    automemberdefaultgroup=[DN(('cn', defaulthostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn)],
                ),
                value=u'hostgroup',
                summary=None,
            ),
        ),


        dict(
            desc='Create %r' % manager1,
            command=(
                'user_add', [manager1], dict(givenname=u'Michael', sn=u'Scott')
            ),
            expected=dict(
                value=manager1,
                summary=u'Added user "mscott"',
                result=dict(
                    gecos=[u'Michael Scott'],
                    givenname=[u'Michael'],
                    homedirectory=[u'/home/mscott'],
                    krbprincipalname=[u'mscott@' + api.env.realm],
                    has_keytab=False,
                    has_password=False,
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'Scott'],
                    uid=[manager1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'%s@%s' % (manager1, api.env.domain)],
                    displayname=[u'Michael Scott'],
                    cn=[u'Michael Scott'],
                    initials=[u'MS'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn', 'global_policy'), ('cn', api.env.realm), ('cn', 'kerberos'),
                                              api.env.basedn)],
                    mepmanagedentry=[DN(('cn', manager1), ('cn', 'groups'), ('cn', 'accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'defaultgroup1', u'ipausers'],
                    dn=DN(('uid', 'mscott'), ('cn', 'users'), ('cn', 'accounts'),
                          api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % user1,
            command=(
                'user_add', [user1], dict(givenname=u'Test', sn=u'User1', manager=manager1)
            ),
            expected=dict(
                value=user1,
                summary=u'Added user "tuser1"',
                result=dict(
                    gecos=[u'Test User1'],
                    givenname=[u'Test'],
                    homedirectory=[u'/home/tuser1'],
                    krbprincipalname=[u'tuser1@' + api.env.realm],
                    has_keytab=False,
                    has_password=False,
                    loginshell=[u'/bin/sh'],
                    objectclass=objectclasses.user,
                    sn=[u'User1'],
                    uid=[user1],
                    uidnumber=[fuzzy_digits],
                    gidnumber=[fuzzy_digits],
                    mail=[u'%s@%s' % (user1, api.env.domain)],
                    manager=[DN(('uid', 'mscott'), ('cn', 'users'), ('cn', 'accounts'), api.env.basedn)],
                    displayname=[u'Test User1'],
                    cn=[u'Test User1'],
                    initials=[u'TU'],
                    ipauniqueid=[fuzzy_uuid],
                    krbpwdpolicyreference=[DN(('cn', 'global_policy'), ('cn', api.env.realm), ('cn', 'kerberos'),
                                              api.env.basedn)],
                    mepmanagedentry=[DN(('cn', user1), ('cn', 'groups'), ('cn', 'accounts'),
                                        api.env.basedn)],
                    memberof_group=[u'group1', u'ipausers'],
                    dn=DN(('uid', 'tuser1'), ('cn', 'users'), ('cn', 'accounts'),
                          api.env.basedn),
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn1,
            command=('host_add', [fqdn1],
                dict(
                    description=u'Test host 1',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn1,
                summary=u'Added host "%s"' % fqdn1,
                result=dict(
                    dn=DN(('fqdn', fqdn1), ('cn', 'computers'), ('cn', 'accounts'), api.env.basedn),
                    fqdn=[fqdn1],
                    description=[u'Test host 1'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn1, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn1],
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn2,
            command=('host_add', [fqdn2],
                dict(
                    description=u'Test host 2',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn2,
                summary=u'Added host "%s"' % fqdn2,
                result=dict(
                    dn=DN(('fqdn', fqdn2), ('cn', 'computers'), ('cn', 'accounts'), api.env.basedn),
                    fqdn=[fqdn2],
                    description=[u'Test host 2'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn2, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn2],
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn3,
            command=('host_add', [fqdn3],
                dict(
                    description=u'Test host 3',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn3,
                summary=u'Added host "%s"' % fqdn3,
                result=dict(
                    dn=DN(('fqdn', fqdn3), ('cn', 'computers'), ('cn', 'accounts'), api.env.basedn),
                    fqdn=[fqdn3],
                    description=[u'Test host 3'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn3, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn3],
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn4,
            command=('host_add', [fqdn4],
                dict(
                    description=u'Test host 4',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn4,
                summary=u'Added host "%s"' % fqdn4,
                result=dict(
                    dn=DN(('fqdn', fqdn4), ('cn', 'computers'), ('cn', 'accounts'), api.env.basedn),
                    fqdn=[fqdn4],
                    description=[u'Test host 4'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn4, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn4],
                ),
            ),
        ),


        dict(
            desc='Create %r' % fqdn5,
            command=('host_add', [fqdn5],
                dict(
                    description=u'Test host 5',
                    l=u'Undisclosed location 1',
                    force=True,
                ),
            ),
            expected=dict(
                value=fqdn5,
                summary=u'Added host "%s"' % fqdn5,
                result=dict(
                    dn=DN(('fqdn', fqdn5), ('cn', 'computers'), ('cn', 'accounts'), api.env.basedn),
                    fqdn=[fqdn5],
                    description=[u'Test host 5'],
                    l=[u'Undisclosed location 1'],
                    krbprincipalname=[u'host/%s@%s' % (fqdn5, api.env.realm)],
                    has_keytab=False,
                    has_password=False,
                    objectclass=objectclasses.host,
                    ipauniqueid=[fuzzy_uuid],
                    managedby_host=[fqdn5],
                ),
            ),
        ),


        dict(
            desc='Retrieve %r' % hostgroup1,
            command=('hostgroup_show', [hostgroup1], {}),
            expected=dict(
                value=hostgroup1,
                summary=None,
                result={
                    'dn': DN(('cn', hostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                    'member_host': [u'%s' % fqdn1],
                    'cn': [hostgroup1],
                    'description': [u'Test desc'],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % defaulthostgroup1,
            command=('hostgroup_show', [defaulthostgroup1], {}),
            expected=dict(
                value=defaulthostgroup1,
                summary=None,
                result={
                    'dn': DN(('cn', defaulthostgroup1), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                    'member_host': [u'%s' % fqdn2],
                    'cn': [defaulthostgroup1],
                    'description': [u'Default test desc'],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % hostgroup2,
            command=('hostgroup_show', [hostgroup2], {}),
            expected=dict(
                value=hostgroup2,
                summary=None,
                result={
                    'dn': DN(('cn', hostgroup2), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                    'member_host': [u'%s' % fqdn3],
                    'cn': [hostgroup2],
                    'description': [u'Test desc'],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % hostgroup3,
            command=('hostgroup_show', [hostgroup3], {}),
            expected=dict(
                value=hostgroup3,
                summary=None,
                result={
                    'dn': DN(('cn', hostgroup3), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                    'member_host': [u'%s' % fqdn4],
                    'cn': [hostgroup3],
                    'description': [u'Test desc'],
                },
            ),
        ),


        dict(
            desc='Retrieve %r' % hostgroup4,
            command=('hostgroup_show', [hostgroup4], {}),
            expected=dict(
                value=hostgroup4,
                summary=None,
                result={
                    'dn': DN(('cn', hostgroup4), ('cn', 'hostgroups'), ('cn', 'accounts'), api.env.basedn),
                    'member_host': [u'%s' % fqdn5],
                    'cn': [hostgroup4],
                    'description': [u'Test desc'],
                },
            ),
        ),

    ]
