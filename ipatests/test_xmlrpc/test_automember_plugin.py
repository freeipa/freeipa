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
Test the `ipaserver/plugins/automember.py` module.
"""

from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.tracker.group_plugin import GroupTracker
from ipatests.test_xmlrpc.tracker.hostgroup_plugin import HostGroupTracker
from ipatests.test_xmlrpc.tracker.automember_plugin import AutomemberTracker
from ipalib import api, errors
from ipapython.dn import DN
from ipapython.ipautil import run
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.util import assert_deepequal

import pytest
import unittest
from lib389.utils import ds_is_older

try:
    from ipaserver.plugins.ldap2 import ldap2
except ImportError:
    have_ldap2 = False
else:
    have_ldap2 = True

user_does_not_exist = u'does_not_exist'
fqdn_does_not_exist = u'does_not_exist.%s' % api.env.domain
group_include_regex = u'mscott'
hostgroup_include_regex = u'^web[1-9]'
hostgroup_include_regex2 = u'^www[1-9]'
hostgroup_include_regex3 = u'webserver[1-9]'
hostgroup_exclude_regex = u'^web5'
hostgroup_exclude_regex2 = u'^www5'
hostgroup_exclude_regex3 = u'^webserver5'


@pytest.fixture(scope='class')
def manager1(request):
    """ User tracker used as a manager account """
    tracker = UserTracker(name=u'mscott', sn=u'Manager1',
                          givenname=u'Automember test manager user1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user1(request, manager1):
    """ User tracker with assigned manager """
    tracker = UserTracker(name=u'tuser1', sn=u'User1', manager=manager1.name,
                          givenname=u'Automember test user1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group1(request):
    tracker = GroupTracker(name=u'tgroup1',
                           description=u'Automember test group1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def defaultgroup1(request):
    tracker = GroupTracker(name=u'defaultgroup1',
                           description=u'Automember test defaultgroup1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup1(request):
    tracker = HostGroupTracker(name=u'thostgroup1',
                               description=u'Automember test hostgroup1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup2(request):
    tracker = HostGroupTracker(name=u'thostgroup2',
                               description=u'Automember test hostgroup2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup3(request):
    tracker = HostGroupTracker(name=u'thostgroup3',
                               description=u'Automember test hostgroup3')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup4(request):
    tracker = HostGroupTracker(name=u'thostgroup4',
                               description=u'Automember test hostgroup4')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def defaulthostgroup1(request):
    tracker = HostGroupTracker(name=u'defaulthostgroup1',
                               description=u'Automember test'
                                           'defaulthostgroup1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host1(request):
    tracker = HostTracker(u'web1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host2(request):
    tracker = HostTracker(u'dev1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host3(request):
    tracker = HostTracker(u'web5')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host4(request):
    tracker = HostTracker(u'www5')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host5(request):
    tracker = HostTracker(u'webserver5')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def automember_group(request, group1):
    tracker = AutomemberTracker(groupname=group1.cn,
                                description=u'Automember group tracker',
                                membertype=u'group')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def automember_hostgroup(request, hostgroup1):
    tracker = AutomemberTracker(groupname=hostgroup1.cn,
                                description=u'Automember hostgroup tracker',
                                membertype=u'hostgroup')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def automember_hostgroup2(request, hostgroup2):
    tracker = AutomemberTracker(groupname=hostgroup2.cn,
                                description=u'Automember hostgroup tracker 2',
                                membertype=u'hostgroup')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def automember_hostgroup3(request, hostgroup3):
    tracker = AutomemberTracker(groupname=hostgroup3.cn,
                                description=u'Automember hostgroup tracker 3',
                                membertype=u'hostgroup')

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def automember_hostgroup4(request, hostgroup4):
    tracker = AutomemberTracker(groupname=hostgroup4.cn,
                                description=u'Automember hostgroup tracker 4',
                                membertype=u'hostgroup')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestNonexistentAutomember(XMLRPC_test):
    def test_create_with_nonexistent_group(self, automember_group, group1):
        """ Try to add a rule with non-existent group """
        group1.ensure_missing()
        command = automember_group.make_create_command()
        with raises_exact(errors.NotFound(
                reason=u'group "%s" not found' % group1.cn)):
            command()

    def test_delete_with_nonexistent_group(self, automember_group, group1):
        """ Try to delete a rule with non-existent group """
        group1.ensure_missing()
        command = automember_group.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: Automember rule not found' % group1.cn)):
            command()

    def test_create_with_nonexistent_hostgroup(self, automember_hostgroup,
                                               hostgroup1):
        """ Try to add a rule with non-existent group """
        hostgroup1.ensure_missing()
        command = automember_hostgroup.make_create_command()
        with raises_exact(errors.NotFound(
                reason=u'hostgroup "%s" not found' % hostgroup1.cn)):
            command()

    def test_delete_with_nonexistent_hostgroup(self, automember_hostgroup,
                                               hostgroup1):
        """ Try to delete a rule with non-existent group """
        hostgroup1.ensure_missing()
        command = automember_hostgroup.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: Automember rule not found' % hostgroup1.cn)):
            command()


@pytest.mark.tier1
class TestCRUDFOnAutomember(XMLRPC_test):
    def test_basic_ops_on_group_automember(self, automember_group, group1):
        """ Test create, retrieve, find, update,
        and delete operations on a group automember """
        group1.create()
        automember_group.create()
        automember_group.retrieve()
        automember_group.find()
        automember_group.update(dict(description=u'New description'))
        automember_group.delete()

    def test_basic_ops_on_hostgroup_automember(self, automember_hostgroup,
                                               hostgroup1):
        """ Test create, retrieve, find, update,
        and delete operations on a hostgroup automember """
        hostgroup1.create()
        automember_hostgroup.create()
        automember_hostgroup.retrieve()
        automember_hostgroup.find()
        automember_hostgroup.update(dict(description=u'New description'))
        automember_hostgroup.delete()


def set_automember_process_modify_ops(value):
    """Configure the auto member plugin to process modifyOps

    Set the value for the attribute autoMemberProcessModifyOps of the entry
    cn=Auto Membership Plugin,cn=plugins,cn=config.
    :param value: can be either on or off
    """
    if not have_ldap2:
        raise unittest.SkipTest('server plugin not available')
    ldap = ldap2(api)
    ldap.connect()
    plugin_entry = ldap.get_entry(
        DN("cn=Auto Membership Plugin,cn=plugins,cn=config"))
    plugin_entry['autoMemberProcessModifyOps'] = value
    try:
        ldap.update_entry(plugin_entry)
    except errors.EmptyModlist:
        pass
    # Requires a 389-ds restart
    dashed_domain = api.env.realm.replace(".", "-")
    cmd = ['systemctl', 'restart', 'dirsrv@{}'.format(dashed_domain)]
    run(cmd)


@pytest.mark.tier1
class TestAutomemberRebuildHostMembership(XMLRPC_test):
    def test_create_deps_for_rebuilding_hostgroups(self, hostgroup1, host1,
                                                   automember_hostgroup):
        """ Create host, hostgroup, and automember tracker for this class
        of tests """
        hostgroup1.ensure_exists()
        host1.ensure_exists()
        automember_hostgroup.ensure_exists()
        automember_hostgroup.add_condition(
            key=u'fqdn', type=u'hostgroup',
            inclusiveregex=[hostgroup_include_regex]
        )
        hostgroup1.retrieve()

    def test_rebuild_membership_hostgroups(self, automember_hostgroup,
                                           hostgroup1, host1):
        """ Rebuild automember membership for hosts, both synchonously and
        asynchronously. Check the host has been added to the hostgroup. """
        # In the first part of test,
        # auto member process modify ops is disabled
        # This means that we can manually remove a member without
        # triggering the auto member plugin
        try:
            set_automember_process_modify_ops(value=b'off')
            automember_hostgroup.rebuild()
            automember_hostgroup.rebuild(no_wait=True)
            # After rebuild, the member is added, and we need to update
            # the tracker obj
            hostgroup1.attrs.update(member_host=[host1.fqdn])
            hostgroup1.retrieve()
            # Now try to remove the member
            hostgroup1.remove_member(dict(host=host1.fqdn))
            hostgroup1.retrieve()
        finally:
            set_automember_process_modify_ops(value=b'on')

        # Rebuild membership to re-add the member
        automember_hostgroup.rebuild()
        automember_hostgroup.rebuild(no_wait=True)
        # After rebuild, the member is added, and we need to update
        # the tracker obj
        hostgroup1.attrs.update(member_host=[host1.fqdn])
        hostgroup1.retrieve()

        # In the second part of the test,
        # enable auto member process modify ops
        # This means that a manual removal of a member will return success
        # but the member gets re-added by the auto member plugin
        # Expecting to raise an error as the member gets re-added
        with pytest.raises(AssertionError) as error:
            hostgroup1.remove_member(dict(host=host1.fqdn))
        assert "extra keys = ['member_host']" in str(error.value)


    def test_rebuild_membership_for_host(self, host1, automember_hostgroup,
                                         hostgroup1):
        """ Rebuild automember membership for one host, both synchronously and
        asynchronously. Check the host has been added to the hostgroup. """
        command = automember_hostgroup.make_rebuild_command(hosts=host1.fqdn)
        result = command()
        automember_hostgroup.check_rebuild(result)

        command = automember_hostgroup.make_rebuild_command(hosts=host1.fqdn,
                                                            no_wait=True)
        result = command()
        automember_hostgroup.check_rebuild(result, no_wait=True)

        hostgroup1.attrs.update(member_host=[host1.fqdn])
        hostgroup1.retrieve()

    def test_delete_deps_for_rebuilding_hostgroups(self, host1, hostgroup1,
                                                   automember_hostgroup):
        """ Delete dependences for this class of tests in desired order """
        host1.delete()
        hostgroup1.delete()
        automember_hostgroup.delete()


@pytest.mark.tier1
class TestAutomemberRebuildGroupMembership(XMLRPC_test):
    def test_create_deps_for_rebuilding_groups(self, group1, manager1, user1,
                                               automember_group):
        """ Create users, groups, and automember tracker for this class
        of tests """
        group1.ensure_exists()
        manager1.ensure_exists()
        user1.ensure_exists()
        automember_group.ensure_exists()
        automember_group.add_condition(
            key=u'manager', type=u'group', inclusiveregex=[group_include_regex]
        )
        group1.retrieve()

    def test_rebuild_membership_groups(self, automember_group, group1, user1):
        """ Rebuild automember membership for groups, both synchonously and
        asynchronously. Check the user has been added to the group. """
        # In the first part of test,
        # auto member process modify ops is disabled
        # This means that we can manually remove a member without
        # triggering the auto member plugin
        try:
            set_automember_process_modify_ops(value=b'off')
            automember_group.rebuild()
            automember_group.rebuild(no_wait=True)
            # After rebuild, the member is added, and we need to update
            # the tracker obj
            group1.attrs.update(member_user=[user1.name])
            group1.retrieve()
            # Now try to remove the member
            group1.remove_member(dict(user=user1.name))
            group1.retrieve()
        finally:
            set_automember_process_modify_ops(value=b'on')

        # Rebuild membership to re-add the member
        automember_group.rebuild()
        automember_group.rebuild(no_wait=True)
        # After rebuild, the member is added, and we need to update
        # the tracker obj
        group1.attrs.update(member_user=[user1.name])
        group1.retrieve()

        # In the second part of the test,
        # auto member process modify ops is enabled
        # This means that a manual removal of a member will return success
        # but the member gets re-added by the auto member plugin
        # Expecting to raise an error as the member gets re-added
        with pytest.raises(AssertionError) as error:
            group1.remove_member(dict(user=user1.name))
        assert "extra keys = ['member_user']" in str(error.value)


    def test_rebuild_membership_for_user(self, user1, automember_group,
                                         group1):
        """ Rebuild automember membership for one user, both synchronously and
        asynchronously. Check the user has been added to the group. """
        command = automember_group.make_rebuild_command(users=user1.name)
        result = command()
        automember_group.check_rebuild(result)
        command = automember_group.make_rebuild_command(users=user1.name,
                                                        no_wait=True)
        result = command()
        automember_group.check_rebuild(result, no_wait=True)
        group1.attrs.update(member_user=[user1.name])
        group1.retrieve()

    def test_delete_deps_for_rebuilding_groups(self, user1, manager1, group1,
                                               automember_group):
        """ Delete dependences for this class of tests in desired order """
        user1.delete()
        manager1.delete()
        group1.delete()
        automember_group.delete()


@pytest.mark.tier1
class TestAutomemberRebuildMembershipIncorrectly(XMLRPC_test):
    def test_rebuild_membership_hosts_incorrectly(self, automember_hostgroup):
        """ Try to issue rebuild automember command without 'type' parameter
        """
        command = automember_hostgroup.make_rebuild_command()
        with raises_exact(errors.MutuallyExclusiveError(
                reason=u'at least one of options: '
                       'type, users, hosts must be specified')):
            command()

    def test_rebuild_membership_user_hosts(self, automember_hostgroup, user1,
                                           host1):
        """ Try to issue rebuild membership command with --users and --hosts
        together """
        command = automember_hostgroup.make_rebuild_command(users=user1.name,
                                                            hosts=host1.fqdn)
        with raises_exact(errors.MutuallyExclusiveError(
                reason=u'users and hosts cannot both be set')):
            command()

    def test_rebuild_membership_users_hostgroup(self, automember_hostgroup,
                                                user1):
        """ Try to issue rebuild membership command with type --hosts and
        users specified """
        command = automember_hostgroup.make_rebuild_command(users=user1.name,
                                                            type=u'hostgroup')
        with raises_exact(errors.MutuallyExclusiveError(
                reason=u"users cannot be set when type is 'hostgroup'")):
            command()

    def test_rebuild_membership_hosts_group(self, automember_hostgroup, user1,
                                            host1):
        """ Try to issue rebuild membership command with type --users and
        hosts specified """
        command = automember_hostgroup.make_rebuild_command(hosts=host1.fqdn,
                                                            type=u'group')
        with raises_exact(errors.MutuallyExclusiveError(
                reason=u"hosts cannot be set when type is 'group'")):
            command()


@pytest.mark.tier1
class TestMultipleAutomemberConditions(XMLRPC_test):
    def test_create_deps_for_multiple_conditions(
            self, group1, hostgroup1, hostgroup2, hostgroup3, hostgroup4,
            defaultgroup1, defaulthostgroup1,
            automember_group, automember_hostgroup
            ):
        """ Create groups, hostgroups, and automember conditions
        for this class of tests """
        group1.ensure_exists()
        hostgroup1.ensure_exists()
        hostgroup2.ensure_exists()
        hostgroup3.ensure_exists()
        hostgroup4.ensure_exists()
        defaultgroup1.ensure_exists()
        defaulthostgroup1.ensure_exists()

        automember_group.ensure_exists()
        automember_group.add_condition(key=u'manager', type=u'group',
                                       inclusiveregex=[group_include_regex])
        automember_hostgroup.ensure_exists()
        automember_hostgroup.add_condition(
            key=u'fqdn', type=u'hostgroup',
            inclusiveregex=[hostgroup_include_regex]
        )

    def test_create_duplicate_automember_condition(self, automember_hostgroup,
                                                   hostgroup1):
        """ Try to create a duplicate automember condition """
        command = automember_hostgroup.make_add_condition_command(
            key=u'fqdn', type=u'hostgroup',
            automemberinclusiveregex=[hostgroup_include_regex]
        )
        result = command()
        automember_hostgroup.check_add_condition_negative(result)

    def test_create_additional_automember_conditions(self,
                                                     automember_hostgroup):
        """ Add additional automember conditions to existing one, with both
        inclusive and exclusive regular expressions the condition """
        command = automember_hostgroup.make_add_condition_command(
            key=u'fqdn', type=u'hostgroup',
            automemberinclusiveregex=[hostgroup_include_regex2,
                                      hostgroup_include_regex3],
            automemberexclusiveregex=[hostgroup_exclude_regex,
                                      hostgroup_exclude_regex2,
                                      hostgroup_exclude_regex3]
        )
        result = command()

        expected = dict(
            value=automember_hostgroup.cn,
            summary=u'Added condition(s) to "%s"' % automember_hostgroup.cn,
            completed=5,
            failed=dict(
                failed=dict(
                    automemberinclusiveregex=tuple(),
                    automemberexclusiveregex=tuple(),
                )
            ),
            result=dict(
                cn=[automember_hostgroup.cn],
                description=[automember_hostgroup.description],
                automembertargetgroup=[automember_hostgroup.attrs
                                       ['automembertargetgroup'][0]],
                automemberinclusiveregex=[u'fqdn=%s' %
                                          hostgroup_include_regex,
                                          u'fqdn=%s' %
                                          hostgroup_include_regex3,
                                          u'fqdn=%s' %
                                          hostgroup_include_regex2,
                                          ],
                automemberexclusiveregex=[u'fqdn=%s' %
                                          hostgroup_exclude_regex2,
                                          u'fqdn=%s' %
                                          hostgroup_exclude_regex3,
                                          u'fqdn=%s' %
                                          hostgroup_exclude_regex,
                                          ],
            ),
        )
        assert_deepequal(expected, result)

        automember_hostgroup.attrs.update(
            automemberinclusiveregex=[u'fqdn=%s' % hostgroup_include_regex,
                                      u'fqdn=%s' % hostgroup_include_regex3,
                                      u'fqdn=%s' % hostgroup_include_regex2,
                                      ],
            automemberexclusiveregex=[u'fqdn=%s' % hostgroup_exclude_regex2,
                                      u'fqdn=%s' % hostgroup_exclude_regex3,
                                      u'fqdn=%s' % hostgroup_exclude_regex,
                                      ]
        )  # modify automember_hostgroup tracker for next tests

    def test_create_set_of_hostgroup_automembers(self, automember_hostgroup2,
                                                 automember_hostgroup3,
                                                 automember_hostgroup4):
        """ Create three more hostgroup automembers """
        automember_hostgroup2.ensure_exists()
        automember_hostgroup2.add_condition(
            key=u'fqdn', type=u'hostgroup',
            inclusiveregex=[hostgroup_exclude_regex]
        )
        automember_hostgroup3.ensure_exists()
        automember_hostgroup3.add_condition(
            key=u'fqdn', type=u'hostgroup',
            inclusiveregex=[hostgroup_exclude_regex2]
        )
        automember_hostgroup4.ensure_exists()
        automember_hostgroup4.add_condition(
            key=u'fqdn', type=u'hostgroup',
            inclusiveregex=[hostgroup_exclude_regex3]
        )

    def test_set_default_group_for_automembers(self, defaultgroup1):
        """ Set new default group for group automembers """
        result = api.Command['automember_default_group_set'](
            type=u'group',
            automemberdefaultgroup=defaultgroup1.cn
        )

        assert_deepequal(
            dict(
                result=dict(
                    cn=[u'Group'],
                    automemberdefaultgroup=[DN(('cn', defaultgroup1.cn),
                                            ('cn', 'groups'),
                                            ('cn', 'accounts'),
                                            api.env.basedn)],
                ),
                value=u'group',
                summary=u'Set default (fallback) group for automember "group"'
                ),
            result)

        result = api.Command['automember_default_group_show'](
            type=u'group',
        )

        assert_deepequal(
            dict(
                result=dict(dn=DN(('cn', 'group'),
                                  ('cn', 'automember'),
                                  ('cn', 'etc'), api.env.basedn),
                            cn=[u'Group'],
                            automemberdefaultgroup=[
                                DN(('cn', defaultgroup1.cn),
                                   ('cn', 'groups'),
                                   ('cn', 'accounts'),
                                   api.env.basedn)
                                ],
                            ),
                value=u'group',
                summary=None,
            ),
            result)

    def test_set_default_hostgroup_for_automembers(self, defaulthostgroup1):
        """ Set new default hostgroup for hostgroup automembers """
        result = api.Command['automember_default_group_set'](
            type=u'hostgroup',
            automemberdefaultgroup=defaulthostgroup1.cn
        )

        assert_deepequal(
            dict(
                result=dict(
                    cn=[u'Hostgroup'],
                    automemberdefaultgroup=[DN(('cn', defaulthostgroup1.cn),
                                            ('cn', 'hostgroups'),
                                            ('cn', 'accounts'),
                                            api.env.basedn)],
                    ),
                value=u'hostgroup',
                summary=u'Set default (fallback) group for '
                        'automember "hostgroup"'),
            result)

        result = api.Command['automember_default_group_show'](
            type=u'hostgroup',
        )

        assert_deepequal(
            dict(
                result=dict(dn=DN(('cn', 'hostgroup'),
                            ('cn', 'automember'),
                            ('cn', 'etc'), api.env.basedn),
                            cn=[u'Hostgroup'],
                            automemberdefaultgroup=[
                                DN(('cn', defaulthostgroup1.cn),
                                   ('cn', 'hostgroups'),
                                   ('cn', 'accounts'),
                                   api.env.basedn)],
                            ),
                value=u'hostgroup',
                summary=None,
            ),
            result)

    def test_create_deps_under_new_conditions(
            self, manager1, user1, host1, host2, host3, host4, host5,
            hostgroup1, hostgroup2, hostgroup3, hostgroup4,
            defaulthostgroup1, defaultgroup1, group1
            ):
        """ Create users and hosts under previously defined
        automember conditions """
        defaulthostgroup1.retrieve()
        defaultgroup1.retrieve()
        manager1.ensure_missing()
        user1.ensure_missing()

        manager1.track_create()
        manager1.attrs.update(memberof_group=[defaultgroup1.cn, u'ipausers'])
        command = manager1.make_create_command()
        result = command()
        manager1.check_create(result)

        user1.track_create()
        user1.attrs.update(memberof_group=[group1.cn, u'ipausers'])
        command = user1.make_create_command()
        result = command()
        user1.check_create(result)

        host1.track_create()
        host1.attrs.update(memberofindirect_netgroup=[hostgroup1.cn],
                           memberof_hostgroup=[hostgroup1.cn])
        command = host1.make_create_command()
        result = command()
        hostgroup1.attrs.update(member_host=[host1.fqdn])

        host2.track_create()
        host2.attrs.update(memberof_hostgroup=[defaulthostgroup1.cn],
                           memberofindirect_netgroup=[defaulthostgroup1.cn])
        command = host2.make_create_command()
        result = command()
        defaulthostgroup1.attrs.update(member_host=[host2.fqdn])

        host3.track_create()
        host3.attrs.update(memberofindirect_netgroup=[hostgroup2.cn],
                           memberof_hostgroup=[hostgroup2.cn])
        command = host3.make_create_command()
        result = command()
        hostgroup2.attrs.update(member_host=[host3.fqdn])

        host4.track_create()
        host4.attrs.update(memberofindirect_netgroup=[hostgroup3.cn],
                           memberof_hostgroup=[hostgroup3.cn])
        command = host4.make_create_command()
        result = command()
        hostgroup3.attrs.update(member_host=[host4.fqdn])

        host5.track_create()
        host5.attrs.update(memberofindirect_netgroup=[hostgroup4.cn],
                           memberof_hostgroup=[hostgroup4.cn])
        command = host5.make_create_command()
        result = command()
        hostgroup4.attrs.update(member_host=[host5.fqdn])

        hostgroup1.retrieve()
        hostgroup2.retrieve()
        hostgroup3.retrieve()
        hostgroup4.retrieve()

    def test_rebuild_membership_for_one_host(self, automember_hostgroup,
                                             host1):
        """ Rebuild hostgroup automember membership for one host """
        command = automember_hostgroup.make_rebuild_command(type=u'hostgroup',
                                                            hosts=host1.fqdn)
        result = command()
        automember_hostgroup.check_rebuild(result)

    def test_rebuild_membership_for_one_user(self, automember_group, user1):
        """ Rebuild group automember membership for one user """
        command = automember_group.make_rebuild_command(type=u'group',
                                                        users=user1.name)
        result = command()
        automember_group.check_rebuild(result)

    def test_rebuild_membership_with_invalid_hosts_in_hosts(
            self, automember_hostgroup):
        """ Try to rebuild membership with invalid host in --hosts """
        command = automember_hostgroup.make_rebuild_command(
            hosts=fqdn_does_not_exist)
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % fqdn_does_not_exist)):
            command()

    def test_rebuild_membership_with_invalid_user_in_users(self,
                                                           automember_group):
        """ Try to rebuild membership with invalid user in --users """
        command = automember_group.make_rebuild_command(
            users=user_does_not_exist)
        with raises_exact(errors.NotFound(
                reason=u'%s: user not found' % user_does_not_exist)):
            command()

    def test_reset_automember_default_groups(self, defaultgroup1, user1,
                                             defaulthostgroup1, manager1):
        """ Reset automember group defaults """
        manager1.delete()
        user1.delete()
        result = api.Command['automember_default_group_remove'](
            type=u'group',
        )

        assert_deepequal(
            dict(
                result=dict(
                    automemberdefaultgroup=u'No default (fallback) group set',
                    cn=([u'Group'])
                    ),
                value=u'group',
                summary=u'Removed default (fallback) group'
                        ' for automember "group"'),
            result)

        result = api.Command['automember_default_group_remove'](
            type=u'hostgroup',
        )

        assert_deepequal(
            dict(
                result=dict(
                    automemberdefaultgroup=u'No default (fallback) group set',
                    cn=([u'Hostgroup'])
                    ),
                value=u'hostgroup',
                summary=u'Removed default (fallback) group'
                        ' for automember "hostgroup"'),
            result)

        defaultgroup1.ensure_missing()
        defaulthostgroup1.ensure_missing()


@pytest.mark.tier1
class TestAutomemberFindOrphans(XMLRPC_test):
    def test_create_deps_for_find_orphans(self, hostgroup1, host1,
                                          automember_hostgroup):
        """ Create host, hostgroup, and automember tracker for this class
        of tests. """

        # Create hostgroup1 and automember rule with condition
        hostgroup1.ensure_exists()
        host1.ensure_exists()

        # Manually create automember rule and condition, racker will try to
        # remove the automember rule in the end, which is failing as the rule
        # is already removed
        api.Command['automember_add'](hostgroup1.cn, type=u'hostgroup')
        api.Command['automember_add_condition'](
            hostgroup1.cn,
            key=u'fqdn', type=u'hostgroup',
            automemberinclusiveregex=[hostgroup_include_regex]
        )

        hostgroup1.retrieve()

    def test_find_orphan_automember_rules(self, hostgroup1):
        """ Remove hostgroup1, find and remove obsolete automember rules. """
        # Remove hostgroup1

        hostgroup1.ensure_missing()

        # Test rebuild (is failing)
        # Only run this test for 389-ds older than 1.4.0.22 where unmembering
        # feature was implemented: https://pagure.io/389-ds-base/issue/50077
        # As of today (2019-04-08), 1.3.9 is not released with this change yet
        if ds_is_older('1.4.0.22'):
            try:
                api.Command['automember_rebuild'](type=u'hostgroup')
            except errors.DatabaseError:
                pass
            else:
                pytest.fail("automember_rebuild was not failing with "
                            "an orphan automember rule")

            # Find obsolete automember rules
            result = api.Command['automember_find_orphans'](type=u'hostgroup')
            assert result['count'] == 1

            # Find and remove obsolete automember rules
            result = api.Command['automember_find_orphans'](type=u'hostgroup',
                                                            remove=True)
            assert result['count'] == 1

        # Find obsolete automember rules
        result = api.Command['automember_find_orphans'](type=u'hostgroup')
        assert result['count'] == 0

        # Test rebuild (may not be failing)
        try:
            api.Command['automember_rebuild'](type=u'hostgroup')
        except errors.DatabaseError:
            assert False

        # Final cleanup of automember rule if it still exists
        with raises_exact(errors.NotFound(
                reason=u'%s: Automember rule not found' % hostgroup1.cn)):
            api.Command['automember_del'](hostgroup1.cn, type=u'hostgroup')
