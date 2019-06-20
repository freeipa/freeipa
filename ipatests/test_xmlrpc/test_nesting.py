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
Test group nesting and indirect members
"""

from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.group_plugin import GroupTracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.tracker.hostgroup_plugin import HostGroupTracker
import pytest


@pytest.fixture(scope='class')
def user1(request, xmlrpc_setup):
    tracker = UserTracker(name=u'tuser1', givenname=u'Test1', sn=u'User1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user2(request, xmlrpc_setup):
    tracker = UserTracker(name=u'tuser2', givenname=u'Test2', sn=u'User2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user3(request, xmlrpc_setup):
    tracker = UserTracker(name=u'tuser3', givenname=u'Test3', sn=u'User3')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def user4(request, xmlrpc_setup):
    tracker = UserTracker(name=u'tuser4', givenname=u'Test4', sn=u'User4')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group1(request, xmlrpc_setup):
    tracker = GroupTracker(name=u'testgroup1', description=u'Test desc1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group2(request, xmlrpc_setup):
    tracker = GroupTracker(name=u'testgroup2', description=u'Test desc2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group3(request, xmlrpc_setup):
    tracker = GroupTracker(name=u'testgroup3', description=u'Test desc3')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def group4(request, xmlrpc_setup):
    tracker = GroupTracker(name=u'testgroup4', description=u'Test desc4')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host1(request, xmlrpc_setup):
    tracker = HostTracker(name=u'host1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup1(request, xmlrpc_setup):
    tracker = HostGroupTracker(name=u'hostgroup1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def hostgroup2(request, xmlrpc_setup):
    tracker = HostGroupTracker(name=u'hostgroup2')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestNestingUserGroups(XMLRPC_test):
    def test_create_groups_and_users(self, group1, group2, group3, group4,
                                     user1, user2, user3, user4):
        """ Create groups and users """
        group1.ensure_exists()
        group2.ensure_exists()
        group3.ensure_exists()
        group4.ensure_exists()
        user1.ensure_exists()
        user2.ensure_exists()
        user3.ensure_exists()
        user4.ensure_exists()

        ###############
        # member stuff
        #
        # Create 4 groups and 4 users and set the following membership:
        #
        # g1:
        #    no direct memberships
        #
        # g2:
        #    memberof: g1
        #    member: user1, user2
        #
        # g3:
        #    memberof: g1
        #    member: user3, g4
        #
        # g4:
        #    memberof: g3
        #    member: user1, user4
        #
        # So when we do a show it looks like:
        #
        # g1:
        #    member groups: g2, g3
        #    indirect member group: g4
        #    indirect member users: user1, user2, tuser3, tuser4
        #
        # g2:
        #    member of group: g1
        #    member users: tuser1, tuser2
        #
        # g3:
        #  member users: tuser3
        #  member groups: g4
        #  member of groups: g1
        #  indirect member users: tuser4
        #
        # g4:
        #  member users: tuser1, tuser4
        #  member of groups: g3
        #  indirect member of groups: g1
        #
        # Note that tuser1 is an indirect member of g1 both through
        # g2 and g4. It should appear just once in the list.

    def test_add_group_members_to_groups(self, group1, group2, group3):
        """ Add group1 two members: group2 and group3 """
        group1.add_member(dict(group=group2.cn))
        group2.attrs.update(memberof_group=[group1.cn])
        group1.add_member(dict(group=group3.cn))
        group3.attrs.update(memberof_group=[group1.cn])

    def test_add_user_members_to_groups(self, user1, user2, user3, user4,
                                        group1, group2, group3, group4):
        """ Add user1 and user2 to group1, add user3 and group4 to group3,
        add user1 and user4 to group4 """
        group2.add_member(dict(user=user1.uid))
        group2.add_member(dict(user=user2.uid))
        group3.add_member(dict(user=user3.uid))
        group3.add_member(dict(group=group4.cn))
        group4.attrs.update(
            memberof_group=[group3.cn],
            memberofindirect_group=[group1.cn]
        )
        group4.add_member(dict(user=user1.uid))
        group4.add_member(dict(user=user4.uid))
        group1.attrs.update(
            memberindirect_user=[user1.uid, user2.uid, user3.uid, user4.uid],
            memberindirect_group=[group4.cn]
        )
        group3.attrs.update(
            memberindirect_user=[u'tuser4', u'tuser1']
        )

    def test_retrieve_group_group(self, group1, group2, group3, group4):
        """ Retrieve all test groups (1-4) """
        group1.retrieve()
        group2.retrieve()
        group3.retrieve()
        group4.retrieve()


@pytest.mark.tier1
class TestNestingHostGroups(XMLRPC_test):
    def test_create_hostgroups(self, host1, hostgroup1, hostgroup2):
        """ Create a host and two hostgroups """
        host1.ensure_exists()
        hostgroup1.ensure_exists()
        hostgroup2.ensure_exists()

    def test_nest_hostgroups(self, host1, hostgroup1, hostgroup2):
        """ Add host1 to hostgroup2, add hostgroup2 to hostgroup1 """
        hostgroup2.add_member(dict(host=host1.fqdn))
        command = hostgroup1.make_add_member_command(
            dict(hostgroup=hostgroup2.cn)
        )
        hostgroup1.attrs.update(
            memberindirect_host=hostgroup2.attrs[u'member_host'],
            member_hostgroup=[hostgroup2.cn]
        )
        result = command()
        hostgroup1.check_add_member(result)
        host1.attrs.update(
            memberof_hostgroup=[hostgroup2.cn],
            memberofindirect_hostgroup=[hostgroup1.cn]
        )

    def test_retrieve_host_hostgroup(self, host1, hostgroup1):
        """ Retrieve host1 and hostgroup1 """
        hostgroup1.retrieve()
        host1.retrieve()
