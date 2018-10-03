# Authors:
#   Petr Vobornik <pvoborni@redhat.com>
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
Automember tests
"""

from ipatests.test_webui.ui_driver import UI_driver, screenshot
import ipatests.test_webui.data_hostgroup as hostgroup
from ipatests.test_webui.test_host import host_tasks
import pytest

ENTITY = 'automember'

USER_GROUP_PKEY = 'admins'
USER_GROUP_DATA = {
    'pkey': USER_GROUP_PKEY,
    'add': [
        ('combobox', 'cn', USER_GROUP_PKEY),
    ],
    'mod': [
        ('textarea', 'description', 'user group rule description'),
    ],
}

HOST_GROUP_DATA = {
    'pkey': hostgroup.PKEY,
    'add': [
        ('combobox', 'cn', hostgroup.PKEY),
    ],
    'mod': [
        ('textarea', 'description', 'host group rule description'),
    ],
}


@pytest.mark.tier1
class test_automember(UI_driver):

    def setup(self):
        super(test_automember, self).setup()
        self.init_app()

    def add_user_group_rule(self, pkey):
        self.add_record(
            ENTITY,
            {'pkey': pkey, 'add': [('combobox', 'cn', pkey)]},
            facet='searchgroup'
        )

    def add_host_group_rule(self, pkey):
        self.add_record(
            ENTITY,
            {'pkey': pkey, 'add': [('combobox', 'cn', pkey)]},
            facet='searchhostgroup'
        )

    def add_user(self, pkey, name, surname):
        self.add_record('user', {
            'pkey': pkey,
            'add': [
                ('textbox', 'uid', pkey),
                ('textbox', 'givenname', name),
                ('textbox', 'sn', surname),
            ]
        })

    def add_user_group(self, pkey, description):
        self.add_record('group', {
            'pkey': pkey,
            'add': [
                ('textbox', 'cn', pkey),
                ('textarea', 'description', description),
            ]
        })

    def add_host_group(self, pkey, description):
        self.add_record('hostgroup', {
            'pkey': pkey,
            'add': [
                ('textbox', 'cn', pkey),
                ('textarea', 'description', description),
            ]
        })

    def delete_user_group_rule(self, pkey):
        self.delete(ENTITY, [{'pkey': pkey}], facet='searchgroup')

    def delete_host_group_rule(self, pkey):
        self.delete(ENTITY, [{'pkey': pkey}], facet='searchhostgroup')

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: automember
        """

        # user group rule
        self.basic_crud(ENTITY, USER_GROUP_DATA,
                        search_facet='searchgroup',
                        default_facet='usergrouprule',
                        details_facet='usergrouprule',
                        )

        # prepare host group
        self.basic_crud(hostgroup.ENTITY, hostgroup.DATA,
                        default_facet=hostgroup.DEFAULT_FACET,
                        delete=False)

        # host group rule
        self.navigate_by_menu('identity/automember/amhostgroup')

        self.basic_crud(ENTITY, HOST_GROUP_DATA,
                        search_facet='searchhostgroup',
                        default_facet='hostgrouprule',
                        details_facet='hostgrouprule',
                        navigate=False,
                        breadcrumb='Host group rules',
                        )

        # cleanup
        self.delete(hostgroup.ENTITY, [hostgroup.DATA])

    @screenshot
    def test_rebuild_membership_hosts(self):
        """
        Test automember rebuild membership feature for hosts
        """

        host_util = host_tasks()
        host_util.driver = self.driver
        host_util.config = self.config
        domain = self.config.get('ipa_domain')
        host1 = 'web1.%s' % domain
        host2 = 'web2.%s' % domain

        # Add a hostgroup
        self.add_host_group('webservers', 'webservers')

        # Add hosts
        self.add_record('host', host_util.get_data("web1", domain))
        self.add_record('host', host_util.get_data("web2", domain))

        # Add an automember rule
        self.add_host_group_rule('webservers')

        # Add a condition for automember rule
        self.navigate_to_record('webservers')
        self.add_table_record(
            'automemberinclusiveregex',
            {'fields': [
                ('selectbox', 'key', 'fqdn'),
                ('textbox', 'automemberinclusiveregex', '^web[1-9]+')
            ]}
        )

        # Assert that hosts are not members of hostgroup
        self.navigate_to_record('webservers', entity='hostgroup')
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record(host1, negative=True)
        self.assert_record(host2, negative=True)

        # Rebuild membership for first host, using action on host details facet
        self.navigate_to_record(host1, entity='host')
        self.action_list_action('automember_rebuild')

        # Assert that host is now a member of hostgroup
        self.navigate_to_record('webservers', entity='hostgroup')
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record(host1)
        self.assert_record(host2, negative=True)

        # Remove host from hostgroup
        self.delete_record(host1)

        # Assert that host is not a member of hostgroup
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record(host1, negative=True)
        self.assert_record(host2, negative=True)

        # Rebuild membership for all hosts, using action on hosts search facet
        self.navigate_by_menu('identity/host')
        self.action_list_action('automember_rebuild')

        # Assert that hosts are now members of hostgroup
        self.navigate_to_record('webservers', entity='hostgroup')
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record(host1)
        self.assert_record(host2)

        # Delete hostgroup, hosts and automember rule
        self.delete('hostgroup', [{'pkey': 'webservers'}])
        self.delete('host', [{'pkey': host1}, {'pkey': host2}])
        self.delete_host_group_rule('webservers')

    @screenshot
    def test_rebuild_membership_users(self):
        """
        Test automember rebuild membership feature for users
        """

        # Add a group
        self.add_user_group('devel', 'devel')

        # Add a user
        self.add_user('dev1', 'Dev', 'One')

        # Add another user
        self.add_user('dev2', 'Dev', 'Two')

        # Add an automember rule
        self.add_user_group_rule('devel')

        # Add a condition for automember rule
        self.navigate_to_record('devel')
        self.add_table_record(
            'automemberinclusiveregex',
            {'fields': [
                ('selectbox', 'key', 'uid'),
                ('textbox', 'automemberinclusiveregex', '^dev[1-9]+')
            ]}
        )

        # Assert that users are not members of group
        self.navigate_to_record('devel', entity='group')
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record('dev1', negative=True)
        self.assert_record('dev2', negative=True)

        # Rebuild membership for first user, using action on user details facet
        self.navigate_to_record('dev1', entity='user')
        self.action_list_action('automember_rebuild')

        # Assert that user is now a member of group
        self.navigate_to_record('devel', entity='group')
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record('dev1')
        self.assert_record('dev2', negative=True)

        # Remove user from group
        self.delete_record('dev1')

        # Assert that user is not a member of group
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record('dev1', negative=True)
        self.assert_record('dev2', negative=True)

        # Rebuild membership for all users, using action on users search facet
        self.navigate_by_menu('identity/user_search')
        self.action_list_action('automember_rebuild')

        # Assert that users are now members of group
        self.navigate_to_record('devel', entity='group')
        self.facet_button_click('refresh')
        self.wait_for_request()
        self.assert_record('dev1')
        self.assert_record('dev2')

        # Delete group, users and automember rule
        self.delete('group', [{'pkey': 'devel'}])
        self.delete('user', [{'pkey': 'dev1'}, {'pkey': 'dev2'}])
        self.delete_user_group_rule('devel')

    @screenshot
    def test_search_user_group_rule(self):
        pkey = 'search123'
        self.add_user_group(pkey, '')
        self.add_user_group_rule(pkey)

        for text in ['search123', 'search', ' search ', 'SEARCH', '123']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey)

        for text in ['search1234', '321']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey, negative=True)

        self.delete_user_group_rule(pkey)
        self.delete('group', [{'pkey': pkey}])

    @screenshot
    def test_search_host_group_rule(self):
        pkey = 'search123'
        self.add_host_group(pkey, '')
        self.add_host_group_rule(pkey)

        for text in ['search123', 'search', ' search ', 'SEARCH', '123']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey)

        for text in ['search1234', '321']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey, negative=True)

        self.delete_host_group_rule(pkey)
        self.delete('hostgroup', [{'pkey': pkey}])
