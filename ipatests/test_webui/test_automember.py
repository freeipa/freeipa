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

SEARCH_CASES = {
    'name': 'search-123',
    'description': 'Short description !@#$%^&*()',
    'positive': [
        'search-123',
        'search',
        'search ',
        ' search',
        'SEARCH',
        '123',
        '!@#$%^&*()',
        'hort descr',
        'description  !',
    ],
    'negative': [
        'searc-123',
        '321',
        'search 123',
        'search Short',
        'description!',
    ],
}

# Condition types
INCLUSIVE = 'inclusive'
EXCLUSIVE = 'exclusive'


@pytest.mark.tier1
class TestAutomember(UI_driver):

    AUTOMEMBER_RULE_EXISTS_ERROR = (
        'Automember rule with name "{}" already exists'
    )

    def setup(self):
        super(TestAutomember, self).setup()
        self.init_app()

    def add_user_group_rules(self, *pkeys, **kwargs):
        # We implicitly trigger "Add and Add Another" by passing multiple
        # records to add_record method.
        # TODO: Create more transparent mechanism to test "Add <entity>" dialog
        self.add_record(
            ENTITY,
            [{
                'pkey': pkey,
                'add': [('combobox', 'cn', pkey)],
            } for pkey in pkeys],
            facet='searchgroup',
            **kwargs
        )

    def add_host_group_rules(self, *pkeys, **kwargs):
        self.add_record(
            ENTITY,
            [{
                'pkey': pkey,
                'add': [('combobox', 'cn', pkey)],
            } for pkey in pkeys],
            facet='searchhostgroup',
            **kwargs
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

    def add_user_group(self, pkey, description=''):
        self.add_record('group', {
            'pkey': pkey,
            'add': [
                ('textbox', 'cn', pkey),
                ('textarea', 'description', description),
            ]
        })

    def add_host_group(self, pkey, description=''):
        self.add_record('hostgroup', {
            'pkey': pkey,
            'add': [
                ('textbox', 'cn', pkey),
                ('textarea', 'description', description),
            ]
        })

    def delete_users(self, *pkeys):
        self.delete('user', [{'pkey': pkey} for pkey in pkeys])

    def delete_user_groups(self, *pkeys):
        self.delete('group', [{'pkey': pkey} for pkey in pkeys])

    def delete_user_group_rules(self, *pkeys):
        self.delete(ENTITY, [{'pkey': pkey} for pkey in pkeys],
                    facet='searchgroup')

    def delete_host_groups(self, *pkeys):
        self.delete('hostgroup', [{'pkey': pkey} for pkey in pkeys])

    def delete_host_group_rules(self, *pkeys):
        self.delete(ENTITY, [{'pkey': pkey} for pkey in pkeys],
                    facet='searchhostgroup')

    def add_conditions(self, conditions, condition_type):
        """
        Add conditions to a rule

        :param conditions: list of conditions where condition is a pair
                           (attribute, expression)
        :param condition_type: can be 'inclusive' or 'exclusive'
        """

        name = 'automember{}regex'.format(condition_type)

        attribute, expression = conditions[0]
        another_conditions = conditions[1:]
        another_conditions.reverse()

        self.add_table_record(name, {'fields': [
            ('selectbox', 'key', attribute),
            ('textbox', name, expression)
        ]}, add_another=bool(another_conditions))

        while another_conditions:
            attribute, expression = another_conditions.pop()
            self.add_another_table_record(
                {'fields': [
                    ('selectbox', 'key', attribute),
                    ('textbox', name, expression)
                ]},
                add_another=bool(another_conditions)
            )

    def delete_conditions(self, conditions, condition_type):
        """
        Delete rule conditions

        :param conditions: list of conditions where condition is a pair
                           (attribute, expression)
        :param condition_type: can be 'inclusive' or 'exclusive'
        """

        self.delete_record(
            ['{}={}'.format(attr, exp) for attr, exp in conditions],
            parent=self.get_facet(),
            table_name='automember{}regex'.format(condition_type)
        )

    def open_new_condition_dialog(self, condition_type):
        table = self.find_by_selector(
            "table[name='automember{}regex'].table".format(condition_type),
            strict=True
        )
        btn = self.find_by_selector(".btn[name=add]", table, strict=True)
        btn.click()
        self.wait()

    def get_host_util(self):
        host_util = host_tasks()
        host_util.driver = self.driver
        host_util.config = self.config
        return host_util

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

        host_util = self.get_host_util()
        domain = self.config.get('ipa_domain')
        host1 = 'web1.%s' % domain
        host2 = 'web2.%s' % domain

        # Add a hostgroup
        self.add_host_group('webservers', 'webservers')

        # Add hosts
        self.add_record('host', host_util.get_data("web1", domain))
        self.add_record('host', host_util.get_data("web2", domain))

        # Add an automember rule
        self.add_host_group_rules('webservers')

        # Add a condition for automember rule
        self.navigate_to_record('webservers')
        self.add_conditions([('fqdn', '^web[1-9]+')], condition_type=INCLUSIVE)

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
        self.delete_host_groups('webservers')
        self.delete('host', [{'pkey': host1}, {'pkey': host2}])
        self.delete_host_group_rules('webservers')

    @screenshot
    def test_rebuild_membership_users(self):
        """
        Test automember rebuild membership feature for users
        """

        # Add a group
        self.add_user_group('devel', 'devel')

        # Add users
        self.add_user('dev1', 'Dev', 'One')
        self.add_user('dev2', 'Dev', 'Two')

        # Add an automember rule
        self.add_user_group_rules('devel')

        # Add a condition for automember rule
        self.navigate_to_record('devel')
        self.add_conditions([('uid', '^dev[1-9]+')], condition_type=INCLUSIVE)

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
        self.delete_user_groups('devel')
        self.delete_users('dev1', 'dev2')
        self.delete_user_group_rules('devel')

    @screenshot
    def test_add_multiple_user_group_rules(self):
        """
        Test creating and deleting multiple user group rules
        """

        groups = ['group1', 'group2', 'group3']

        for group in groups:
            self.add_user_group(group)

        self.add_user_group_rules(*groups)
        self.delete_user_group_rules(*groups)

    @screenshot
    def test_add_multiple_host_group_rules(self):
        """
        Test creating and deleting multiple host group rules
        """

        groups = ['group1', 'group2', 'group3']

        for group in groups:
            self.add_host_group(group)

        self.add_host_group_rules(*groups)
        self.delete_host_group_rules(*groups)

    @screenshot
    def test_search_user_group_rule(self):
        """
        Test searching user group rules using filter
        """

        pkey = SEARCH_CASES['name']
        self.add_user_group(pkey, '')
        self.add_user_group_rules(pkey)
        self.navigate_to_record(pkey)
        self.mod_record(ENTITY, {'mod': [
            ('textarea', 'description', SEARCH_CASES['description']),
        ]}, facet='usergrouprule')
        self.navigate_to_entity(ENTITY, facet='searchgroup')

        for text in SEARCH_CASES['positive']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey)

        for text in SEARCH_CASES['negative']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey, negative=True)

        self.delete_user_group_rules(pkey)
        self.delete_user_groups(pkey)

    @screenshot
    def test_search_host_group_rule(self):
        """
        Test searching host group rules using filter
        """

        pkey = SEARCH_CASES['name']
        self.add_host_group(pkey, '')
        self.add_host_group_rules(pkey, navigate=True)
        self.navigate_to_record(pkey)
        self.mod_record(ENTITY, {'mod': [
            ('textarea', 'description', SEARCH_CASES['description']),
        ]}, facet='hostgrouprule')
        self.navigate_to_entity(ENTITY, facet='searchhostgroup')

        for text in SEARCH_CASES['positive']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey)

        for text in SEARCH_CASES['negative']:
            self.apply_search_filter(text)
            self.wait_for_request()
            self.assert_record(pkey, negative=True)

        self.delete_host_group_rules(pkey)
        self.delete_host_groups(pkey)

    @screenshot
    def test_add_user_group_rule_conditions(self):
        """
        Test creating and deleting user group rule conditions
        """

        pkey = 'devel'
        one_inc_condition = ('employeetype', '*engineer*')
        inc_conditions = [
            ('cn', 'inclusive-expression'),
            ('description', 'other-inclusive-expression'),
        ]
        one_exc_condition = ('employeetype', '*manager*')
        exc_conditions = [
            ('cn', 'exclusive-expression'),
            ('description', 'other-exclusive-expression'),
        ]

        self.add_user_group(pkey)
        self.add_user_group_rules(pkey)

        self.navigate_to_record(pkey)

        self.add_conditions([one_inc_condition], condition_type=INCLUSIVE)
        self.add_conditions(inc_conditions, condition_type=INCLUSIVE)
        self.add_conditions([one_exc_condition], condition_type=EXCLUSIVE)
        self.add_conditions(exc_conditions, condition_type=EXCLUSIVE)

        self.delete_conditions([one_inc_condition], condition_type=INCLUSIVE)
        self.delete_conditions(inc_conditions, condition_type=INCLUSIVE)
        self.delete_conditions([one_exc_condition], condition_type=EXCLUSIVE)
        self.delete_conditions(inc_conditions, condition_type=EXCLUSIVE)

        self.delete_user_group_rules(pkey)
        self.delete_user_groups(pkey)

    @screenshot
    def test_add_host_group_rule_conditions(self):
        """
        Test creating and deleting user group rule conditions
        """

        pkey = 'devel'
        one_inc_condition = ('ipaclientversion', '4.8')
        inc_conditions = [
            ('cn', 'inclusive-expression'),
            ('description', 'other-inclusive-expression'),
        ]
        one_exc_condition = ('ipaclientversion', '4.7')
        exc_conditions = [
            ('cn', 'exclusive-expression'),
            ('description', 'other-exclusive-expression'),
        ]

        self.add_host_group(pkey)
        self.add_host_group_rules(pkey)

        self.navigate_to_record(pkey)

        self.add_conditions([one_inc_condition], condition_type=INCLUSIVE)
        self.add_conditions(inc_conditions, condition_type=INCLUSIVE)
        self.add_conditions([one_exc_condition], condition_type=EXCLUSIVE)
        self.add_conditions(exc_conditions, condition_type=EXCLUSIVE)

        self.delete_conditions([one_inc_condition], condition_type=INCLUSIVE)
        self.delete_conditions(inc_conditions, condition_type=INCLUSIVE)
        self.delete_conditions([one_exc_condition], condition_type=EXCLUSIVE)
        self.delete_conditions(inc_conditions, condition_type=EXCLUSIVE)

        self.delete_host_group_rules(pkey)
        self.delete_host_groups(pkey)

    @screenshot
    def test_cancel_new_user_group_rule_condition_dialog(self):
        """
        Test canceling of creating new user group rule condition
        """

        pkey = 'devel'

        self.add_user_group(pkey)
        self.add_user_group_rules(pkey)
        self.navigate_to_record(pkey)

        for condition_type in [INCLUSIVE, EXCLUSIVE]:
            self.open_new_condition_dialog(condition_type)
            self.fill_fields([('selectbox', 'key', 'title')])
            self.dialog_button_click('cancel')

        self.delete_user_group_rules(pkey)
        self.delete_user_groups(pkey)

    @screenshot
    def test_cancel_new_host_group_rule_condition_dialog(self):
        """
        Test canceling of creating new host group rule condition
        """

        pkey = 'devel'

        self.add_host_group(pkey)
        self.add_host_group_rules(pkey)
        self.navigate_to_record(pkey)

        for condition_type in [INCLUSIVE, EXCLUSIVE]:
            self.open_new_condition_dialog(condition_type)
            self.fill_fields([('selectbox', 'key', 'serverhostname')])
            self.dialog_button_click('cancel')

        self.delete_host_group_rules(pkey)
        self.delete_host_groups(pkey)

    @screenshot
    def test_set_default_user_group(self):
        """
        Test setting default user group
        """

        pkey = 'default-user-group'
        user_pkey = 'some-user'

        self.add_user_group(pkey)
        self.navigate_by_menu('identity/automember/amgroup')
        self.select_combobox('automemberdefaultgroup', pkey)

        self.add_user(user_pkey, 'Some', 'User')
        self.navigate_to_record(user_pkey)
        self.switch_to_facet('memberof_group')
        self.assert_record(pkey)

        self.delete_users(user_pkey)
        self.delete_user_groups(pkey)

    @screenshot
    def test_set_default_host_group(self):
        """
        Test setting default host group
        """

        pkey = 'default-host-group'
        host_util = self.get_host_util()
        domain = self.config.get('ipa_domain')

        self.add_host_group(pkey)
        self.navigate_by_menu('identity/automember/amhostgroup')
        self.select_combobox('automemberdefaultgroup', pkey)

        host_data = host_util.get_data('some-host', domain)
        self.add_record('host', host_data)
        self.navigate_to_record(host_data['pkey'])
        self.switch_to_facet('memberof_hostgroup')
        self.assert_record(pkey)

        self.delete('host', [{'pkey': host_data['pkey']}])
        self.delete_host_groups(pkey)

    @screenshot
    def test_add_user_group_rule_with_no_group(self):

        self.add_record(
            ENTITY,
            {'pkey': 'empty-user-group', 'add': []},
            facet='searchgroup',
            negative=True
        )

    @screenshot
    def test_add_host_group_rule_with_no_group(self):

        self.add_record(
            ENTITY,
            {'pkey': 'empty-host-group', 'add': []},
            facet='searchhostgroup',
            negative=True
        )

    @screenshot
    def test_add_user_group_rules_for_same_group(self):
        """
        Test creating user group rules for same group
        """

        group_name = 'some-user-group'

        self.add_user_group(group_name)
        self.add_user_group_rules(group_name)
        self.add_user_group_rules(group_name, negative=True, pre_delete=False)

        self.assert_last_error_dialog(
            self.AUTOMEMBER_RULE_EXISTS_ERROR.format(group_name)
        )

        self.delete_user_group_rules(group_name)
        self.delete_user_groups(group_name)

    @screenshot
    def test_add_host_group_rules_for_same_group(self):
        """
        Test creating host group rules for same group
        """

        group_name = 'some-host-group'

        self.add_host_group(group_name)
        self.add_host_group_rules(group_name)
        self.add_host_group_rules(group_name, negative=True, pre_delete=False)

        self.assert_last_error_dialog(
            self.AUTOMEMBER_RULE_EXISTS_ERROR.format(group_name)
        )

        self.delete_host_group_rules(group_name)
        self.delete_host_groups(group_name)

    @screenshot
    def test_cancel_group_rule_creating(self):
        """
        Test canceling of creating new automember group rule
        """

        self.add_user_group_rules('some-user-group', dialog_btn='cancel')
        self.add_host_group_rules('some-host-group', dialog_btn='cancel')
