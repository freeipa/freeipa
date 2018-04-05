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
Group tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_group as group
import ipatests.test_webui.data_user as user
import ipatests.test_webui.data_netgroup as netgroup
import ipatests.test_webui.data_hbac as hbac
import ipatests.test_webui.test_rbac as rbac
import ipatests.test_webui.data_sudo as sudo
import pytest

try:
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass


@pytest.mark.tier1
class test_group(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: group
        """
        self.init_app()
        self.basic_crud(group.ENTITY, group.DATA,
                        default_facet=group.DEFAULT_FACET)

    @screenshot
    def test_group_types(self):
        """
        Test group types in adder dialog
        """
        self.init_app()

        pkey = 'itest-group'
        data = {
            'pkey': pkey,
            'add': [
                ('callback', self.check_posix_enabled, True),
                ('textbox', 'cn', pkey),
                ('textarea', 'description', 'test-group desc'),
                ('radio', 'type', 'nonposix'),
                ('callback', self.check_posix_enabled, False),
                ('radio', 'type', 'posix'),
                ('callback', self.check_posix_enabled, True),
                ('radio', 'type', 'external'),
                ('callback', self.check_posix_enabled, False),
                ('radio', 'type', 'posix'),
                ('callback', self.check_posix_enabled, True),
            ],
        }

        self.add_record(group.ENTITY, data)
        self.delete(group.ENTITY, [data], navigate=False)

    def check_posix_enabled(self, enabled):
        self.assert_disabled("[name=gidnumber]", negative=enabled)

    @screenshot
    def test_add_group_negative(self):
        """
        Negative test for adding groups
        """
        self.init_app()

        self.empty_group_name()
        self.invalid_group_name()
        self.duplicate_group_name()
        self.tailing_spaces_in_group_description()
        self.leading_spaces_in_group_description()

    def empty_group_name(self):
        self.navigate_to_entity(group.ENTITY)
        self.facet_button_click('add')
        self.dialog_button_click('add')
        elem = self.find(".widget[name='cn']")
        self.assert_field_validation_required(elem)
        self.dialog_button_click('cancel')

    def invalid_group_name(self):
        expected_error = 'may only include letters, numbers, _, -, . and $'
        pkey = ';test-gr@up'
        self.navigate_to_entity(group.ENTITY)
        self.facet_button_click('add')
        self.fill_input('cn', pkey)
        elem = self.find(".widget[name='cn']")
        self.assert_field_validation(expected_error, parent=elem)
        self.dialog_button_click('cancel')

    def duplicate_group_name(self):
        pkey = 'editors'
        expected_error = 'group with name "editors" already exists'
        self.navigate_to_entity(group.ENTITY)
        self.facet_button_click('add')
        self.fill_input('cn', pkey)
        self.cancel_retry_dialog(expected_error)

    def tailing_spaces_in_group_description(self):
        pkey = 'itest_group0'
        desc = 'with_trailing_space '
        expected_error = 'invalid \'desc\': Leading and trailing ' \
                         'spaces are not allowed'
        self.navigate_to_entity(group.ENTITY)
        self.facet_button_click('add')
        self.fill_input('cn', pkey)
        self.fill_textarea('description', desc)
        self.cancel_retry_dialog(expected_error)

    def leading_spaces_in_group_description(self):
        pkey = 'itest_group0'
        desc = ' with_leading_space'
        expected_error = 'invalid \'desc\': Leading and trailing' \
                         ' spaces are not allowed'
        self.navigate_to_entity(group.ENTITY)
        self.facet_button_click('add')
        self.fill_input('cn', pkey)
        self.fill_textarea('description', desc)
        self.cancel_retry_dialog(expected_error)

    def cancel_retry_dialog(self, expected_error):
        self.dialog_button_click('add')
        dialog = self.get_last_error_dialog()
        assert (expected_error in dialog.text)
        self.wait_for_request()
        # Key press for Retry
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(n=2)
        self.dialog_button_click('cancel')
        self.wait_for_request(n=2)
        self.dialog_button_click('cancel')

    @screenshot
    def test_add_multiple_group(self):
        """
        Use 'add and add another' button to create multiple groups at one shot
        """
        self.init_app()
        # adding a POSIX and a Non-POSIX group
        self.add_record(group.ENTITY, [group.DATA, group.DATA2])

        # adding Two Non-POSIX groups
        self.add_record(group.ENTITY, [group.DATA9, group.DATA10])

        # adding Two POSIX groups
        self.add_record(group.ENTITY, [group.DATA5, group.DATA6])

        # delete multiple records
        records = [group.DATA, group.DATA2, group.DATA5, group.DATA6,
                   group.DATA9, group.DATA10]
        self.select_multiple_records(records)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')

    @screenshot
    def test_add_and_edit_group(self):
        """
        1. add and switch to edit mode
        2. add and cancel
        """
        self.init_app()

        # add and edit record
        self.add_record(group.ENTITY, group.DATA, dialog_btn='add_and_edit')
        self.switch_to_facet('details')
        self.delete_action()

        # add then cancel
        self.add_record(group.ENTITY, group.DATA, dialog_btn='cancel')

    @screenshot
    def test_actions(self):
        """
        Test group actions
        """

        self.init_app()

        self.add_record(group.ENTITY, group.DATA)
        self.navigate_to_record(group.PKEY)
        self.switch_to_facet('details')
        self.make_posix_action()
        self.delete_action()

        self.add_record(group.ENTITY, group.DATA, navigate=False)
        self.navigate_to_record(group.PKEY)
        self.switch_to_facet('details')
        self.facet_button_click('refresh')  # workaround for BUG: #3702
        self.make_external_action()
        self.delete_action()

    def make_external_action(self):
        self.action_list_action('make_external')
        self.wait_for_request(n=2)
        self.assert_no_error_dialog()
        self.assert_text_field('external', 'External', element='span')

    def make_posix_action(self):
        self.action_list_action('make_posix')
        self.wait_for_request(n=2)
        self.assert_no_error_dialog()
        self.assert_text_field('external', 'POSIX', element='span')

    def delete_action(self, entity=group.ENTITY, pkey=group.PKEY):
        self.action_list_action('delete')
        self.wait_for_request(n=4)
        self.assert_no_error_dialog()
        self.assert_facet(entity, 'search')
        self.assert_record(pkey, negative=True)

    @screenshot
    def test_associations(self):
        """
        Test group associations
        """
        self.init_app()

        # prepare
        # -------
        self.add_record(group.ENTITY, [group.DATA, group.DATA2, group.DATA3])
        self.add_record(user.ENTITY, [user.DATA, user.DATA2])
        self.add_record(netgroup.ENTITY, [netgroup.DATA, netgroup.DATA2])
        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)

        # add & remove associations
        # -------------------------
        self.navigate_to_record(group.PKEY, entity=group.ENTITY)

        # "members" add with multiple select
        self.add_associations([group.PKEY2, group.PKEY3], facet='member_group',
                              delete=True)
        self.add_associations([user.PKEY, user.PKEY2], facet='member_user',
                              delete=True)
        # TODO: external

        # "member of": add with search
        self.add_associations([group.PKEY3, group.PKEY2],
                              facet='memberof_group', delete=True, search=True)
        self.add_associations([netgroup.PKEY, netgroup.PKEY2],
                              facet='memberof_netgroup',
                              delete=True, search=True)
        self.add_associations([rbac.ROLE_PKEY], facet='memberof_role',
                              delete=True)
        self.add_associations([hbac.RULE_PKEY], facet='memberof_hbacrule',
                              delete=True)
        self.navigate_to_record(group.PKEY, entity=group.ENTITY)
        self.add_associations([sudo.RULE_PKEY], facet='memberof_sudorule',
                              delete=True, search=True)

        # cleanup
        # -------
        self.delete(group.ENTITY, [group.DATA, group.DATA2, group.DATA3])
        self.delete(user.ENTITY, [user.DATA, user.DATA2])
        self.delete(netgroup.ENTITY, [netgroup.DATA, netgroup.DATA2])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_indirect_associations(self):
        """
        Group indirect associations
        """
        self.init_app()

        # add
        # ---
        self.add_record(group.ENTITY, [group.DATA, group.DATA2, group.DATA3,
                                       group.DATA4, group.DATA5])
        self.add_record(user.ENTITY, user.DATA)

        # prepare indirect member
        self.navigate_to_entity(group.ENTITY, 'search')
        self.navigate_to_record(group.PKEY2)
        self.add_associations([user.PKEY])
        self.add_associations([group.PKEY3], 'member_group')

        self.navigate_to_entity(group.ENTITY, 'search')
        self.navigate_to_record(group.PKEY)
        self.add_associations([group.PKEY2], 'member_group')

        # prepare indirect memberof
        self.navigate_to_entity(group.ENTITY, 'search')
        self.navigate_to_record(group.PKEY4)
        self.add_associations([group.PKEY], 'member_group')
        self.add_associations([group.PKEY5], 'memberof_group')

        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.navigate_to_record(netgroup.PKEY)
        self.add_table_associations('memberuser_group', [group.PKEY4])

        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.navigate_to_record(rbac.ROLE_PKEY)
        self.add_associations([group.PKEY4], facet='member_group')

        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)
        self.add_table_associations('memberuser_group', [group.PKEY4])

        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)
        self.navigate_to_record(sudo.RULE_PKEY)
        self.add_table_associations('memberuser_group', [group.PKEY4])

        # check indirect associations
        # ---------------------------
        self.navigate_to_entity(group.ENTITY, 'search')
        self.navigate_to_record(group.PKEY)

        self.assert_indirect_record(user.PKEY, group.ENTITY, 'member_user')
        self.assert_indirect_record(group.PKEY3, group.ENTITY, 'member_group')

        self.assert_indirect_record(group.PKEY5, group.ENTITY,
                                    'memberof_group')
        self.assert_indirect_record(netgroup.PKEY, group.ENTITY,
                                    'memberof_netgroup')
        self.assert_indirect_record(rbac.ROLE_PKEY, group.ENTITY,
                                    'memberof_role')
        self.assert_indirect_record(hbac.RULE_PKEY, group.ENTITY,
                                    'memberof_hbacrule')
        self.assert_indirect_record(sudo.RULE_PKEY, group.ENTITY,
                                    'memberof_sudorule')

        # cleanup
        # -------
        self.delete(group.ENTITY, [group.DATA, group.DATA2, group.DATA3,
                                   group.DATA4, group.DATA5])
        self.delete(user.ENTITY, [user.DATA])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])
