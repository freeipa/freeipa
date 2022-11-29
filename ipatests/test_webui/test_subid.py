
"""
Tests for subordinateid.
"""

from ipatests.test_webui.ui_driver import UI_driver
import ipatests.test_webui.data_config as config_data
import ipatests.test_webui.data_user as user_data
from ipatests.test_webui.ui_driver import screenshot

import re
import pytest

try:
    from selenium.common.exceptions import NoSuchElementException
except ImportError:
    pass


class test_subid(UI_driver):

    def add_user(self, pkey, name, surname):
        self.add_record('user', {
            'pkey': pkey,
            'add': [
                ('textbox', 'uid', pkey),
                ('textbox', 'givenname', name),
                ('textbox', 'sn', surname),
            ]
        })

    def set_default_subid(self):
        self.navigate_to_entity(config_data.ENTITY)
        self.check_option('ipauserdefaultsubordinateid', 'checked')
        self.facet_button_click('save')

    def get_user_count(self, user_pkey):
        self.navigate_to_entity('subid', facet='search')
        self.apply_search_filter(user_pkey)
        self.wait_for_request()
        return self.get_rows()

    @screenshot
    def test_set_defaultsubid(self):
        """
        Test to verify that enable/disable is working for
        adding subids to new users.
        """
        self.init_app()
        self.add_record(user_data.ENTITY, user_data.DATA2)
        self.navigate_to_entity(config_data.ENTITY)
        # test subid can be enabled/disabled.
        self.set_default_subid()
        assert self.get_field_checked('ipauserdefaultsubordinateid')
        self.set_default_subid()
        assert not self.get_field_checked('ipauserdefaultsubordinateid')

    @screenshot
    def test_user_defaultsubid(self):
        """
        Test to verify that subid is generated for new user.
        """
        self.init_app()
        user_pkey = "some-user"

        self.set_default_subid()
        assert self.get_field_checked('ipauserdefaultsubordinateid')

        before_count = self.get_user_count(user_pkey)
        assert len(before_count) == 0

        self.add_user(user_pkey, 'Some', 'User')
        after_count = self.get_user_count(user_pkey)
        assert len(after_count) == 1

    @screenshot
    def test_user_subid_mod_desc(self):
        """
        Test to verify that auto-assigned subid description is modified.
        """
        self.init_app()
        self.navigate_to_record("some-user")
        self.switch_to_facet('memberof_subid')
        rows = self.get_rows()
        self.navigate_to_row_record(rows[-1])
        self.fill_textbox("description", "some-user-subid-desc")
        self.facet_button_click('save')

    @screenshot
    def test_admin_subid(self):
        """
        Test to verify that subid range is created with owner admin.
        """
        self.init_app()
        self.navigate_to_entity('subid', facet='search')
        self.facet_button_click('add')
        self.select_combobox('ipaowner', 'admin')
        self.dialog_button_click('add')
        self.wait(0.3)
        self.assert_no_error_dialog()

    @screenshot
    def test_admin_subid_negative(self):
        """
        Test to verify that readding the subid fails with error.
        """
        self.init_app()
        self.navigate_to_entity('subid', facet='search')
        self.facet_button_click('add')
        self.select_combobox('ipaowner', 'admin')
        self.dialog_button_click('add')
        self.wait(0.3)
        err_dialog = self.get_last_error_dialog(dialog_name='error_dialog')
        text = self.get_text('.modal-body div p', err_dialog)
        text = text.strip()
        pattern = r'Subordinate id with with name .* already exists.'
        assert re.search(pattern, text) is not None
        self.close_all_dialogs()

    @screenshot
    def test_user_subid_add(self):
        """
        Test to verify that subid range is created for given user.
        """
        self.init_app()
        self.navigate_to_entity('subid', facet='search')
        before_count = self.get_rows()
        self.facet_button_click('add')
        self.select_combobox('ipaowner', user_data.PKEY2)
        self.dialog_button_click('add')
        self.wait(0.3)
        self.assert_no_error_dialog()
        after_count = self.get_rows()
        assert len(before_count) < len(after_count)

    @screenshot
    def test_subid_range_deletion_not_allowed(self):
        """
        Test to check that subid range delete is not
        allowed from WebUI i.e Delete button is not available.
        """
        self.init_app()
        self.navigate_to_entity('subid', facet='search')
        admin_uid = self.get_record_pkey("admin", "ipaowner",
                                         table_name="ipauniqueid")
        with pytest.raises(NoSuchElementException) as excinfo:
            self.delete_record(admin_uid, table_name="ipauniqueid")
        # Ensure that the exception is really related to missing remove button
        msg = r"Unable to locate element: .facet-controls button\[name=remove\]"
        assert excinfo.match(msg)
