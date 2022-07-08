#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Place for various miscellaneous test cases that do not fit to other suites
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest
import re

try:
    from selenium.webdriver.common.by import By
except ImportError:
    pass


@pytest.mark.tier1
class TestMiscCases(UI_driver):

    @screenshot
    def test_version_present(self):

        self.init_app()

        self.profile_menu_action('about')

        about_text = self.get_text('div[data-name="version_dialog"] p')
        ver_re = re.compile('version: .*')
        assert re.search(ver_re, about_text), 'Version not found'
        self.dialog_button_click('ok')

    @screenshot
    def test_customization_pagination_input_required(self):
        """Test if 'pagination size' is required when submitting the form."""
        self.init_app()

        self.profile_menu_action('configuration')
        self.fill_input('pagination_size', '')
        self.dialog_button_click('save')

        pagination_size_elem = self.find(
            ".widget[name='pagination_size']", By.CSS_SELECTOR)

        self.assert_field_validation_required(parent=pagination_size_elem)
