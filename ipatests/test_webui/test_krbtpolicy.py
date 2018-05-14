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
Kerberos policy tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest

ENTITY = 'krbtpolicy'

DATA = {
    'mod': [
        ('textbox', 'krbmaxrenewableage', '599000'),
        ('textbox', 'krbmaxticketlife', '79800'),
    ],
}

DATA2 = {
    'mod': [
        ('textbox', 'krbmaxrenewableage', '604800'),
        ('textbox', 'krbmaxticketlife', '86400'),
    ],
}


@pytest.mark.tier1
class test_krbtpolicy(UI_driver):

    @screenshot
    def test_mod(self):
        """
        Kerberos policy mod test
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        self.mod_record(ENTITY, DATA)
        self.mod_record(ENTITY, DATA2)

    @screenshot
    def test_verifying_button(self):
        """
        verifying Revert, Refresh and Undo button
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # verifying Revert, Refresh and Undo button for max renewable age
        self.button_reset('krbmaxrenewableage', '444800')

        # verifying Revert, Refresh and Undo button for max ticket age
        self.button_reset('krbmaxticketlife', '46400')

    def button_reset(self, field, value):
        """
        testing "Revert", "Refresh" and "Undo" button
        """
        # verifying undo button
        self.fill_textbox(field, value)
        facet = self.get_facet()
        s = ".input-group button[name='undo']"
        self._button_click(s, facet)
        self.verify_btn_action(field, value)
        self.wait_for_request(n=2)

        # verifying revert button
        self.fill_textbox(field, value)
        self.facet_button_click('revert')
        self.verify_btn_action(field, value)
        self.wait_for_request(n=2)

        # verifying refresh button
        self.fill_textbox(field, value)
        self.facet_button_click('refresh')
        self.verify_btn_action(field, value)
        self.wait_for_request(n=2)

    def verify_btn_action(self, field, mod_value, negative=True):
        """
        comparing current value with modified value
        """
        current_value = self.get_field_value(field, element="input")
        if negative:
            assert current_value != mod_value
        else:
            assert current_value == mod_value

    @screenshot
    def test_negative_value(self):
        """
        Negative test for Max renew
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)

        # string used instead of integer
        expected_error = 'Must be an integer'
        value = 'nonInteger'
        self.modify_policy(expected_error, value)

        # bigger than max value
        expected_error = 'Maximum value is 2147483647'
        value = '2147483649'
        self.modify_policy(expected_error, value)

        # smaller than max value
        expected_error = 'Minimum value is 1'
        value = '-1'
        self.modify_policy(expected_error, value)

    def modify_policy(self, expected_error, value):
        """
        modifying kerberos policy values and asserting expected error
        """
        self.fill_textbox('krbmaxrenewableage', value)
        self.wait_for_request()
        self.assert_field_validation(expected_error)
        self.facet_button_click('revert')
        self.fill_textbox('krbmaxticketlife', value)
        self.wait_for_request()
        self.assert_field_validation(expected_error, field='krbmaxticketlife')
        self.facet_button_click('revert')

    @screenshot
    def test_verify_measurement_unit(self):
        """
        verifying measurement unit for Max renew and Max life
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)
        krbmaxrenewableage = self.get_text('label[name="krbmaxrenewableage"]')
        krbmaxticketlife = self.get_text('label[name="krbmaxticketlife"]')
        assert "Max renew (seconds)" in krbmaxrenewableage
        assert "Max life (seconds)" in krbmaxticketlife
