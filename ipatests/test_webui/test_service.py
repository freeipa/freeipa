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
Service tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest

ENTITY = 'service'


@pytest.mark.tier1
class sevice_tasks(UI_driver):

    def prep_data(self):

        host = self.config.get('ipa_server')
        realm = self.config.get('ipa_realm')
        pkey = 'itest'

        return {
            'pkey': '%s/%s@%s' % (pkey, host, realm),
            'add': [
                ('textbox', 'service', pkey),
                ('combobox', 'host', host)
            ],
            'mod': [
                ('checkbox', 'ipakrbokasdelegate', None),
            ],
        }

    def load_file(self, path):
        # ENHANCEMENT: generate csr dynamically
        with open(path, 'r') as file_d:
            content = file_d.read()
        return content

    def get_http_pkey(self):
        host = self.config.get('ipa_server')
        realm = self.config.get('ipa_realm')
        pkey = 'HTTP/%s@%s' % (host, realm)
        return pkey


@pytest.mark.tier1
class test_service(sevice_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: service
        """
        self.init_app()
        data = self.prep_data()
        self.basic_crud(ENTITY, data)

    @screenshot
    def test_certificates(self):
        """
        Test service certificate actions

        Requires to have CA installed and 'service_csr_path' configuration option
        set.
        """

        if not self.has_ca():
            self.skip('CA is not configured')

        csr_path = self.config.get('service_csr_path')
        if not csr_path:
            self.skip('CSR file is not configured')

        self.init_app()
        data = self.prep_data()
        pkey = data.get('pkey')
        csr = self.load_file(csr_path)
        cert_widget_sel = "div.certificate-widget"

        self.add_record(ENTITY, data)
        self.navigate_to_record(pkey)

        # cert request
        self.action_list_action('request_cert', confirm=False)
        self.assert_dialog()
        self.fill_text("textarea[name='csr'", csr)
        self.dialog_button_click('issue')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel)

        # cert view
        self.action_list_action('view', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        # check that text area is not empty
        self.assert_empty_value('textarea.certificate', negative=True)
        self.dialog_button_click('close')

        # cert download - we can only try to click the download action
        self.action_list_action('download', confirm=False,
                                parents_css_sel=cert_widget_sel)
        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert revoke
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '6')
        self.dialog_button_click('ok')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel + " div.watermark")

        # check that revoke action is not enabled
        self.assert_action_list_action('revoke', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is enabled
        self.assert_action_list_action('remove_hold',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert remove hold
        self.action_list_action('remove_hold', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.dialog_button_click('ok')
        self.wait_for_request(n=2)

        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cleanup
        self.navigate_to_entity(ENTITY, 'search')
        self.delete_record(pkey, data.get('del'))

    @screenshot
    def test_arbitrary_certificates(self):
        """
        Test managing service arbitrary certificate.

        Requires to have 'arbitrary_cert_path' configuration set.
        """
        cert_path = self.config.get('arbitrary_cert_path')
        if not cert_path:
            self.skip('Arbitrary certificate file is not configured')

        self.init_app()
        data = self.prep_data()
        pkey = data.get('pkey')
        cert = self.load_file(cert_path)
        cert_widget_sel = "div.certificate-widget"

        self.add_record(ENTITY, data)
        self.navigate_to_record(pkey)

        # check whether certificate section is present
        self.assert_visible("div[name='certificate']")

        # add certificate
        self.button_click('add', parents_css_sel="div[name='certificate']")
        self.assert_dialog()
        self.fill_textarea('new_cert', cert)
        self.dialog_button_click('add')

        self.assert_visible(cert_widget_sel)

        # cert view
        self.action_list_action('view', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()

        # check that the textarea is not empty
        self.assert_empty_value('textarea.certificate', negative=True)
        self.dialog_button_click('close')

        # cert download - we can only try to click the download action
        self.action_list_action('download', confirm=False,
                                parents_css_sel=cert_widget_sel)

        # check that revoke action is not enabled
        self.assert_action_list_action('revoke', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cleanup
        self.navigate_to_entity(ENTITY, 'search')
        self.delete_record(pkey, data.get('del'))

    @screenshot
    def test_ca_less(self):
        """
        Test service certificate actions in CA-less install
        http://www.freeipa.org/page/V3/CA-less_install
        """
        if self.has_ca():
            self.skip('CA is installed')

        self.init_app()

        data = self.prep_data()
        pkey = data.get('pkey')

        self.add_record(ENTITY, data)
        self.navigate_to_record(pkey)

        self.assert_action_list_action('request_cert', visible=False)

        self.navigate_by_breadcrumb('Services')
        self.delete_record(pkey, data.get('del'))

    @screenshot
    def test_kerberos_flags(self):
        """
        Test Kerberos flags
        http://www.freeipa.org/page/V3/Kerberos_Flags
        """
        pkey = self.get_http_pkey()
        name = 'ipakrbokasdelegate'
        mod = {'mod': [('checkbox', name, None)]}
        checked = ['checked']

        self.init_app()
        self.navigate_to_record(pkey, entity=ENTITY)

        if self.get_field_checked(name) == checked:
            self.mod_record(ENTITY, mod)  # uncheck

        self.mod_record(ENTITY, mod)
        self.validate_fields([('checkbox', name, checked)])
        self.mod_record(ENTITY, mod)
        self.validate_fields([('checkbox', name, [])])
