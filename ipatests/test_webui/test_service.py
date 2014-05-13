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

ENTITY = 'service'


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

    def load_csr(self, path):
        # ENHANCEMENT: generate csr dynamically
        with open(path, 'r') as csr_file:
            csr = csr_file.read()
        return csr

    def get_http_pkey(self):
        host = self.config.get('ipa_server')
        realm = self.config.get('ipa_realm')
        pkey = 'HTTP/%s@%s' % (host, realm)
        return pkey


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
        csr = self.load_csr(csr_path)
        host = self.config.get('ipa_server')
        realm = self.config.get('ipa_realm')

        self.add_record(ENTITY, data)
        self.navigate_to_record(pkey)

        self.assert_visible("div[name='certificate-missing']")

        # cert request
        self.action_list_action('request_cert', confirm=False)
        self.fill_text('textarea.certificate', csr)
        self.dialog_button_click('issue')
        self.wait_for_request(n=2, d=0.5)
        self.assert_visible("div[name='certificate-valid']")

        # cert view
        self.action_list_action('view_cert', confirm=False)
        self.wait()
        self.assert_text("tbody tr:nth-child(2) td:nth-child(2)", host)
        self.assert_text("tbody tr:nth-child(3) td:nth-child(2)", realm)
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get_cert', confirm=False)
        self.wait()
        # We don't know the cert text, so at least open and close the dialog
        self.dialog_button_click('close')

        # cert revoke
        self.action_list_action('revoke_cert', confirm=False)
        self.wait()
        self.select('select', '6')
        self.dialog_button_click('ok')
        self.wait_for_request(n=2)
        self.assert_visible("div[name='certificate-revoked']")

        # cert restore
        self.action_list_action('restore_cert', confirm=False)
        self.wait()
        self.dialog_button_click('ok')
        self.wait_for_request(n=2)
        self.assert_visible("div[name='certificate-valid']")

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
        self.assert_action_list_action('revoke_cert', visible=False)
        self.assert_action_list_action('restore_cert', visible=False)

        self.assert_action_list_action('view_cert', enabled=False)
        self.assert_action_list_action('get_cert', enabled=False)

        self.navigate_by_breadcrumb('Services')
        self.delete_record(pkey, data.get('del'))

        # test HTTP, which should have cert set by default and so 'view' and 'get'
        # actions visible and enabled
        pkey = self.get_http_pkey()

        self.navigate_to_record(pkey)
        self.assert_action_list_action('view_cert')
        self.assert_action_list_action('get_cert')

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
