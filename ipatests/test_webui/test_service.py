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

from ipatests.test_webui.crypto_utils import generate_certificate, generate_csr
from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest

try:
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    pass

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

    def get_service_pkey(self, service, host=None):
        if not host:
            host = self.config.get('ipa_server')
        realm = self.config.get('ipa_realm')
        pkey = '{}/{}@{}'.format(service, host, realm)
        return pkey

    def add_host(self, hostname, dns_zone, force=False):
        self.navigate_to_entity('host')
        self.facet_button_click('add')
        self.fill_textbox('hostname', hostname)
        self.fill_textbox('dnszone', dns_zone)
        if force:
            self.check_option('force', 'checked')
        self.dialog_button_click('add')

    def add_service(self, service,
                    host=None,
                    textbox=None,
                    force=False,
                    cancel=False,
                    confirm=True):

        if not host:
            host = self.config.get('ipa_server')
        self.navigate_to_entity(ENTITY)
        self.facet_button_click('add')

        self.select_combobox('service', service, combobox_input=textbox)
        self.select_combobox('host', host)
        if force:
            self.wait(0.5)
            self.check_option('force', 'checked')
        if cancel:
            self.dialog_button_click('cancel')
            return
        if not confirm:
            return
        self.dialog_button_click('add')
        self.wait(0.3)
        self.assert_no_error_dialog()

    def run_keytab_on_host(self, principal, action):
        """
        Run ipa-get/rmkeytab command on UI host in order to test whether
        we have the key un/provisioned.

        Actions:

        'get' for /usr/sbin/ipa-getkeytab
        'rm' for /usr/sbin/ipa-rmkeytab
        """

        kt_path = '/tmp/test.keytab'

        if action == 'get':
            cmd = '/usr/sbin/ipa-getkeytab -p {} -k {}'.format(principal,
                                                               kt_path)
            self.run_cmd_on_ui_host(cmd)
        elif action == 'rm':
            cmd = '/usr/sbin/ipa-rmkeytab -p {} -k {}'.format(principal,
                                                              kt_path)
            kt_rm_cmd = 'rm -f {}'.format(kt_path)
            self.run_cmd_on_ui_host(cmd)
            self.run_cmd_on_ui_host(kt_rm_cmd)
        else:
            raise ValueError("Bad action specified")


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

        Requires to have CA installed.
        """

        if not self.has_ca():
            self.skip('CA is not configured')

        self.init_app()
        data = self.prep_data()
        pkey = data.get('pkey')
        hostname = self.config.get('ipa_server')
        csr = generate_csr(hostname)
        cert_widget_sel = "div.certificate-widget"

        self.add_record(ENTITY, data)
        self.navigate_to_record(pkey)

        # cert request
        self.action_list_action('request_cert', confirm=False)
        # testing if cancel button works
        self.dialog_button_click('cancel')
        self.action_list_action('request_cert', confirm=False)
        self.assert_dialog()
        self.fill_text("textarea[name='csr'", csr)
        self.dialog_button_click('issue')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel)

        widget = self.find(cert_widget_sel, By.CSS_SELECTOR)

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

        # cert revoke/hold cancel
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '6')
        self.dialog_button_click('cancel')

        # cert revoke/hold
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '6')
        self.dialog_button_click('ok')
        self.wait_while_working(widget)

        self.assert_visible(cert_widget_sel + " div.watermark")

        # check that revoke action is not enabled
        self.assert_action_list_action('revoke', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is enabled
        self.assert_action_list_action('remove_hold',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert remove hold cancel
        self.action_list_action('remove_hold', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.dialog_button_click('cancel')

        # cert remove hold
        self.action_list_action('remove_hold', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.dialog_button_click('ok')
        self.wait_while_working(widget)

        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert revoke cancel
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '1')
        self.dialog_button_click('cancel')

        # cert revoke
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '1')
        self.dialog_button_click('ok')
        self.close_notifications()
        self.wait_while_working(widget)

        # check that revoke action is not enabled
        self.assert_action_list_action('revoke', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action not is enabled
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
        """
        self.init_app()
        data = self.prep_data()
        pkey = data.get('pkey')
        hostname = self.config.get('ipa_server')
        cert = generate_certificate(hostname)
        cert_widget_sel = "div.certificate-widget"

        self.add_record(ENTITY, data)
        self.navigate_to_record(pkey)

        # check whether certificate section is present
        self.assert_visible("div[name='certificate']")

        # add certificate
        self.button_click('add', parents_css_sel="div[name='certificate']")
        self.assert_dialog('cert-add-dialog')
        self.fill_textarea('new_cert', cert)
        self.dialog_button_click('ok')

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
        pkey = self.get_service_pkey('HTTP')
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

    @screenshot
    def test_add_remove_services(self):
        """
        Test add/remove common services on default host
        """
        self.init_app()

        services = ['cifs', 'ftp', 'imap', 'libvirt', 'nfs', 'qpidd', 'smtp']
        added_services = []

        # add services
        for service in services:
            pkey = self.get_service_pkey(service)
            self.add_service(service)
            self.wait(0.5)
            assert self.has_record(pkey)
            added_services.append(pkey)

        # delete single service
        svc_tbd = added_services.pop()
        self.delete_record(svc_tbd)
        self.assert_notification()
        assert not self.has_record(svc_tbd)

        # delete multiple services (rest of them)
        self.delete_record(added_services)
        self.assert_notification()
        for service in added_services:
            assert not self.has_record(service)

    @screenshot
    def test_add_remove_services_force(self):
        """
        Test add/remove services using force (on different host)
        """
        self.init_app()

        services = ['DNS', 'HTTP', 'ldap']
        added_services = []

        # add temp host without DNS
        temp_host = 'host-no-dns.ipa.test'
        self.add_host('host-no-dns', 'ipa.test', force=True)

        for service in services:
            pkey = self.get_service_pkey(service, host=temp_host)
            self.add_service(service, host=temp_host, force=True)
            assert self.has_record(pkey)
            added_services.append(pkey)

        # delete single service
        svc_tbd = added_services.pop()
        self.delete_record(svc_tbd)
        self.assert_notification()
        assert not self.has_record(svc_tbd)

        # delete multiple services (rest of them)
        self.delete_record(added_services)
        self.assert_notification()
        for service in added_services:
            assert not self.has_record(service)

        # host cleanup
        self.navigate_to_entity('host')
        self.delete_record(temp_host)

    @screenshot
    def test_add_custom_service(self):
        """
        Test add custom service using textbox
        """
        self.init_app()
        pkey = self.get_service_pkey('test_service')
        self.add_service('test_service', textbox='service')
        assert self.has_record(pkey)

        # service cleanup
        self.delete_record(pkey)
        self.assert_notification()
        assert not self.has_record(pkey)

    @screenshot
    def test_cancel_adding_service(self):
        """
        Test cancel when adding a service
        """
        self.init_app()
        pkey = self.get_service_pkey('cifs')
        self.add_service('cifs', cancel=True)
        assert not self.has_record(pkey)

    @screenshot
    def test_cancel_delete_service(self):
        """
        Test cancel deleting a service
        """
        self.init_app()
        pkey = self.get_service_pkey('HTTP')
        self.navigate_to_entity(ENTITY)
        self.delete_record(pkey, confirm_btn='cancel')
        assert self.has_record(pkey)

    @screenshot
    def test_cancel_add_delete_managedby_host(self):
        """
        Test cancel/add/delete managed by host
        """
        pkey = self.get_service_pkey('HTTP')
        temp_host = 'host-no-dns.ipa.test'
        self.init_app()

        # add another host for "managedby" testing
        self.add_host('host-no-dns', 'ipa.test', force=True)

        self.navigate_to_record(pkey, entity=ENTITY)
        self.add_associations([temp_host], facet='managedby_host',
                              confirm_btn='cancel')
        self.add_associations([temp_host], facet='managedby_host',
                              delete=True)

        # host cleanup
        self.navigate_to_entity('host')
        self.delete_record(temp_host)

    @screenshot
    def test_add_service_missing_hostname_field(self):
        """
        Test add service "hostname" field required
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)
        self.facet_button_click('add')
        self.select_combobox('service', 'cifs', combobox_input='service')
        self.dialog_button_click('add')
        host_elem = self.find(".widget[name='host']", By.CSS_SELECTOR)
        self.assert_field_validation_required(parent=host_elem)

    @screenshot
    def test_add_service_missing_service_field(self):
        """
        Test add service "service field required
        """
        self.init_app()
        host = self.config.get('ipa_server')
        self.navigate_to_entity(ENTITY)
        self.facet_button_click('add')
        self.select_combobox('host', host)
        self.dialog_button_click('add')
        self.wait()
        service_elem = self.find(".widget[name='service']", By.CSS_SELECTOR)
        self.assert_field_validation_required(parent=service_elem)

    @screenshot
    def test_search_services(self):
        """
        Search different services
        """
        # keywords to search (find_record accepts data dict)
        http_search = {'pkey': self.get_service_pkey('HTTP')}
        ldap_search = {'pkey': self.get_service_pkey('ldap')}
        dns_search = {'pkey': self.get_service_pkey('DNS')}
        self.init_app()
        self.navigate_to_entity(ENTITY)
        self.find_record('service', http_search)
        self.find_record('service', ldap_search)
        self.find_record('service', dns_search)

    @screenshot
    def test_dropdown(self):
        """
        Test service combobox dropdowns with UP/DOWN arrows
        """
        self.init_app()
        self.navigate_to_entity(ENTITY)
        self.facet_button_click('add')

        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ARROW_DOWN)
        # all actions are performed at once with perform()
        actions.send_keys(Keys.ARROW_DOWN).perform()
        actions.send_keys(Keys.ENTER)
        actions.send_keys(Keys.TAB)
        actions.send_keys(Keys.ARROW_DOWN)
        actions.send_keys(Keys.ARROW_DOWN)
        actions.send_keys(Keys.ENTER).perform()

        # evaluate value fields are not empty
        service_cb = "input[name='service']"
        service = self.find(service_cb, By.CSS_SELECTOR)
        assert service.get_attribute('value') != ""
        host_cb = "[name='host'].combobox-widget"
        host = self.find(host_cb, By.CSS_SELECTOR)
        assert host.get_attribute('value') != ""

    @screenshot
    def test_add_service_using_enter(self):
        """
        Add a service using enter key
        """
        self.init_app()
        pkey = self.get_service_pkey('smtp')
        self.add_service('smtp', confirm=False)
        actions = ActionChains(self.driver)
        actions.click()
        actions.send_keys(Keys.ENTER).perform()
        self.wait(1)
        assert self.has_record(pkey)

        # service cleanup
        self.delete_record(pkey)
        assert not self.has_record(pkey)

    @screenshot
    def test_delete_service_using_enter(self):
        """
        Delete a service using enter key
        """
        self.init_app()
        pkey = self.get_service_pkey('smtp')
        self.add_service('smtp')
        assert self.has_record(pkey)
        self.delete_record(pkey, confirm_btn=None)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(1)
        assert not self.has_record(pkey)

    @screenshot
    def test_provision_unprovision_keytab(self):
        """
        Test provision / unprovision keytab

        Requires to run a ipa-get/rmkeytab on UI host.
        """
        if not self.has_ca():
            self.skip('CA is not configured')

        hostname = self.config.get('ipa_server')
        csr = generate_csr(hostname)

        self.init_app()
        pkey = self.get_service_pkey('cifs')

        self.navigate_to_entity(ENTITY)

        # provision service
        self.add_service('cifs')
        self.navigate_to_record(pkey, entity=ENTITY)
        self.action_list_action('request_cert', confirm=False)
        self.assert_dialog()
        self.fill_text("textarea[name='csr'", csr)
        self.dialog_button_click('issue')
        self.run_keytab_on_host(pkey, 'get')
        self.wait(1)
        self.facet_button_click('refresh')

        # assert key present
        no_key_selector = 'div[name="kerberos-key-valid"] label'
        provisioned_assert = 'Kerberos Key Present, Service Provisioned'
        self.assert_text(no_key_selector, provisioned_assert)

        # unprovision service
        self.action_list_action('unprovision', confirm_btn='unprovision')
        self.facet_button_click('refresh')
        self.run_keytab_on_host(pkey, 'rm')

        # assert key not present
        no_key_selector = 'div[name="kerberos-key-missing"] label'
        provisioned_assert = 'Kerberos Key Not Present'
        self.assert_text(no_key_selector, provisioned_assert)

        # service cleanup
        self.navigate_to_entity(ENTITY)
        self.delete_record(pkey)
