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
Host tests
"""

import uuid
from random import randint

from ipatests.test_webui.crypto_utils import generate_csr
from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_hostgroup as hostgroup
import ipatests.test_webui.data_netgroup as netgroup
import ipatests.test_webui.data_hbac as hbac
import ipatests.test_webui.test_rbac as rbac
import ipatests.test_webui.data_sudo as sudo
import ipatests.test_webui.data_host as host
import pytest

try:
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
except ImportError:
    NO_SELENIUM = True

ENTITY = 'host'


@pytest.mark.tier1
class host_tasks(UI_driver):

    def setup(self, *args, **kwargs):
        super(host_tasks, self).setup(*args, **kwargs)
        self.prep_data()
        self.prep_data2()
        self.prep_data3()
        self.prep_data4()

    def prep_data(self):
        host = self.rand_host()
        domain = self.config.get('ipa_domain')
        ip = self.get_ip()
        self.data = self.get_data(host, domain, ip)
        self.pkey = self.data['pkey']
        return self.data

    def prep_data2(self):
        host = self.rand_host()
        domain = self.config.get('ipa_domain')
        self.data2 = self.get_data(host, domain)
        self.pkey2 = self.data2['pkey']
        return self.data2

    def prep_data3(self):
        host = self.rand_host()
        domain = self.config.get('ipa_domain')
        self.data3 = self.get_data(host, domain)
        self.pkey3 = self.data3['pkey']
        return self.data3

    def prep_data4(self):
        host = self.rand_host()
        domain = self.config.get('ipa_domain')
        self.data4 = self.get_data(host, domain)
        self.pkey4 = self.data4['pkey']
        return self.data4

    def get_data(self, host, domain, ip=None):
        if self.has_dns():
            add_data = [
                ('textbox', 'hostname', host),
                ('combobox', 'dnszone', domain+'.'),
            ]
            if ip:
                add_data.append(('textbox', 'ip_address', ip))
            add_data.append(('checkbox', 'force', None))
            del_data = [
                ('checkbox', 'updatedns', None)
            ]
        else:
            add_data = [
                ('textbox', 'fqdn', '%s.%s' % (host, domain)),
                ('checkbox', 'force', None),
            ]
            del_data = None

        data = {
            'pkey': '%s.%s' % (host, domain),
            'add': add_data,
            'mod': [
                ('textarea', 'description', 'Desc'),
            ],
            'del': del_data,
        }

        return data

    def get_ip(self):
        """
        Get next IP
        """
        ip = self.config.get('ipa_ip')
        if not ip:
            self.skip('FreeIPA Server IP address not configured')

        while True:
            new_ip = '10.{}.{}.{}'.format(
                randint(0, 255),
                randint(0, 255),
                randint(1, 254)
            )
            if new_ip != ip:
                break
        return new_ip

    @staticmethod
    def rand_host():
        return 'host-{}'.format(uuid.uuid4().hex[:8])

    def load_file(self, path):
        """
        Load file helper mainly for CSR load_file
        """

        with open(path, 'r') as file_d:
            content = file_d.read()
        return content


@pytest.mark.tier1
class test_host(host_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: host
        """
        self.init_app()
        self.basic_crud(ENTITY, self.data)

    @screenshot
    def test_certificates(self):
        """
        Test host certificate actions
        """

        if not self.has_ca():
            self.skip('CA is not configured')

        self.init_app()

        cert_widget_sel = "div.certificate-widget"

        self.add_record(ENTITY, self.data)
        self.navigate_to_record(self.pkey)

        # cert request
        csr = generate_csr(self.pkey)
        self.action_list_action('request_cert', confirm=False)
        self.assert_dialog()
        self.fill_text("textarea[name='csr']", csr)
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
        # check that the textarea is not empty
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
        self.delete_record(self.pkey, self.data.get('del'))

    @screenshot
    def test_arbitrary_certificates(self):
        """
        Test managing host arbitrary certificate.

        Requires to have 'arbitrary_cert_path' configuration set.
        """
        cert_path = self.config.get('arbitrary_cert_path')
        if not cert_path:
            self.skip('Arbitrary certificate file is not configured')

        self.init_app()
        cert = self.load_file(cert_path)
        self.add_record(ENTITY, self.data)

        self.navigate_to_record(self.pkey)

        # check whether certificate section is present
        self.assert_visible("div[name='certificate']")

        # add certificate
        self.button_click('add', parents_css_sel="div[name='certificate']")
        self.assert_dialog()
        self.fill_textarea('new_cert', cert)
        self.dialog_button_click('add')

        self.assert_visible("div.certificate-widget")

        # cert view
        self.action_list_action('view', confirm=False,
                                parents_css_sel="div.certificate-widget")
        self.assert_dialog()
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get', confirm=False,
                                parents_css_sel="div.certificate-widget")
        self.assert_dialog()

        # check that the textarea is not empty
        self.assert_empty_value('textarea.certificate', negative=True)
        self.dialog_button_click('close')

        # cert download - we can only try to click the download action
        self.action_list_action('download', confirm=False,
                                parents_css_sel="div.certificate-widget")

        # check that revoke action is not enabled
        self.assert_action_list_action(
            'revoke', enabled=False,
            parents_css_sel="div.certificate-widget",
            facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action(
            'remove_hold', enabled=False,
            parents_css_sel="div.certificate-widget",
            facet_actions=False)

        # cleanup
        self.navigate_to_entity(ENTITY, 'search')
        self.delete_record(self.pkey, self.data.get('del'))

    @screenshot
    def test_ca_less(self):
        """
        Test host certificate actions in CA-less install
        http://www.freeipa.org/page/V3/CA-less_install
        """
        if self.has_ca():
            self.skip('CA is installed')

        self.init_app()
        self.add_record(ENTITY, self.data)
        self.navigate_to_record(self.pkey)

        self.assert_action_list_action('request_cert', visible=False)

        self.navigate_by_breadcrumb('Hosts')
        self.delete_record(self.pkey, self.data.get('del'))

    @screenshot
    def test_kerberos_flags(self):
        """
        Test Kerberos flags
        http://www.freeipa.org/page/V3/Kerberos_Flags
        """
        name = 'ipakrbokasdelegate'
        mod = {'mod': [('checkbox', name, None)]}
        checked = ['checked']

        self.init_app()
        self.add_record(ENTITY, self.data)
        self.navigate_to_record(self.pkey)

        if self.get_field_checked(name) == checked:
            self.mod_record(ENTITY, mod)  # uncheck

        self.mod_record(ENTITY, mod)
        self.validate_fields([('checkbox', name, checked)])
        self.mod_record(ENTITY, mod)
        self.validate_fields([('checkbox', name, [])])
        self.close_notifications()
        self.delete(ENTITY, [self.data])

    @screenshot
    def test_associations(self):
        """
        Host direct associations
        """

        self.init_app()

        # prepare
        # -------
        self.add_record(ENTITY, self.data)
        self.add_record(ENTITY, self.data2, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)

        # add & remove associations
        # -------------------------
        self.navigate_to_entity(ENTITY)
        self.navigate_to_record(self.pkey)

        self.add_associations([hostgroup.PKEY], facet='memberof_hostgroup', delete=True)
        self.add_associations([netgroup.PKEY], facet='memberof_netgroup', delete=True)
        self.add_associations([rbac.ROLE_PKEY], facet='memberof_role', delete=True)
        self.add_associations([hbac.RULE_PKEY], facet='memberof_hbacrule', delete=True)
        self.add_associations([sudo.RULE_PKEY], facet='memberof_sudorule', delete=True)
        self.add_associations([self.pkey2], facet='managedby_host', delete=True)

        # cleanup
        # -------
        self.delete(ENTITY, [self.data, self.data2])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_indirect_associations(self):
        """
        Host indirect associations
        """
        self.init_app()

        # add
        # ---
        self.add_record(ENTITY, self.data)

        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.navigate_to_record(hostgroup.PKEY)
        self.add_associations([self.pkey])

        self.add_record(hostgroup.ENTITY, hostgroup.DATA2)
        self.navigate_to_record(hostgroup.PKEY2)
        self.switch_to_facet('member_hostgroup')
        self.add_associations([hostgroup.PKEY])

        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.navigate_to_record(netgroup.PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY2])

        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.navigate_to_record(rbac.ROLE_PKEY)
        self.switch_to_facet('member_hostgroup')
        self.add_associations([hostgroup.PKEY2])

        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY2])

        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)
        self.navigate_to_record(sudo.RULE_PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY2])

        # check indirect associations
        # ---------------------------
        self.navigate_to_entity(ENTITY, 'search')
        self.navigate_to_record(self.pkey)

        self.assert_indirect_record(hostgroup.PKEY2, ENTITY, 'memberof_hostgroup')
        self.assert_indirect_record(netgroup.PKEY, ENTITY, 'memberof_netgroup')
        self.assert_indirect_record(rbac.ROLE_PKEY, ENTITY, 'memberof_role')
        self.assert_indirect_record(hbac.RULE_PKEY, ENTITY, 'memberof_hbacrule')
        self.assert_indirect_record(sudo.RULE_PKEY, ENTITY, 'memberof_sudorule')

        # cleanup
        # -------
        self.delete(ENTITY, [self.data])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA, hostgroup.DATA2])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_buttons(self):
        """Test buttons"""
        self.init_app()
        self.navigate_to_entity(ENTITY)
        # add with enter key
        self.navigate_to_entity(ENTITY)
        self.button_click('add')
        self.fill_textbox("hostname", self.pkey)
        self.check_option('force')
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait_for_request(n=3)
        self.assert_record(self.pkey)

        # add and another
        self.add_record(ENTITY, [self.data2, self.data3])

        # add and edit record
        self.add_record(ENTITY, self.data4, dialog_btn='add_and_edit')
        self.assert_facet(ENTITY, facet="details")

        # cancel managedby
        self.add_associations([self.pkey3], facet='managedby_host',
                              confirm_btn="cancel")
        self.wait()
        self.select_record(self.pkey4, table_name='fqdn')
        self.button_click('remove')
        self.dialog_button_click('cancel')
        self.assert_record(self.pkey4)

        # add duplicate
        self.add_record(ENTITY, self.data2, negative=True, pre_delete=False)
        dialog_info = self.get_dialog_info()
        expected_msg = 'host with name "' + self.data2['pkey'] + \
                       '" already exist'
        if expected_msg in dialog_info['text']:
            self.dialog_button_click('cancel')
            self.dialog_button_click('cancel')
        else:
            assert False, "Duplicate dialog missing or have wrong text."

        # duplicate with pressed keys
        self.add_record(ENTITY, self.data2, negative=True, pre_delete=False)
        self.wait()
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.TAB).perform()
        self.wait()
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(2)
        self.dialog_button_click('cancel')
        self.assert_no_dialog()

        # remove multiple
        self.navigate_to_entity(ENTITY)
        self.select_multiple_records([self.data2, self.data3, self.data4])
        self.facet_button_click('remove')
        self.wait()
        self.check_option('updatedns')
        self.dialog_button_click('ok')
        self.assert_notification()
        self.close_notifications()

        # remove without updatedns
        self.select_record(self.pkey)
        self.facet_button_click('remove')
        self.dialog_button_click('ok')
        self.assert_notification()
        self.close_notifications()

    @screenshot
    def test_negative_add_input(self):
        """ Test field validations for adding """
        self.init_app()

        # wrong hostname input
        hosts_tests = [host.hostname_tilde,
                       host.hostname_trailing_space,
                       host.hostname_dash]
        for hostname_test in hosts_tests:
            self.add_record(ENTITY, hostname_test, negative=True)
            dialog_info = self.get_dialog_info()
            if host.BAD_HOSTNAME_MSG in dialog_info['text']:
                self.dialog_button_click('cancel')
                self.dialog_button_click('cancel')

        # leading space in hostname
        self.add_record(ENTITY, host.hostname_leading_space, negative=True)
        dialog_info = self.get_dialog_info()
        if host.BAS_HOSTNAME_SPACE_MSG in dialog_info['text']:
            self.dialog_button_click('cancel')
            self.dialog_button_click('cancel')

        # empty hostname
        self.add_record(ENTITY, host.empty_hostname, negative=True)
        self.assert_field_validation_required(field='hostname')
        self.dialog_button_click('cancel')

        # empty domain
        self.add_record(ENTITY, host.empty_domain, negative=True)
        self.assert_field_validation_required(field='dnszone')
        self.dialog_button_click('cancel')

        # Wrong IP input
        ip_tests = [host.ip_alpha, host.ip_many_oct,
                    host.ip_bad_oct, host.ip_special_char]
        for ip_test in ip_tests:
            self.add_record(ENTITY, ip_test, negative=True)
            self.assert_field_validation(host.BAD_IP_MSG, field='ip_address')
            self.dialog_button_click('cancel')

    @screenshot
    def test_details_input(self):
        """ Test text fields in details page """
        self.init_app()

        self.add_record(ENTITY, self.data2)
        self.navigate_to_record(self.data2['pkey'], entity=ENTITY)

        # modify
        modify_tests = [host.mod_desc, host.mod_locality,
                        host.mod_location, host.mod_platform,
                        host.mod_os]
        for mod_test in modify_tests:
            self.fill_fields(mod_test)
            self.button_click('save')
            self.assert_notification()
            self.close_notifications()

        self.fill_fields(host.mod_desc_m)
        self.click_undo_button('description')

        self.delete(ENTITY, [self.data2])

        # otp set_otp
        otp_tests = [host.otp_alpha, host.otp_num, host.otp_alphanum,
                     host.otp_special, host.otp_mixed]
        for otp_test in otp_tests:
            self.add_record(ENTITY, self.data2)
            self.close_notifications()
            self.navigate_to_record(self.data2['pkey'], entity=ENTITY)
            self.action_list_action('set_otp', confirm=False)
            self.fill_fields(otp_test)
            self.dialog_button_click('confirm')
            self.assert_notification()
            self.close_notifications()
            self.delete(ENTITY, [self.data2])
            self.close_notifications()

        # otp cancel and reset
        self.add_record(ENTITY, self.data2)
        self.navigate_to_record(self.data2['pkey'], entity=ENTITY)
        self.action_list_action('set_otp', confirm=False)
        self.assert_dialog()
        self.dialog_button_click('cancel')
        self.assert_no_dialog()
        self.navigate_to_record(self.data2['pkey'], entity=ENTITY)
        self.action_list_action('set_otp', confirm=False)
        self.fill_fields(host.otp_alpha)
        self.dialog_button_click('confirm')
        self.assert_notification()
        self.close_notifications()
        self.action_list_action('reset_otp', confirm=False)
        self.assert_dialog()
        self.dialog_button_click('cancel')
        self.assert_no_dialog()

        # cleanup
        self.delete(ENTITY, [self.data2])

    @screenshot
    def test_sshkey(self):
        """ Test ssh keys """
        self.init_app()
        self.add_record(ENTITY, self.data2)
        self.close_notifications()
        # add dsa key
        self.add_sshkey_to_record(host.ssh_dsa, self.data2['pkey'],
                                  entity=ENTITY, navigate=True)
        self.assert_notification()
        self.close_notifications()

        # delete ssh key
        self.delete_record_sshkeys(self.data2['pkey'],
                                   entity=ENTITY, navigate=True)

        # add rsa key
        self.add_sshkey_to_record(host.ssh_rsa, self.data2['pkey'],
                                  entity=ENTITY, navigate=True)
        self.assert_notification()
        self.close_notifications()

        # negative ssh key input
        neg_key_tests = [host.ssh_empty, host.ssh_rsa]
        for key in neg_key_tests:
            self.add_sshkey_to_record(key, self.data2['pkey'],
                                      entity=ENTITY, navigate=True)
            self.assert_dialog()
            dialog_info = self.get_dialog_info()
            if host.ssh_nomod_error in dialog_info['text']:
                self.dialog_button_click('cancel')

        # invalid ssh key
        self.add_sshkey_to_record(host.ssh_invalid, self.data2['pkey'],
                                  entity=ENTITY, navigate=True)
        self.assert_dialog()
        dialog_info = self.get_dialog_info()
        if host.ssh_invalid_error in dialog_info['text']:
            self.dialog_button_click('cancel')

        # undo all and delete ssh keys
        self.undo_ssh_keys(btn_name='undo_all')
        self.delete_record_sshkeys(self.data2['pkey'],
                                   entity=ENTITY)

        # undo
        self.add_sshkey_to_record(host.ssh_rsa, self.data2['pkey'],
                                  entity=ENTITY, navigate=True, save=False)
        self.undo_ssh_keys()

        # refresh
        self.add_sshkey_to_record(host.ssh_rsa, self.data2['pkey'],
                                  entity=ENTITY, navigate=True, save=False)
        self.facet_button_click('refresh')
        self.assert_num_ssh_keys(0)

        # revert
        self.add_sshkey_to_record(host.ssh_rsa, self.data2['pkey'],
                                  entity=ENTITY, navigate=True, save=False)
        self.facet_button_click('revert')
        self.assert_num_ssh_keys(0)

        # cleanup
        self.delete(ENTITY, [self.data2])

    @screenshot
    def test_negative_cert(self):
        """ Test negative CSR """
        self.init_app()
        self.add_record(ENTITY, self.data2)
        self.close_notifications()
        self.navigate_to_record(self.data2['pkey'], entity=ENTITY)

        # emtpy CSR
        csr_add = 'div[name="certificate"] button[name="add"]'
        csr_add_btn = self.find(csr_add, By.CSS_SELECTOR, strict=True)
        csr_add_btn.click()
        self.wait()
        self.dialog_button_click('ok')
        self.assert_field_validation_required()
        self.dialog_button_click('cancel')

        # invalid CSR
        csr_add = 'div[name="certificate"] button[name="add"]'
        csr_add_btn = self.find(csr_add, By.CSS_SELECTOR, strict=True)
        csr_add_btn.click()
        self.wait()
        self.fill_textarea('new_cert', host.csr_invalid)
        self.dialog_button_click('ok')
        dialog_info = self.get_dialog_info()
        self.wait()
        if host.csr_invalid_error in dialog_info['text']:
            self.dialog_button_click('cancel')
            self.dialog_button_click('cancel')

        # other hostname CSR
        self.action_list_action('request_cert', confirm=False)
        self.assert_dialog()
        self.fill_text("textarea[name='csr']", host.csr_other_host)
        self.dialog_button_click('issue')
        dialog_info = self.get_dialog_info()
        if host.csr_other_host_error in dialog_info['text']:
            self.dialog_button_click('cancel')
            self.dialog_button_click('cancel')

        # cleanup
        self.delete(ENTITY, [self.data2])

    @screenshot
    def test_keytab(self):
        """ Test keytab """
        self.init_app()
        self.add_record(ENTITY, self.data2)
        # provision keytab
        kt_tmp = '/tmp/test.keytab'
        hostname = self.data2['pkey']
        realm = self.config.get('ipa_realm')
        principal = 'host/{}@{}'.format(hostname, realm)
        self.run_cmd_on_ui_host('/usr/sbin/ipa-getkeytab '
                                '-p {} '
                                '-k {} '.format(principal, kt_tmp))
        self.navigate_to_record(hostname, entity=ENTITY)
        self.wait(3)
        enroll = 'div[name="has_keytab"] label[name="present"]'
        self.assert_text(enroll, host.krb_enrolled)
        # test cancel button exist
        self.action_list_action('unprovision', confirm=False)
        self.dialog_button_click('cancel')
        # unprovision keytab
        self.action_list_action('unprovision', confirm=False)
        self.dialog_button_click('unprovision')
        self.wait_for_request(n=4)
        self.facet_button_click('refresh')
        enroll = 'div[name="has_keytab"] label[name="missing"]'
        self.assert_text(enroll, host.krb_not_enrolled)
        # cleanup
        self.delete(ENTITY, [self.data2])

    def test_search(self):
        self.init_app()
        self.navigate_to_entity(ENTITY)
        self.add_record(ENTITY, [self.data2, self.data3])
        # positive search filter
        self.fill_search_filter(self.pkey2)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.assert_record(self.pkey2)
        # negative search filter
        self.fill_search_filter(self.pkey3)
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.assert_record(self.pkey4, negative=True)
        # cleanup
        self.fill_search_filter('')
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.ENTER).perform()
        self.wait(0.5)
        self.delete_record([self.pkey2, self.pkey3])
