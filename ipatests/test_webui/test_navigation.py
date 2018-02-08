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
Basic ui tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest


ENTITIES = [
    'group',
    'user',
    'host',
    'hostgroup',
    'netgroup',
    'service',
    'dnszone',
    'dnsforwardzone',
    # TODO: dnsrecord
    'dnsconfig',
    'cert',
    'otptoken',
    'radiusproxy',
    'realmdomains',
    'hbacrule',
    'hbacsvc',
    'hbacsvcgroup',
    'hbactest',
    'sudorule',
    'sudocmd',
    'sudocmdgroup',
    'automountlocation',
    # TODO: add nested maps, keys
    'pwpolicy',
    'krbtpolicy',
    'selinuxusermap',
    'automember',
    # TODO: add different types
    'role',
    'privilege',
    'permission',
    'selfservice',
    'delegation',
    'idrange',
    'config',
    # TODO: add conditional
]


@pytest.mark.tier1
class test_navigation(UI_driver):

    @screenshot
    def test_url_navigation(self):
        """
        Navigation test: direct url change
        """

        self.init_app()

        unsupported = []
        if not self.has_dns():
            unsupported.extend([
                               'dnszone',
                               'dnsforwardzone',
                               'dnsconfig',
                               ])
        if not self.has_ca():
            unsupported.append('cert')

        entities = [e for e in ENTITIES if e not in unsupported]

        for e in entities:
            self.wait_for_request()
            self.navigate_to_entity(e)
            self.assert_facet(e)
            url = self.get_url(e)
            self.assert_e_url(url, e)

    @screenshot
    def test_menu_navigation(self):
        """
        Navigation test: menu items
        """

        self.init_app()

        # Identity
        # don't start by users (default)
        self.navigate_by_menu('identity/group_search', False)
        # navigate on the side bar
        self.click_on_link('User Groups')
        self.click_on_link('Host Groups')
        self.navigate_by_menu('identity/user_search', False)
        self.navigate_by_menu('identity/host', False)
        self.navigate_by_menu('identity/service', False)
        self.navigate_by_menu('identity/idview', False)
        self.navigate_by_menu('identity/automember', False)
        self.navigate_by_menu('identity/automember/amhostgroup')
        self.navigate_by_menu('identity/automember/amgroup')

        # Policy
        self.navigate_by_menu('policy')
        self.navigate_by_menu('policy/hbac', False)
        self.navigate_by_menu('policy/hbac/hbacsvc', False)
        self.navigate_by_menu('policy/hbac/hbacrule')
        self.navigate_by_menu('policy/hbac/hbacsvcgroup')
        self.navigate_by_menu('policy/hbac/hbactest')
        self.navigate_by_menu('policy/sudo', False)
        self.navigate_by_menu('policy/sudo/sudorule', False)
        self.navigate_by_menu('policy/sudo/sudocmd')
        self.navigate_by_menu('policy/sudo/sudocmdgroup')
        self.navigate_by_menu('policy/selinuxusermap', False)
        self.navigate_by_menu('policy/pwpolicy', False)
        self.navigate_by_menu('policy/krbtpolicy', False)

        # Authentication
        self.navigate_by_menu('authentication')
        self.navigate_by_menu('authentication/radiusproxy', False)
        self.navigate_by_menu('authentication/otptoken', False)
        if self.has_ca():
            self.navigate_by_menu('authentication/cert_search', False)
        else:
            self.assert_menu_item('authentication/cert_search', False)

        # Network Services
        self.navigate_by_menu('network_services')
        self.navigate_by_menu('network_services/automount')
        if self.has_dns():
            self.navigate_by_menu('network_services/dns/dnsconfig', True)
            self.navigate_by_menu('network_services/dns', False)
            self.navigate_by_menu('network_services/dns/dnszone', False)
            self.navigate_by_menu('network_services/dns/dnsforwardzone')
        else:
            self.assert_menu_item('network_services/dns', False)

        # IPA Server
        self.navigate_by_menu('ipaserver')
        self.navigate_by_menu('ipaserver/rbac', False)
        self.navigate_by_menu('ipaserver/rbac/privilege', False)
        self.navigate_by_menu('ipaserver/rbac/role')
        self.navigate_by_menu('ipaserver/rbac/permission')
        self.navigate_by_menu('ipaserver/rbac/selfservice')
        self.navigate_by_menu('ipaserver/rbac/delegation')
        self.navigate_by_menu('ipaserver/idrange', False)
        self.navigate_by_menu('ipaserver/realmdomains', False)
        if self.has_trusts():
            self.navigate_by_menu('ipaserver/trusts', False)
            self.navigate_by_menu('ipaserver/trusts/trust', False)
            self.navigate_by_menu('ipaserver/trusts/trustconfig')
        else:
            self.assert_menu_item('ipaserver/trusts', False)
        self.navigate_by_menu('ipaserver/config', False)


    def assert_e_url(self, url, e):
        """
        Assert correct url for entity
        """
        if not self.driver.current_url.startswith(url):
            msg = 'Invalid url for: %s' % e
            raise AssertionError(msg)
