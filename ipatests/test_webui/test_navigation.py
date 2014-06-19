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

        # don't start by users (default)
        self.navigate_by_menu('identity/group', False)
        self.navigate_by_menu('identity/user', False)
        self.navigate_by_menu('identity/host', False)
        self.navigate_by_menu('identity/hostgroup', False)
        self.navigate_by_menu('identity/netgroup', False)
        self.navigate_by_menu('identity/service', False)
        if self.has_dns():
            self.navigate_by_menu('identity/dns/dnsconfig', True)
            self.navigate_by_menu('identity/dns', False)
            self.navigate_by_menu('identity/dns/dnszone', False)
            self.navigate_by_menu('identity/dns/dnsforwardzone')
        else:
            self.assert_menu_item('identity/dns', False)
        if self.has_ca():
            self.navigate_by_menu('identity/cert', False)
        else:
            self.assert_menu_item('identity/cert', False)
        self.navigate_by_menu('identity/realmdomains', False)
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
        self.navigate_by_menu('policy/automount', False)
        self.navigate_by_menu('policy/pwpolicy', False)
        self.navigate_by_menu('policy/krbtpolicy', False)
        self.navigate_by_menu('policy/selinuxusermap', False)
        self.navigate_by_menu('policy/automember', False)
        self.navigate_by_menu('policy/automember/amhostgroup')
        self.navigate_by_menu('policy/automember/amgroup')
        self.navigate_by_menu('ipaserver')
        self.navigate_by_menu('ipaserver/rolebased', False)
        self.navigate_by_menu('ipaserver/rolebased/privilege', False)
        self.navigate_by_menu('ipaserver/rolebased/role')
        self.navigate_by_menu('ipaserver/rolebased/permission')
        self.navigate_by_menu('ipaserver/selfservice', False)
        self.navigate_by_menu('ipaserver/delegation', False)
        self.navigate_by_menu('ipaserver/idrange', False)
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
