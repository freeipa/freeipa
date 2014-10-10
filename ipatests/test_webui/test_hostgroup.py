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
Hostgroup tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_hostgroup as hostgroup
from ipatests.test_webui.test_host import host_tasks, ENTITY as HOST_ENTITY
import ipatests.test_webui.data_netgroup as netgroup
import ipatests.test_webui.data_hbac as hbac
import ipatests.test_webui.test_rbac as rbac
import ipatests.test_webui.data_sudo as sudo


class test_hostgroup(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: hostgroup
        """
        self.init_app()
        self.basic_crud(hostgroup.ENTITY, hostgroup.DATA,
                        default_facet=hostgroup.DEFAULT_FACET)

    @screenshot
    def test_associations(self):
        """
        Hostgroup associations
        """
        self.init_app()
        host = host_tasks()
        host.setup(self.driver, self.config)

        # prepare
        # -------
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA2, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA3, navigate=False)
        self.add_record(HOST_ENTITY, host.data2)
        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)

        # add & remove associations
        # -------------------------
        self.navigate_to_entity(hostgroup.ENTITY)
        self.navigate_to_record(hostgroup.PKEY)

        # members
        self.add_associations([hostgroup.PKEY2], facet='member_hostgroup', delete=True)
        self.add_associations([host.pkey2], facet='member_host', delete=True)

        # member of
        self.add_associations([hostgroup.PKEY3], facet='memberof_hostgroup', delete=True)
        self.add_associations([netgroup.PKEY], facet='memberof_netgroup', delete=True)
        self.add_associations([hbac.RULE_PKEY], facet='memberof_hbacrule', delete=True)
        self.add_associations([sudo.RULE_PKEY], facet='memberof_sudorule', delete=True)

        # cleanup
        # -------
        self.delete(hostgroup.ENTITY, [hostgroup.DATA, hostgroup.DATA2, hostgroup.DATA3])
        self.delete(HOST_ENTITY, [host.data2])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_indirect_associations(self):
        """
        Hostgroup indirect associations
        """
        self.init_app()
        host = host_tasks()
        host.setup(self.driver, self.config)

        # add
        # ---
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA2, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA3, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA4, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA5, navigate=False)
        self.add_record(HOST_ENTITY, host.data2)

        # prepare indirect member
        self.navigate_to_entity(hostgroup.ENTITY, 'search')
        self.navigate_to_record(hostgroup.PKEY2)
        self.add_associations([host.pkey2])
        self.add_associations([hostgroup.PKEY3], 'member_hostgroup')

        self.navigate_to_entity(hostgroup.ENTITY, 'search')
        self.navigate_to_record(hostgroup.PKEY)
        self.add_associations([hostgroup.PKEY2], 'member_hostgroup')

        # prepare indirect memberof
        self.navigate_to_entity(hostgroup.ENTITY, 'search')
        self.navigate_to_record(hostgroup.PKEY4)
        self.add_associations([hostgroup.PKEY], 'member_hostgroup')
        self.add_associations([hostgroup.PKEY5], 'memberof_hostgroup')

        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY4])

        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)
        self.navigate_to_record(sudo.RULE_PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY4])

        # check indirect associations
        # ---------------------------
        self.navigate_to_entity(hostgroup.ENTITY, 'search')
        self.navigate_to_record(hostgroup.PKEY)

        self.assert_indirect_record(hostgroup.PKEY3, hostgroup.ENTITY, 'member_hostgroup')
        self.assert_indirect_record(host.pkey2, hostgroup.ENTITY, 'member_host')

        self.assert_indirect_record(hostgroup.PKEY5, hostgroup.ENTITY, 'memberof_hostgroup')
        self.assert_indirect_record(hbac.RULE_PKEY, hostgroup.ENTITY, 'memberof_hbacrule')
        self.assert_indirect_record(sudo.RULE_PKEY, hostgroup.ENTITY, 'memberof_sudorule')

        ## cleanup
        ## -------
        self.delete(hostgroup.ENTITY, [hostgroup.DATA, hostgroup.DATA2,
                                       hostgroup.DATA3, hostgroup.DATA4, hostgroup.DATA5])
        self.delete(HOST_ENTITY, [host.data2])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])
