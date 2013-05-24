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
Automember tests
"""

from ipatests.test_webui.ui_driver import UI_driver
import ipatests.test_webui.data_hostgroup as hostgroup

ENTITY = 'automember'

USER_GROUP_PKEY = 'admins'
USER_GROUP_DATA = {
    'pkey': USER_GROUP_PKEY,
    'add': [
        ('combobox', 'cn', USER_GROUP_PKEY),
    ],
    'mod': [
        ('textarea', 'description', 'user group rule description'),
        #(
            #'add_table_record',
            #'automemberinclusiveregex',
            #(
                #'table-widget',
                #{
                    #'fields': [
                        #('textbox', 'automemberinclusiveregex', 'testregex')
                    #]
                #},
            #)
        #)
    ],
}

HOST_GROUP_DATA = {
    'pkey': hostgroup.PKEY,
    'add': [
        ('combobox', 'cn', hostgroup.PKEY),
    ],
    'mod': [
        ('textarea', 'description', 'host group rule description'),
    ],
}

class test_automember(UI_driver):

    def test_crud(self):
        """
        Basic CRUD: automember
        """
        self.init_app()

        # user group rule
        self.basic_crud(ENTITY, USER_GROUP_DATA,
            search_facet='searchgroup',
            default_facet='usergrouprule',
            details_facet='usergrouprule',
        )

        # prepare host group
        self.basic_crud(hostgroup.ENTITY, hostgroup.DATA,
                        default_facet=hostgroup.DEFAULT_FACET,
                        delete=False)

        # host group rule
        self.navigate_by_menu('policy/automember/amhostgroup')

        self.basic_crud(ENTITY, HOST_GROUP_DATA,
            search_facet='searchhostgroup',
            default_facet='hostgrouprule',
            details_facet='hostgrouprule',
            navigate=False,
            breadcrumb='Host group rules',
        )

        # cleanup
        self.delete(hostgroup.ENTITY, [hostgroup.DATA])
