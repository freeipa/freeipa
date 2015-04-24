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
Automount tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import pytest

LOC_ENTITY = 'automountlocation'
MAP_ENTITY = 'automountmap'
KEY_ENTITY = 'automountkey'

LOC_PKEY = 'itestloc'
LOC_DATA = {
    'pkey': LOC_PKEY,
    'add': [
        ('textbox', 'cn', LOC_PKEY),
    ],
}

MAP_PKEY = 'itestmap'
MAP_DATA = {
    'pkey': MAP_PKEY,
    'add': [
        ('textbox', 'automountmapname', MAP_PKEY),
        ('textarea', 'description', 'map desc'),
    ],
    'mod': [
        ('textarea', 'description', 'map desc mod'),
    ]
}

KEY_PKEY = 'itestkey'
KEY_DATA = {
    'pkey': KEY_PKEY,
    'add': [
        ('textbox', 'automountkey', KEY_PKEY),
        ('textbox', 'automountinformation', '/itest/key'),
    ],
    'mod': [
        ('textbox', 'automountinformation', '/itest/key2'),
    ]
}


@pytest.mark.tier1
class test_automount(UI_driver):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: automount
        """
        self.init_app()

        # location
        self.basic_crud(LOC_ENTITY, LOC_DATA,
                        default_facet='maps',
                        delete=False,
                        breadcrumb='Automount Locations'
                        )

        # map
        self.navigate_to_record(LOC_PKEY)

        self.basic_crud(MAP_ENTITY, MAP_DATA,
                        parent_entity=LOC_ENTITY,
                        search_facet='maps',
                        default_facet='keys',
                        delete=False,
                        navigate=False,
                        breadcrumb=LOC_PKEY,
                        )

        # key
        self.navigate_to_record(MAP_PKEY)

        self.basic_crud(KEY_ENTITY, KEY_DATA,
                        parent_entity=MAP_ENTITY,
                        search_facet='keys',
                        navigate=False,
                        breadcrumb=MAP_PKEY,
                        )

        # delete
        self.navigate_by_breadcrumb(LOC_PKEY)
        self.delete_record(MAP_PKEY)

        ## test indirect maps
        direct_pkey = 'itest-direct'
        indirect_pkey = 'itest-indirect'

        self.add_record(LOC_ENTITY,
                        {
                            'pkey': direct_pkey,
                            'add': [
                                ('radio', 'method', 'add'),
                                ('textbox', 'automountmapname', direct_pkey),
                                ('textarea', 'description', 'foobar'),
                            ],
                        },
                        facet='maps',
                        navigate=False)

        self.add_record(LOC_ENTITY,
                        {
                            'pkey': indirect_pkey,
                            'add': [
                                ('radio', 'method', 'add_indirect'),
                                ('textbox', 'automountmapname', indirect_pkey),
                                ('textarea', 'description', 'foobar'),
                                ('textbox', 'key', 'baz'),
                                ('textbox', 'parentmap', direct_pkey),
                            ],
                        },
                        facet='maps',
                        navigate=False)

        self.assert_record(direct_pkey)
        self.assert_record(indirect_pkey)

        # delete
        self.delete_record(direct_pkey)
        self.delete_record(indirect_pkey)
        self.navigate_by_breadcrumb('Automount Locations')
        self.delete_record(LOC_PKEY)
