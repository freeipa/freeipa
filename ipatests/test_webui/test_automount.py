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

DIRECT_MAPS = [
    {
        'pkey': 'map1',
        'add': [
            ('radio', 'method', 'add'),
            ('textbox', 'automountmapname', 'map1'),
            ('textarea', 'description', 'foobar'),
        ],
    },
    {
        'pkey': 'map2',
        'add': [
            ('radio', 'method', 'add'),
            ('textbox', 'automountmapname', 'map2'),
            ('textarea', 'description', 'foobar'),
        ],
    },
    {
        'pkey': 'map3',
        'add': [
            ('radio', 'method', 'add'),
            ('textbox', 'automountmapname', 'map3'),
            ('textarea', 'description', 'foobar'),
        ],
    },
    {
        'pkey': 'map4',
        'add': [
            ('radio', 'method', 'add'),
            ('textbox', 'automountmapname', 'map4'),
            ('textarea', 'description', 'foobar'),
        ],
    },
]

INDIRECT_MAPS = [
    {
        'pkey': 'map1',
        'add': [
            ('radio', 'method', 'add'),
            ('textbox', 'automountmapname', 'map1'),
            ('textarea', 'description', 'foobar'),
        ],
    },
    {
        'pkey': 'map2',
        'add': [
            ('radio', 'method', 'add_indirect'),
            ('textbox', 'automountmapname', 'map2'),
            ('textarea', 'description', 'foobar'),
            ('textbox', 'key', 'mount1'),
            ('textbox', 'parentmap', 'map1'),
        ],
    },
    {
        'pkey': 'map3',
        'add': [
            ('radio', 'method', 'add_indirect'),
            ('textbox', 'automountmapname', 'map3'),
            ('textarea', 'description', 'foobar'),
            ('textbox', 'key', 'mount2'),
            ('textbox', 'parentmap', 'map1'),
        ],
    },
    {
        'pkey': 'map4',
        'add': [
            ('radio', 'method', 'add_indirect'),
            ('textbox', 'automountmapname', 'map4'),
            ('textarea', 'description', 'foobar'),
            ('textbox', 'key', 'mount3'),
            ('textbox', 'parentmap', 'map1'),
        ],
    },
]


@pytest.mark.tier1
class TestAutomount(UI_driver):

    def setup(self):
        super().setup()
        self.init_app()

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

    def test_add_location_dialog(self):
        """
        Test 'Add Automount Location' dialog behaviour
        """

        pkeys = ['loc1', 'loc2', 'loc3', 'loc4']
        locations = [{
            'pkey': pkey,
            'add': [('textbox', 'cn', pkey)]
        } for pkey in pkeys]

        self.navigate_to_entity(LOC_ENTITY)

        # Add and add another
        self.add_record(LOC_ENTITY, [locations[0], locations[1]],
                        navigate=False)
        self.assert_record(locations[0]['pkey'])
        self.assert_record(locations[1]['pkey'])

        # Add and edit
        self.add_record(LOC_ENTITY, locations[2], dialog_btn='add_and_edit',
                        navigate=False)
        self.assert_facet(LOC_ENTITY, facet='maps')

        # Cancel dialog
        self.add_record(LOC_ENTITY, locations[3], dialog_btn='cancel')
        self.assert_record(locations[3]['pkey'], negative=True)

        self.delete_record(pkeys)

    @pytest.mark.parametrize('maps', [DIRECT_MAPS, INDIRECT_MAPS])
    def test_add_map_dialog(self, maps):
        """
        Test 'Add Automount Map' dialog behaviour
        """

        self.add_record(LOC_ENTITY, LOC_DATA)
        self.navigate_to_record(LOC_PKEY)

        # Add and add another
        self.add_record(LOC_ENTITY, [maps[0], maps[1]],
                        facet='maps', navigate=False)
        self.assert_record(maps[0]['pkey'])
        self.assert_record(maps[1]['pkey'])

        # Add and edit
        self.add_record(LOC_ENTITY, maps[2], dialog_btn='add_and_edit',
                        facet='maps', navigate=False)
        self.assert_facet(MAP_ENTITY, facet='keys')

        # Cancel dialog
        self.add_record(LOC_ENTITY, maps[3], facet='maps', dialog_btn='cancel')
        self.assert_record(maps[3]['pkey'], negative=True)

        self.delete_record(LOC_PKEY)

    def test_add_key_dialog(self):
        """
        Test 'Add Automount Key' dialog behaviour
        """

        pkeys = ['key1', 'key2', 'key3', 'key4']

        keys = [
            {
                'pkey': pkey,
                'add': [
                    ('textbox', 'automountkey', pkey),
                    ('textbox', 'automountinformation', '/itest/%s' % pkey),
                ],
            } for pkey in pkeys
        ]

        self.add_record(LOC_ENTITY, LOC_DATA)
        self.navigate_to_record(LOC_PKEY)
        self.add_record(LOC_ENTITY, MAP_DATA, facet='maps', navigate=False)
        self.navigate_to_record(MAP_PKEY)

        # Add and add another
        self.add_record(MAP_ENTITY, [keys[0], keys[1]],
                        facet='keys', navigate=False)
        self.assert_record(keys[0]['pkey'])
        self.assert_record(keys[1]['pkey'])

        # Add and edit
        self.add_record(MAP_ENTITY, keys[2], dialog_btn='add_and_edit',
                        facet='keys', navigate=False)
        self.assert_facet(KEY_ENTITY, facet='details')

        # Cancel dialog
        self.add_record(MAP_ENTITY, keys[3], facet='keys', dialog_btn='cancel')
        self.assert_record(keys[3]['pkey'], negative=True)

        self.delete_record(LOC_PKEY)
