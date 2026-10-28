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

ENTITY = 'netgroup'
PKEY = 'itest-netgroup'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textarea', 'description', 'test-netgroup desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-netgroup desc modified'),
    ],
}

PKEY2 = 'itest-netgroup2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'cn', PKEY2),
        ('textarea', 'description', 'test-netgroup2 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-netgroup2 desc modified'),
    ],
}

PKEY3 = 'itest-netgroup3'
DATA3 = {
    'pkey': PKEY3,
    'add': [
        ('textbox', 'cn', PKEY3),
        ('textarea', 'description', 'test-netgroup3 desc'),
    ]
}

PKEY4 = 'itest-netgroup4'
DATA4 = {
    'pkey': PKEY4,
    'add': [
        ('textbox', 'cn', PKEY4),
        ('textarea', 'description', 'test-netgroup4 desc'),
    ]
}

PKEY5 = 'NewNetGroup'
DATA_MIXED_CASE = {
    'pkey': PKEY5,
    'add': [
        ('textbox', 'cn', PKEY5),
        ('textarea', 'description', 'Trying to add mixed case netgroup name'),
    ]
}

PKEY6 = 'long-netgroup-name_{}'.format('long' * 15)
DATA_LONG_NAME = {
    'pkey': PKEY6,
    'add': [
        ('textbox', 'cn', PKEY6),
        ('textarea', 'description', 'Trying to add long netgroup name'),
    ]
}

PKEY7 = 'a'
DATA_SINGLE_CHAR = {
    'pkey': PKEY7,
    'add': [
        ('textbox', 'cn', PKEY7),
        ('textarea', 'description', 'Trying to add single character netgroup'
                                    ' name'),
    ]
}

PKEY8 = 'itest-netgroup8'
DATA8 = {
    'pkey': PKEY8,
    'add': [
        ('textbox', 'cn', PKEY8),
        ('textarea', 'description', 'test-netgroup8 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'description modified for testing buttons'
         ),
    ],
}
