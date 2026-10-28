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

ENTITY = 'group'
DEFAULT_FACET = 'member_user'

PKEY = 'itest-group'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textarea', 'description', 'test-group desc'),
        ('radio', 'type', 'nonposix'),
    ],
    'mod': [
        ('textarea', 'description', 'test-group desc modified'),
    ],
}

PKEY2 = 'itest-group2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'cn', PKEY2),
        ('textarea', 'description', 'test-group2 desc'),
    ]
}

PKEY3 = 'itest-group3'
DATA3 = {
    'pkey': PKEY3,
    'add': [
        ('textbox', 'cn', PKEY3),
        ('textarea', 'description', 'test-group3 desc'),
    ]
}

PKEY4 = 'itest-group4'
DATA4 = {
    'pkey': PKEY4,
    'add': [
        ('textbox', 'cn', PKEY4),
        ('textarea', 'description', 'test-group4 desc'),
    ]
}

PKEY5 = 'itest-group5'
DATA5 = {
    'pkey': PKEY5,
    'add': [
        ('textbox', 'cn', PKEY5),
        ('textarea', 'description', 'test-group5 desc'),
    ]
}

PKEY6 = 'itest-group6'
DATA6 = {
    'pkey': PKEY6,
    'add': [
        ('textbox', 'cn', PKEY6),
        ('textarea', 'description', 'test-group6 desc'),
        ('textbox', 'gidnumber', '77777'),
    ]
}

PKEY7 = ''
DATA7 = {
    'pkey': PKEY7,
    'add': [
        ('textbox', 'cn', PKEY7),
        ('textarea', 'description', 'Empty Group name'),
    ]
}

PKEY8 = ';test-gr@up'
DATA8 = {
    'pkey': PKEY8,
    'add': [
        ('textbox', 'cn', PKEY8),
        ('textarea', 'description', 'Invalid Group name'),
    ]
}

PKEY9 = 'itest-group9'
DATA9 = {
    'pkey': PKEY9,
    'add': [
        ('textbox', 'cn', PKEY9),
        ('textarea', 'description', 'test-group9 desc'),
        ('radio', 'type', 'nonposix'),
    ]
}

PKEY10 = 'itest-group10'
DATA10 = {
    'pkey': PKEY10,
    'add': [
        ('textbox', 'cn', PKEY10),
        ('textarea', 'description', 'test-group10 desc'),
        ('radio', 'type', 'nonposix'),
    ]
}

PKEY_SPECIAL_CHAR_GROUP = 'itest...group_-$'
DATA_SPECIAL_CHAR_GROUP = {
    'pkey': PKEY_SPECIAL_CHAR_GROUP,
    'add': [
        ('textbox', 'cn', PKEY_SPECIAL_CHAR_GROUP),
        ('textarea', 'description', 'special characters group desc'),
    ]
}
