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

ENTITY = 'hostgroup'
DEFAULT_FACET = 'member_host'

LEADING_SPACE = ' leading-space'
TRAILING_SPACE = 'trailign-space '
NAME_SPACE = 'name space'

CHAR_WARNING_MSG = "may only include letters, numbers, _, -, and ."
EMPTY_WARNING_MSG = "Required field"
DUPLICATE_WARNING_MSG = 'already exists'
DESCRIPTION_ERROR_DIALOG = 'Leading and trailing spaces are not allowed'

PKEY = 'itest-hostgroup'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textarea', 'description', 'test-hostgroup desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-hostgroup desc modified'),
    ],
}

PKEY2 = 'itest-hostgroup2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'cn', PKEY2),
        ('textarea', 'description', 'test-hostgroup2 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-hostgroup2 desc modified'),
    ],
}

PKEY3 = 'itest-hostgroup3'
DATA3 = {
    'pkey': PKEY3,
    'add': [
        ('textbox', 'cn', PKEY3),
        ('textarea', 'description', 'test-hostgroup3 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-hostgroup3 desc modified'),
    ],
}

PKEY4 = 'itest-hostgroup4'
DATA4 = {
    'pkey': PKEY4,
    'add': [
        ('textbox', 'cn', PKEY4),
        ('textarea', 'description', 'test-hostgroup4 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-hostgroup4 desc modified'),
    ],
}

PKEY5 = 'itest-hostgroup5'
DATA5 = {
    'pkey': PKEY5,
    'add': [
        ('textbox', 'cn', PKEY5),
        ('textarea', 'description', 'test-hostgroup5 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'test-hostgroup5 desc modified'),
    ],
}

PKEY6 = 'ITEST-HOSTGROUP6'
DATA6 = {
    'pkey': PKEY6,
    'add': [
        ('textbox', 'cn', PKEY6),
        ('textarea', 'description', 'TEST-HOSTGROUP6 DESC'),
    ],
}

PKEY7 = 'Itest-hostGROUP7'
DATA7 = {
    'pkey': PKEY7,
    'add': [
        ('textbox', 'cn', PKEY7),
        ('textarea', 'description', 'TesT-HosTGroUP7 DESC'),
    ],
}

PKEY8 = 16 * 'long-name-hostgroup8'
DKEY8 = 16 * 'long hostgroup description'
DATA8 = {
    'pkey': PKEY8,
    'add': [
        ('textbox', 'cn', PKEY8),
        ('textarea', 'description', DKEY8),
    ],
}
