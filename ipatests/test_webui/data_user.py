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


ENTITY = 'user'

PKEY = 'itest-user'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'uid', PKEY),
        ('textbox', 'givenname', 'Name'),
        ('textbox', 'sn', 'Surname'),
    ],
    'add_v': [
        ('textbox', 'givenname', 'Name'),
        ('textbox', 'sn', 'Surname'),
        ('label', 'uid', PKEY),
    ],
    'mod': [
        ('textbox', 'givenname', 'OtherName'),
        ('textbox', 'sn', 'OtherSurname'),
        ('multivalued', 'telephonenumber', [
            ('add', '123456789'),
            ('add', '987654321'),
        ]),
        ('combobox', 'manager', 'admin'),
    ],
    'mod_v': [
        ('textbox', 'givenname', 'OtherName'),
        ('textbox', 'sn', 'OtherSurname'),
        ('multivalued', 'telephonenumber', ['123456789', '987654321']),
        ('combobox', 'manager', 'admin'),
    ],
}

PKEY2 = 'itest-user2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'uid', PKEY2),
        ('textbox', 'givenname', 'Name2'),
        ('textbox', 'sn', 'Surname2'),
    ],
    'mod': [
        ('textbox', 'givenname', 'OtherName2'),
        ('textbox', 'sn', 'OtherSurname2'),
    ],
}
