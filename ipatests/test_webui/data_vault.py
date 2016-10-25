# Authors:
#   Pavel Vomacka <pvomacka@redhat.com>
#
# Copyright (C) 2016  Red Hat
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

ENTITY = 'vault'

PKEY = 'itest-user-vault'
DATA = {
    'pkey': PKEY,
    'facet': 'user_search',
    'add': [
        ('radio', 'type', 'user'),
        ('textbox', 'cn', PKEY),
        ('textbox', 'description', 'test-desc')
    ],
    'mod': [
        ('textbox', 'description', 'test-desc-mod'),
    ],
}

PKEY2 = 'itest-service-vault'
DATA2 = {
    'pkey': PKEY2,
    'facet': 'service_search',
    'add': [
        ('radio', 'type', 'service'),
        # service
        ('textbox', 'cn', PKEY2),
        ('textbox', 'description', 'test-desc')
    ],
    'mod': [
        ('textbox', 'description', 'test-desc-mod'),
    ],
}

PKEY3 = 'itest-shared-vault'
DATA3 = {
    'pkey': PKEY3,
    'facet': 'shared_search',
    'add': [
        ('radio', 'type', 'shared'),
        ('textbox', 'cn', PKEY3),
        ('textbox', 'description', 'test-desc')
    ],
    'mod': [
        ('textbox', 'description', 'test-desc-mod'),
    ],
}
