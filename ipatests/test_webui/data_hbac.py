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

RULE_ENTITY = 'hbacrule'
RULE_PKEY = 'itesthbacrule'
RULE_DATA = {
    'pkey': RULE_PKEY,
    'add': [
        ('textbox', 'cn', RULE_PKEY),
    ],
    'mod': [
        ('textarea', 'description', 'testhbacrulec desc'),
    ],
}

SVC_ENTITY = 'hbacsvc'
SVC_PKEY = 'itesthbacsvc'
SVC_DATA = {
    'pkey': SVC_PKEY,
    'add': [
        ('textbox', 'cn', SVC_PKEY),
        ('textarea', 'description', 'testhbacsvc desc'),
    ],
    'mod': [
        ('textarea', 'description', 'testhbacsvc desc mod'),
    ],
}

SVCGROUP_ENTITY = 'hbacsvcgroup'
SVCGROUP_DEF_FACET = 'member_hbacsvc'
SVCGROUP_PKEY = 'itesthbaccvcgroup'
SVCGROUP_DATA = {
    'pkey': SVCGROUP_PKEY,
    'add': [
        ('textbox', 'cn', SVCGROUP_PKEY),
        ('textarea', 'description', 'testhbaccvcgroup desc'),
    ],
    'mod': [
        ('textarea', 'description', 'testhbaccvcgroup desc mod'),
    ],
}
