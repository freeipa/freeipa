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

RULE_ENTITY = 'sudorule'
CMDENTITY = 'sudocmd'
CMDGROUP_ENTITY = 'sudocmdgroup'
CMDGROUP_DEF_FACET = 'member_sudocmd'

RULE_PKEY = 'itestsudorule'
RULE_DATA = {
    'pkey': RULE_PKEY,
    'add': [
        ('textbox', 'cn', RULE_PKEY),
    ],
    'mod': [
        ('textarea', 'description', 'itestsudorule desc'),
    ],
}

CMD_PKEY = 'itestsudocmd'
CMD_DATA = {
    'pkey': CMD_PKEY,
    'add': [
        ('textbox', 'sudocmd', CMD_PKEY),
        ('textarea', 'description', 'itestsudocmd desc'),
    ],
    'mod': [
        ('textarea', 'description', 'itestsudocmd desc mod'),
    ],
}

CMD_PKEY2 = 'itestsudocmd2'
CMD_DATA2 = {
    'pkey': CMD_PKEY2,
    'add': [
        ('textbox', 'sudocmd', CMD_PKEY2),
        ('textarea', 'description', 'itestsudocmd2 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'itestsudocmd2 desc mod'),
    ],
}

CMD_GROUP_PKEY = 'itestsudocmdgroup'
CMDGROUP_DATA = {
    'pkey': CMD_GROUP_PKEY,
    'add': [
        ('textbox', 'cn', CMD_GROUP_PKEY),
        ('textarea', 'description', 'itestsudocmdgroup desc'),
    ],
    'mod': [
        ('textarea', 'description', 'itestsudocmdgroup desc mod'),
    ],
}

CMD_GROUP_PKEY2 = 'itestsudocmdgroup2'
CMDGROUP_DATA2 = {
    'pkey': CMD_GROUP_PKEY2,
    'add': [
        ('textbox', 'cn', CMD_GROUP_PKEY2),
        ('textarea', 'description', 'itestsudocmdgroup2 desc'),
    ],
    'mod': [
        ('textarea', 'description', 'itestsudocmdgroup2 desc mod'),
    ],
}
