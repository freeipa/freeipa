# Authors:
#   Richard Kalinec <rkalinec@gmail.com>
#
# Copyright (C) 2020  Red Hat
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


ENTITY = 'apppw'

PKEY = '10'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'uid', PKEY),
        ('textbox', 'description', 'My eMail app password for tablet'),
        ('textbox', 'ou', 'eMail'),
    ],
    'add_v': [
        ('textbox', 'description', 'My eMail app password for tablet'),
        ('textbox', 'ou', 'eMail'),
        ('label', 'uid', PKEY),
    ],
}

PKEY2 = '11'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'uid', PKEY2),
        ('textbox', 'description', 'My Slack app password for smartphone'),
        ('textbox', 'ou', 'Slack'),
    ],
}

PKEY_UID_TOO_HIGH = '527'
DATA_UID_TOO_HIGH = {
    'pkey': PKEY_UID_TOO_HIGH,
    'add': [
        ('textbox', 'uid', PKEY_UID_TOO_HIGH),
        ('textbox', 'description', 'My special app password'),
        ('textbox', 'ou', 'all'),
    ]
}

PKEY_UID_WITH_LOWERCASE_AND_TOO_LONG = '6m2'
DATA_UID_WITH_LOWERCASE_AND_TOO_LONG = {
    'pkey': PKEY_UID_WITH_LOWERCASE_AND_TOO_LONG,
    'add': [
        ('textbox', 'uid', PKEY_UID_WITH_LOWERCASE_AND_TOO_LONG),
        ('textbox', 'description', 'My special app password'),
        ('textbox', 'ou', 'all'),
    ]
}

PKEY_UID_WITH_UPPERCASE = '1D'
DATA_UID_WITH_UPPERCASE = {
    'pkey': PKEY_UID_WITH_UPPERCASE,
    'add': [
        ('textbox', 'uid', PKEY_UID_WITH_UPPERCASE),
        ('textbox', 'description', 'My special app password'),
        ('textbox', 'ou', 'all'),
    ]
}

PKEY_UID_LEAD_ZERO_1 = '00'
DATA_UID_LEAD_ZERO_1 = {
    'pkey': PKEY_UID_LEAD_ZERO_1,
    'add': [
        ('textbox', 'uid', PKEY_UID_LEAD_ZERO_1),
        ('textbox', 'description', 'My GitHub app password for laptop'),
        ('textbox', 'ou', 'GitHub'),
    ]
}

PKEY_UID_LEAD_ZERO_2 = '08'
DATA_UID_LEAD_ZERO_2 = {
    'pkey': PKEY_UID_LEAD_ZERO_2,
    'add': [
        ('textbox', 'uid', PKEY_UID_LEAD_ZERO_2),
        ('textbox', 'description', 'My GitHub app password for PC'),
        ('textbox', 'ou', 'GitHub'),
    ]
}

PKEY_UID_LEAD_SPACE = ' 5'
DATA_UID_LEAD_SPACE = {
    'pkey': PKEY_UID_LEAD_SPACE,
    'add': [
        ('textbox', 'uid', PKEY_UID_LEAD_SPACE),
        ('textbox', 'description', 'My Skype app password for laptop'),
        ('textbox', 'ou', 'Skype'),
    ]
}

PKEY_UID_TRAIL_SPACE = '5 '
DATA_UID_TRAIL_SPACE = {
    'pkey': PKEY_UID_TRAIL_SPACE,
    'add': [
        ('textbox', 'uid', PKEY_UID_TRAIL_SPACE),
        ('textbox', 'description', 'My Skype app password for PC'),
        ('textbox', 'ou', 'Skype'),
    ]
}

PKEY_APPNAME_WITH_DOTS = '15'
DATA_APPNAME_WITH_DOTS = {
    'pkey': PKEY_APPNAME_WITH_DOTS,
    'add': [
        ('textbox', 'uid', PKEY_APPNAME_WITH_DOTS),
        ('textbox', 'description', 'My app password for company server'),
        ('textbox', 'ou', 'server.company.com'),
    ]
}

PKEY_APPNAME_LEAD_SPACE = '16'
DATA_APPNAME_LEAD_SPACE = {
    'pkey': PKEY_APPNAME_LEAD_SPACE,
    'add': [
        ('textbox', 'uid', PKEY_APPNAME_LEAD_SPACE),
        ('textbox', 'description', 'My Skype app password for smartphone'),
        ('textbox', 'ou', ' Skype'),
    ]
}

PKEY_APPNAME_TRAIL_SPACE = '17'
DATA_APPNAME_TRAIL_SPACE = {
    'pkey': PKEY_APPNAME_TRAIL_SPACE,
    'add': [
        ('textbox', 'uid', PKEY_APPNAME_TRAIL_SPACE),
        ('textbox', 'description', 'My Skype app password for smartphone'),
        ('textbox', 'ou', 'Skype '),
    ]
}

PKEY_NO_UID = '12'
DATA_NO_UID = {
    'pkey': PKEY_NO_UID,
    'add': [
        ('textbox', 'description', 'My WhatsApp app password for tablet'),
        ('textbox', 'ou', 'WhatsApp'),
    ]
}

PKEY_NO_DESCRIPTION = '13'
DATA_NO_DESCRIPTION = {
    'pkey': PKEY_NO_DESCRIPTION,
    'add': [
        ('textbox', 'uid', PKEY_NO_DESCRIPTION),
        ('textbox', 'ou', 'WhatsApp'),
    ]
}

PKEY_NO_APPNAME = '14'
DATA_NO_APPNAME = {
    'pkey': PKEY_NO_APPNAME,
    'add': [
        ('textbox', 'uid', PKEY_NO_APPNAME),
        ('textbox', 'description', 'My WhatsApp app password for tablet'),
    ]
}
