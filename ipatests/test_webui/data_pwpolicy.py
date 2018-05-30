#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

import ipatests.test_webui.data_group as group

ENTITY = 'pwpolicy'
DEFAULT_POLICY = 'global_policy'

DATA = {
    'pkey': 'admins',
    'add': [
        ('combobox', 'cn', 'admins'),
        ('textbox', 'cospriority', '364'),
    ],
    'mod': [
        ('textbox', 'krbmaxpwdlife', '3000'),
        ('textbox', 'krbminpwdlife', '1'),
        ('textbox', 'krbpwdhistorylength', '0'),
        ('textbox', 'krbpwdmindiffchars', '2'),
        ('textbox', 'krbpwdminlength', '2'),
        ('textbox', 'krbpwdmaxfailure', '15'),
        ('textbox', 'krbpwdfailurecountinterval', '5'),
        ('textbox', 'krbpwdlockoutduration', '3600'),
        ('textbox', 'cospriority', '365'),
    ],
}

PKEY1 = group.PKEY
DATA1 = {
    'pkey': group.PKEY,
    'add': [
        ('combobox', 'cn', group.PKEY),
        ('textbox', 'cospriority', '1'),
    ],
}

PKEY2 = group.PKEY2
DATA2 = {
    'pkey': group.PKEY2,
    'add': [
        ('combobox', 'cn', group.PKEY2),
        ('textbox', 'cospriority', '2'),
    ],
}

PKEY3 = group.PKEY3
DATA3 = {
    'pkey': group.PKEY3,
    'add': [
        ('combobox', 'cn', group.PKEY3),
        ('textbox', 'cospriority', '3'),
    ],
}

PKEY6 = group.PKEY6
DATA_RESET = {
    'pkey': group.PKEY6,
    'add': [
        ('combobox', 'cn', group.PKEY6),
        ('textbox', 'cospriority', '6'),
    ],
    'mod': [
        ('textbox', 'krbmaxpwdlife', '1000'),
        ('textbox', 'krbminpwdlife', '2'),
        ('textbox', 'krbpwdhistorylength', '0'),
        ('textbox', 'krbpwdmindiffchars', '3'),
        ('textbox', 'krbpwdminlength', '4'),
        ('textbox', 'krbpwdmaxfailure', '17'),
        ('textbox', 'krbpwdfailurecountinterval', '4'),
        ('textbox', 'krbpwdlockoutduration', '4200'),
        ('textbox', 'cospriority', '38'),
    ],
}

PKEY_SPECIAL_CHAR = group.PKEY_SPECIAL_CHAR_GROUP
DATA_SPECIAL_CHAR = {
    'pkey': group.PKEY_SPECIAL_CHAR_GROUP,
    'add': [
        ('combobox', 'cn', group.PKEY_SPECIAL_CHAR_GROUP),
        ('textbox', 'cospriority', '7'),
    ],
}

PKEY7 = group.PKEY4
DATA7 = {
    'pkey': group.PKEY4,
    'add': [
        ('combobox', 'cn', group.PKEY4),
        ('textbox', 'cospriority', '4'),
    ],
}
