#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

ENTITY = 'selinuxusermap'

PKEY = 'itest-selinuxusermap'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textbox', 'ipaselinuxuser', 'user_u:s0'),
    ],
    'mod': [
        ('textarea', 'description', 'itest-selinuxusermap desc'),
    ],
}

PKEY2 = 'itest-selinuxusermap2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'cn', PKEY2),
        ('textbox', 'ipaselinuxuser', 'unconfined_u:s0-s0:c0.c1023'),
    ],
    'mod': [
        ('textarea', 'description', 'itest-selinuxusermap desc2'),
    ],
}

PKEY_MLS_RANGE = 'itest-selinuxusermap_MLS_range'
DATA_MLS_RANGE = {
    'pkey': PKEY_MLS_RANGE,
    'add': [
        ('textbox', 'cn', PKEY_MLS_RANGE),
        ('textbox', 'ipaselinuxuser', 'user_u:s0-s1'),
    ],
}

PKEY_MCS_RANGE = 'itest-selinuxusermap_MLS_range'
DATA_MCS_RANGE = {
    'pkey': PKEY_MCS_RANGE,
    'add': [
        ('textbox', 'cn', PKEY_MCS_RANGE),
        ('textbox', 'ipaselinuxuser', 'user_u:s0-s15:c0.c1023'),
    ],
}

PKEY_MCS_COMMAS = 'itest-selinuxusermap_MCS_commas'
DATA_MCS_COMMAS = {
    'pkey': PKEY_MCS_COMMAS,
    'add': [
        ('textbox', 'cn', PKEY_MCS_COMMAS),
        ('textbox', 'ipaselinuxuser', 'user_u:s0-s1:c0,c2,c15.c26'),
    ],
}

PKEY_MLS_SINGLE_VAL = 'itest-selinuxusermap_MLS_single_val'
DATA_MLS_SINGLE_VAL = {
    'pkey': PKEY_MLS_SINGLE_VAL,
    'add': [
        ('textbox', 'cn', PKEY_MLS_SINGLE_VAL),
        ('textbox', 'ipaselinuxuser', 'user_u:s0-s0:c0.c1023'),
    ],
}

PKEY_NON_EXIST_SEUSER = 'itest-selinuxusermap_nonexistent_user'
DATA_NON_EXIST_SEUSER = {
    'pkey': PKEY_NON_EXIST_SEUSER,
    'add': [
        ('textbox', 'cn', PKEY_NON_EXIST_SEUSER),
        ('textbox', 'ipaselinuxuser', 'abc:s0'),
    ],
}

PKEY_INVALID_MCS = 'itest-selinuxusermap_invalid_MCS'
DATA_INVALID_MCS = {
    'pkey': PKEY_INVALID_MCS,
    'add': [
        ('textbox', 'cn', PKEY_INVALID_MCS),
        ('textbox', 'ipaselinuxuser', 'user:s0:c'),
    ],
}

PKEY_INVALID_MLS = 'itest-selinuxusermap_invalid_MLS'
DATA_INVALID_MLS = {
    'pkey': PKEY_INVALID_MLS,
    'add': [
        ('textbox', 'cn', PKEY_INVALID_MLS),
        ('textbox', 'ipaselinuxuser', 'user'),
    ],
}

PKEY_FIELD_REQUIRED = 'itest-selinuxusermap_without_SELinux_user'
DATA_FIELD_REQUIRED = {
    'pkey': PKEY_FIELD_REQUIRED,
    'add': [
        ('textbox', 'cn', PKEY_FIELD_REQUIRED),
    ],
}
