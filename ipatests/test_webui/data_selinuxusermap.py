#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

from ipaplatform.constants import constants as platformconstants

# for example, user_u:s0
selinuxuser1 = platformconstants.SELINUX_USERMAP_ORDER.split("$$")[0]
selinuxuser2 = platformconstants.SELINUX_USERMAP_ORDER.split("$$")[1]

selinux_mcs_max = platformconstants.SELINUX_MCS_MAX
selinux_mls_max = platformconstants.SELINUX_MLS_MAX

second_mls_level = 's{}'.format(list(range(0, selinux_mls_max + 1))[0])
second_mcs_level = 'c{}'.format(list(range(0, selinux_mcs_max + 1))[0])
mcs_range = '{0}.{0}'.format(second_mcs_level)

ENTITY = 'selinuxusermap'

PKEY = 'itest-selinuxusermap'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textbox', 'ipaselinuxuser', selinuxuser1),
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
        ('textbox', 'ipaselinuxuser', selinuxuser2),
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
        ('textbox', 'ipaselinuxuser', 'foo:s0-{}'.format(second_mls_level)),
    ],
}

PKEY_MCS_RANGE = 'itest-selinuxusermap_MLS_range'
DATA_MCS_RANGE = {
    'pkey': PKEY_MCS_RANGE,
    'add': [
        ('textbox', 'cn', PKEY_MCS_RANGE),
        ('textbox', 'ipaselinuxuser',
         'foo:s0-s{}:c0.c{}'.format(selinux_mls_max, selinux_mcs_max)
         ),
    ],
}

PKEY_MCS_COMMAS = 'itest-selinuxusermap_MCS_commas'
DATA_MCS_COMMAS = {
    'pkey': PKEY_MCS_COMMAS,
    'add': [
        ('textbox', 'cn', PKEY_MCS_COMMAS),
        ('textbox', 'ipaselinuxuser',
         'foo:s0-{}:c0,{},{}'.format(
             second_mls_level, second_mcs_level, mcs_range),
         ),
    ],
}

PKEY_MLS_SINGLE_VAL = 'itest-selinuxusermap_MLS_single_val'
DATA_MLS_SINGLE_VAL = {
    'pkey': PKEY_MLS_SINGLE_VAL,
    'add': [
        ('textbox', 'cn', PKEY_MLS_SINGLE_VAL),
        ('textbox', 'ipaselinuxuser',
         'foo:s0-s0:c0.c{}'.format(selinux_mcs_max)
         ),
    ],
}

PKEY_NON_EXIST_SEUSER = 'itest-selinuxusermap_nonexistent_user'
DATA_NON_EXIST_SEUSER = {
    'pkey': PKEY_NON_EXIST_SEUSER,
    'add': [
        ('textbox', 'cn', PKEY_NON_EXIST_SEUSER),
        ('textbox', 'ipaselinuxuser', 'foo:s0'),
    ],
}

PKEY_INVALID_MCS = 'itest-selinuxusermap_invalid_MCS'
DATA_INVALID_MCS = {
    'pkey': PKEY_INVALID_MCS,
    'add': [
        ('textbox', 'cn', PKEY_INVALID_MCS),
        ('textbox', 'ipaselinuxuser', 'foo:s0:c'),
    ],
}

PKEY_INVALID_MLS = 'itest-selinuxusermap_invalid_MLS'
DATA_INVALID_MLS = {
    'pkey': PKEY_INVALID_MLS,
    'add': [
        ('textbox', 'cn', PKEY_INVALID_MLS),
        ('textbox', 'ipaselinuxuser', 'foo'),
    ],
}

PKEY_FIELD_REQUIRED = 'itest-selinuxusermap_without_SELinux_user'
DATA_FIELD_REQUIRED = {
    'pkey': PKEY_FIELD_REQUIRED,
    'add': [
        ('textbox', 'cn', PKEY_FIELD_REQUIRED),
    ],
}
