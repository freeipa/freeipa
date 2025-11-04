# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information
ENTITY = 'sysaccount'

PKEY = 'itest-sysaccount'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'uid', PKEY),
        ('textbox', 'description', 'test system account desc'),
        ('password', 'userpassword', 'Secret123'),
        ('password', 'userpassword2', 'Secret123'),
    ],
    'add_v': [
        ('label', 'uid', PKEY),
        ('textbox', 'description', 'test system account desc'),
    ],
    'mod': [
        ('textbox', 'description', 'test system account desc modified'),
    ],
    'mod_v': [
        ('label', 'uid', PKEY),
        ('textbox', 'description', 'test system account desc modified'),
    ],
    'del': [
        ('textbox', 'description', 'test system account desc modified'),
    ],

}

PKEY2 = 'itest-sysaccount2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'uid', PKEY2),
        ('textbox', 'description', 'test system account2 desc'),
        ('checkbox', 'privileged', 'checked'),
        ('password', 'userpassword', 'Secret123'),
        ('password', 'userpassword2', 'Secret123'),
    ],
}

PKEY_PRIVILEGED = 'itest-sysaccount-privileged'
DATA_PRIVILEGED = {
    'pkey': PKEY_PRIVILEGED,
    'add': [
        ('textbox', 'uid', PKEY_PRIVILEGED),
        ('textbox', 'description', 'privileged system account'),
        ('checkbox', 'privileged', 'checked'),
        ('password', 'userpassword', 'Secret123'),
        ('password', 'userpassword2', 'Secret123'),
    ],
    'mod': [
        ('checkbox', 'privileged', None),
    ],
    'mod_v': [
        ('label', 'uid', PKEY_PRIVILEGED),
        ('checkbox', 'privileged', None),
    ],
}
