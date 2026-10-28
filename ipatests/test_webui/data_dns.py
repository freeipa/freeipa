#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

ZONE_ENTITY = 'dnszone'
FORWARD_ZONE_ENTITY = 'dnsforwardzone'
RECORD_ENTITY = 'dnsrecord'
CONFIG_ENTITY = 'dnsconfig'

ZONE_DEFAULT_FACET = 'records'

ZONE_PKEY = 'foo.itest.'

ZONE_DATA = {
    'pkey': ZONE_PKEY,
    'add': [
        ('textbox', 'idnsname', ZONE_PKEY),
    ],
    'mod': [
        ('checkbox', 'idnsallowsyncptr', 'checked'),
    ],
}

FORWARD_ZONE_PKEY = 'forward.itest.'

FORWARD_ZONE_DATA = {
    'pkey': FORWARD_ZONE_PKEY,
    'add': [
        ('textbox', 'idnsname', FORWARD_ZONE_PKEY),
        ('multivalued', 'idnsforwarders', [
            ('add', '192.168.2.1'),
        ]),
        ('radio', 'idnsforwardpolicy', 'only'),
    ],
    'mod': [
        ('multivalued', 'idnsforwarders', [
            ('add', '192.168.3.1'),
        ]),
        ('checkbox', 'idnsforwardpolicy', 'first'),
    ],
}

RECORD_PKEY = 'itest'
A_IP = '192.168.1.10'
RECORD_ADD_DATA = {
    'pkey': RECORD_PKEY,
    'add': [
        ('textbox', 'idnsname', RECORD_PKEY),
        ('textbox', 'a_part_ip_address', A_IP),
    ]
}

RECORD_MOD_DATA = {
    'fields': [
        ('textbox', 'a_part_ip_address', '192.168.1.11'),
    ]
}

CONFIG_MOD_DATA = {
    'mod': [
        ('checkbox', 'idnsallowsyncptr', 'checked'),
    ],
}
