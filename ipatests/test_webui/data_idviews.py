#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

ENTITY = 'idview'
USER_FACET = 'idoverrideuser'
GROUP_FACET = 'idoverridegroup'
HOST_FACET = 'appliedtohosts'

PKEY = 'itest-view'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'cn', PKEY),
        ('textarea', 'description', 'Description of ID view'),
    ],
    'mod': [
        ('textarea', 'description', 'Different description'),
    ],
}
