#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

ENTITY = 'config'

GRP_SEARCH_FIELD_DEFAULT = 'cn,description'
USR_SEARCH_FIELD_DEFAULT = 'uid,givenname,sn,telephonenumber,ou,title'

DATA = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', '200'),
        ('textbox', 'ipasearchtimelimit', '3'),
    ],
}

DATA2 = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', '100'),
        ('textbox', 'ipasearchtimelimit', '2'),
    ],
}

DATA_SIZE_LIMIT_LETTER = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', 'a'),
    ],
}

DATA_SIZE_LIMIT_SPACE = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', ' space'),
    ],
}

DATA_SIZE_LIMIT_NEG = {
    'mod': [
        ('textbox', 'ipasearchrecordslimit', '-2'),
    ],
}

DATA_TIME_LIMIT_LETTER = {
    'mod': [
        ('textbox', 'ipasearchtimelimit', 'a'),
    ],
}

DATA_TIME_LIMIT_SPACE = {
    'mod': [
        ('textbox', 'ipasearchtimelimit', ' space'),
    ],
}

DATA_TIME_LIMIT_NEG = {
    'mod': [
        ('textbox', 'ipasearchtimelimit', '-2'),
    ],
}
