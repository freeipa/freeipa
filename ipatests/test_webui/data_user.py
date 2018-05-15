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


ENTITY = 'user'

PKEY = 'itest-user'
DATA = {
    'pkey': PKEY,
    'add': [
        ('textbox', 'uid', PKEY),
        ('textbox', 'givenname', 'Name'),
        ('textbox', 'sn', 'Surname'),
    ],
    'add_v': [
        ('textbox', 'givenname', 'Name'),
        ('textbox', 'sn', 'Surname'),
        ('label', 'uid', PKEY),
    ],
    'mod': [
        ('textbox', 'givenname', 'OtherName'),
        ('textbox', 'sn', 'OtherSurname'),
        ('textbox', 'initials', 'NOS'),
        ('textbox', 'loginshell', '/bin/csh'),
        ('textbox', 'homedirectory', '/home/alias'),
        ('multivalued', 'telephonenumber', [
            ('add', '123456789'),
            ('add', '987654321'),
        ]),
        ('multivalued', 'mail', [
            ('add', 'one@ipa.test'),
            ('add', 'two@ipa.test'),
            ('add', 'three@ipa.test'),
        ]),
        ('multivalued', 'pager', [
            ('add', '1234567'),
            ('add', '7654321'),
        ]),
        ('multivalued', 'mobile', [
            ('add', '001123456'),
            ('add', '001654321'),
        ]),
        ('multivalued', 'facsimiletelephonenumber', [
            ('add', '1122334'),
            ('add', '4332211'),
        ]),
        ('textbox', 'street', 'Wonderwall ave.'),
        ('textbox', 'l', 'Atlantis'),
        ('textbox', 'st', 'Universe'),
        ('textbox', 'postalcode', '61600'),
        ('multivalued', 'carlicense', [
            ('add', 'ZLA-1336'),
        ]),
        ('textbox', 'ou', 'QE'),
        ('combobox', 'manager', 'admin'),
        ('textbox', 'employeenumber', '123'),
        ('textbox', 'employeetype', 'contractor'),
        ('textbox', 'preferredlanguage', 'Spanish'),
    ],
    'mod_v': [
        ('textbox', 'givenname', 'OtherName'),
        ('textbox', 'sn', 'OtherSurname'),
        ('textbox', 'initials', 'NOS'),
        ('textbox', 'loginshell', '/bin/csh'),
        ('textbox', 'homedirectory', '/home/alias'),
        ('label', 'krbmaxrenewableage', '604800'),
        ('label', 'krbmaxticketlife', '86400'),
        ('multivalued', 'telephonenumber', ['123456789', '987654321']),
        ('multivalued', 'mail', ['one@ipa.test', 'two@ipa.test',
                                 'three@ipa.test']),
        ('multivalued', 'pager', ['1234567', '7654321']),
        ('multivalued', 'mobile', ['001123456', '001654321']),
        ('multivalued', 'facsimiletelephonenumber', ['1122334', '4332211']),
        ('textbox', 'street', 'Wonderwall ave.'),
        ('textbox', 'l', 'Atlantis'),
        ('textbox', 'st', 'Universe'),
        ('textbox', 'postalcode', '61600'),
        ('multivalued', 'carlicense', ['ZLA-1336']),
        ('textbox', 'ou', 'QE'),
        ('combobox', 'manager', 'admin'),
        ('textbox', 'employeenumber', '123'),
        ('textbox', 'employeetype', 'contractor'),
        ('textbox', 'preferredlanguage', 'Spanish'),
    ],
}

PKEY2 = 'itest-user2'
DATA2 = {
    'pkey': PKEY2,
    'add': [
        ('textbox', 'uid', PKEY2),
        ('textbox', 'givenname', 'Name2'),
        ('textbox', 'sn', 'Surname2'),
    ],
    'mod': [
        ('textbox', 'givenname', 'OtherName2'),
        ('textbox', 'sn', 'OtherSurname2'),
        ('textbox', 'postalcode', '007007'),
    ],
}

PKEY3 = 'itest-user3'
DATA3 = {
    'pkey': PKEY3,
    'add': [
        ('textbox', 'uid', PKEY3),
        ('textbox', 'givenname', 'Name3'),
        ('textbox', 'sn', 'Surname3'),
        ('checkbox', 'noprivate', None),
    ]
}

PKEY4 = 'itest-user4'
DATA4 = {
    'pkey': PKEY4,
    'add': [
        ('textbox', 'uid', PKEY4),
        ('textbox', 'givenname', 'Name4'),
        ('textbox', 'sn', 'Surname4'),
        ('checkbox', 'noprivate', None),
        ('combobox', 'gidnumber', '77777'),
    ]
}

PKEY_SPECIAL_CHARS = '1spe.cial_us-er$'
PASSWD_SCECIAL_CHARS = '!!!@@@###$$$'
DATA_SPECIAL_CHARS = {
    'pkey': PKEY_SPECIAL_CHARS,
    'add': [
        ('textbox', 'uid', PKEY_SPECIAL_CHARS),
        ('textbox', 'givenname', 'S$p|e>c--i_a%l_'),
        ('textbox', 'sn', '%U&s?e+r'),
        ('password', 'userpassword', PASSWD_SCECIAL_CHARS),
        ('password', 'userpassword2', PASSWD_SCECIAL_CHARS),
    ]
}

PKEY_LONG_LOGIN = 'itest-user' * 5
DATA_LONG_LOGIN = {
    'pkey': PKEY_LONG_LOGIN,
    'add': [
        ('textbox', 'uid', PKEY_LONG_LOGIN),
        ('textbox', 'givenname', 'Name8'),
        ('textbox', 'sn', 'Surname8'),
    ]
}

PKEY_PASSWD_LEAD_SPACE = 'itest-user-passwd-leading-space'
DATA_PASSWD_LEAD_SPACE = {
    'pkey': PKEY_PASSWD_LEAD_SPACE,
    'add': [
        ('textbox', 'uid', PKEY_PASSWD_LEAD_SPACE),
        ('textbox', 'givenname', 'Name7'),
        ('textbox', 'sn', 'Surname7'),
        ('password', 'userpassword', ' Password123 '),
        ('password', 'userpassword2', ' Password123 '),
    ]
}

PKEY_PASSWD_TRAIL_SPACE = 'itest-user-passwd-trailing-space'
DATA_PASSWD_TRAIL_SPACE = {
    'pkey': PKEY_PASSWD_LEAD_SPACE,
    'add': [
        ('textbox', 'uid', PKEY_PASSWD_LEAD_SPACE),
        ('textbox', 'givenname', 'Name8'),
        ('textbox', 'sn', 'Surname8'),
        ('password', 'userpassword', 'Password123 '),
        ('password', 'userpassword2', 'Password123 '),
    ]
}

PKEY_PASSWD_MISMATCH = 'itest-user-passwd-mismatch'
DATA_PASSWD_MISMATCH = {
    'pkey': PKEY_PASSWD_MISMATCH,
    'add': [
        ('textbox', 'uid', PKEY_PASSWD_MISMATCH),
        ('textbox', 'givenname', 'Name9'),
        ('textbox', 'sn', 'Surname9'),
        ('password', 'userpassword', 'Password123'),
        ('password', 'userpassword2', 'Password12'),
    ]
}

PKEY_NO_LOGIN = 'itest-user-no-login'
DATA_NO_LOGIN = {
    'pkey': PKEY_NO_LOGIN,
    'add': [
        ('textbox', 'givenname', 'Name10'),
        ('textbox', 'sn', 'Surname10'),
        ('password', 'userpassword', 'Password123'),
        ('password', 'userpassword2', 'Password123'),
    ]
}

SSH_RSA = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBVmLXpTDhrYkABOPlADFk'
    'GV8/QfgQqUQ0xn29hk18t/NTEQOW/Daq4EF84e9aTiopRXIk7jahBLzwWTZI'
    'WwuvegGYqs89bDhUHZEnS9TBfXkkYq9LamlEVooR5kxb/kPtCnmMMXhQUOzH'
    'xqakuZiN4AduRCzaecu0mearVjZWAChM3fYp4sMXKoRzek2F/xOUh81GxrW0'
    'kbhpbaeXd6oG8p6AC3QCrEspzX78WEOCPSTJlx/BAv77A27b5zO2cSeZNbZq'
    'XFqaQQj8AX46qoATWLhOnokoE2xeJTKikG/4nmc3D2KO6SRh66dEQWtJuVVw'
    'ZqgQRdaseDjjgR1FKbC1'
)

SSH_RSA2 = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBVmLXpTDhrYkABOPlADFk'
    'GV8/QfgQqUQ0xn29hk18t/NTEQOW/Daq4EF84e9aTiopRXIk7jahBLzwWTZI'
    'WwuvegGYqs89bDhUHZEnS9TBfXkkYq9LamlEVooR5kxb/kPtCnmMMXhQUOzH'
    'xqakuZiN4AduRCzaecu0mearVjZWAChM3fYp4sMXKoRzek2F/xOUh81GxrW0'
    'kbhpbaeXd6oG8p6AC3QCrEspzX78WEOCPSTJlx/BAv77A27b5zO2cSeZNbZq'
    'XFqaQQj8AX46qoATWLhOnokoE2xeJTKikG/4nmc3D2KO6SRh66dEQWtJuVVw'
    'ZqgQRdaseDjjgR1FK222'
)

SSH_DSA = (
    'ssh-dss AAAAB3NzaC1kc3MAAACBAKSh2gHHQ0lsPEKZU7utlx3I/M8FtSMx'
    '+MtE+QjReRPIWHjwTHLC6j5Bh2A8kwwiiqiiiDbvkJPgV3+5zmrnWvTICzet'
    'zS4vOgk6ymDux2J/1JPRb6c2yjjFaYL0SndC6abdgohyUAJPzNkgEhnQll/o'
    'QeavJXzLyonaX1wcl+R1AAAAFQCuMfl69Zyrx5B1qZmUsRVqG24W7wAAAIEA'
    'pFVe4JOuhRjSufJXMV+nzoqkhIhDEOYLqcpnq3cUrvBFEkQ5tKyYephFJxq+'
    'u7xkFx4d/K5eC7NH6/o/ziBocKJ7ESXBihC2lGLsHnWqreN9vCBihspBij+n'
    '/wUpgcq2dMBDC2BzqCfdashM1xHm1XahqCvV87pvjRhl1avy+K0AAACAEQKs'
    '3kKhEB/WGuAQa+tojRyIwtBc4lzZuJia4qOg6R4oSviKINwEtFtH08snteGn'
    'c4qiZ6XBrfYJT2VS1yjFVj+OmGSHmrX1GdfRfco8Y1ZYC7VLwt20dutw9hKK'
    'MSHI9NrJ5oOZ/GONlaKuqzKtTNb/vOIn/8yz52Od3X2Ehh1='
)
