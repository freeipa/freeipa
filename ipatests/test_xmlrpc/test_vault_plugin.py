# Authors:
#   Endi S. Dewata <edewata@redhat.com>
#
# Copyright (C) 2015  Red Hat
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

"""
Test the `ipalib/plugins/vault.py` module.
"""

from ipalib import api, errors
from xmlrpc_test import Declarative, fuzzy_string

vault_name = u'test_vault'
service_name = u'HTTP/server.example.com'
user_name = u'testuser'


class test_vault_plugin(Declarative):

    cleanup_commands = [
        ('vault_del', [vault_name], {'continue': True}),
        ('vault_del', [vault_name], {
            'service': service_name,
            'continue': True
        }),
        ('vault_del', [vault_name], {'shared': True, 'continue': True}),
        ('vault_del', [vault_name], {'user': user_name, 'continue': True}),
    ]

    tests = [

        {
            'desc': 'Create private vault',
            'command': (
                'vault_add',
                [vault_name],
                {},
            ),
            'expected': {
                'value': vault_name,
                'summary': 'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,%s'
                          % (vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Find private vaults',
            'command': (
                'vault_find',
                [],
                {},
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,%s'
                              % (vault_name, api.env.basedn),
                        'cn': [vault_name],
                    },
                ],
            },
        },

        {
            'desc': 'Show private vault',
            'command': (
                'vault_show',
                [vault_name],
                {},
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=admin,cn=users,cn=vaults,%s'
                          % (vault_name, api.env.basedn),
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Modify private vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                },
            },
        },

        {
            'desc': 'Delete private vault',
            'command': (
                'vault_del',
                [vault_name],
                {},
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create service vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=%s,cn=services,cn=vaults,%s'
                          % (vault_name, service_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Find service vaults',
            'command': (
                'vault_find',
                [],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=%s,cn=services,cn=vaults,%s'
                              % (vault_name, service_name, api.env.basedn),
                        'cn': [vault_name],
                    },
                ],
            },
        },

        {
            'desc': 'Show service vault',
            'command': (
                'vault_show',
                [vault_name],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=%s,cn=services,cn=vaults,%s'
                          % (vault_name, service_name, api.env.basedn),
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Modify service vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'service': service_name,
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                },
            },
        },

        {
            'desc': 'Delete service vault',
            'command': (
                'vault_del',
                [vault_name],
                {
                    'service': service_name,
                },
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create shared vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'shared': True
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=shared,cn=vaults,%s'
                          % (vault_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Find shared vaults',
            'command': (
                'vault_find',
                [],
                {
                    'shared': True
                },
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=shared,cn=vaults,%s'
                              % (vault_name, api.env.basedn),
                        'cn': [vault_name],
                    },
                ],
            },
        },

        {
            'desc': 'Show shared vault',
            'command': (
                'vault_show',
                [vault_name],
                {
                    'shared': True
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=shared,cn=vaults,%s'
                          % (vault_name, api.env.basedn),
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Modify shared vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'shared': True,
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                },
            },
        },

        {
            'desc': 'Delete shared vault',
            'command': (
                'vault_del',
                [vault_name],
                {
                    'shared': True
                },
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

        {
            'desc': 'Create user vault',
            'command': (
                'vault_add',
                [vault_name],
                {
                    'user': user_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Added vault "%s"' % vault_name,
                'result': {
                    'dn': u'cn=%s,cn=%s,cn=users,cn=vaults,%s'
                          % (vault_name, user_name, api.env.basedn),
                    'objectclass': [u'top', u'ipaVault'],
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Find user vaults',
            'command': (
                'vault_find',
                [],
                {
                    'user': user_name,
                },
            ),
            'expected': {
                'count': 1,
                'truncated': False,
                'summary': u'1 vault matched',
                'result': [
                    {
                        'dn': u'cn=%s,cn=%s,cn=users,cn=vaults,%s'
                              % (vault_name, user_name, api.env.basedn),
                        'cn': [vault_name],
                    },
                ],
            },
        },

        {
            'desc': 'Show user vault',
            'command': (
                'vault_show',
                [vault_name],
                {
                    'user': user_name,
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': None,
                'result': {
                    'dn': u'cn=%s,cn=%s,cn=users,cn=vaults,%s'
                          % (vault_name, user_name, api.env.basedn),
                    'cn': [vault_name],
                },
            },
        },

        {
            'desc': 'Modify user vault',
            'command': (
                'vault_mod',
                [vault_name],
                {
                    'user': user_name,
                    'description': u'Test vault',
                },
            ),
            'expected': {
                'value': vault_name,
                'summary': u'Modified vault "%s"' % vault_name,
                'result': {
                    'cn': [vault_name],
                    'description': [u'Test vault'],
                },
            },
        },

        {
            'desc': 'Delete user vault',
            'command': (
                'vault_del',
                [vault_name],
                {
                    'user': user_name,
                },
            ),
            'expected': {
                'value': [vault_name],
                'summary': u'Deleted vault "%s"' % vault_name,
                'result': {
                    'failed': (),
                },
            },
        },

    ]
