# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Password policy
"""

from ipalib import api, errors
from ipalib import Command
from ipalib import Int

_fields = {
    'krbminpwdlife': 'Minimum lifetime (in hours)',
    'krbmaxpwdlife': 'Maximum lifetime (in days)',
    'krbpwdmindiffchars': 'Minimum number of characters classes',
    'krbpwdminlength': 'Minimum length',
    'krbpwdhistorylength': 'History size',
}

def _convert_time_for_output(entry_attrs):
    if 'krbmaxpwdlife' in entry_attrs:
        entry_attrs['krbmaxpwdlife'][0] = str(
            int(entry_attrs['krbmaxpwdlife'][0]) / 86400
        )
    if 'krbminpwdlife' in entry_attrs:
        entry_attrs['krbminpwdlife'][0] = str(
            int(entry_attrs['krbminpwdlife'][0]) / 3600
        )


class pwpolicy_mod(Command):
    """
    Modify password policy.
    """
    takes_options = (
        Int('krbmaxpwdlife?',
            cli_name='maxlife',
            doc='Max. Password Lifetime (days)',
            minvalue=0,
            attribute=True,
        ),
        Int('krbminpwdlife?',
            cli_name='minlife',
            doc='Min. Password Lifetime (hours)',
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdhistorylength?',
            cli_name='history',
            doc='Password History Size',
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdmindiffchars?',
            cli_name='minclasses',
            doc='Min. Number of Character Classes',
            minvalue=0,
            attribute=True,
        ),
        Int('krbpwdminlength?',
            cli_name='minlength',
            doc='Min. Length of Password',
            minvalue=0,
            attribute=True,
        ),
    )

    def execute(self, *args, **options):
        assert 'dn' not in options
        ldap = self.api.Backend.ldap2

        entry_attrs = self.args_options_2_entry(*args, **options)
        dn = self.api.env.container_accounts

        # Convert hours and days to seconds
        if 'krbmaxpwdlife' in entry_attrs:
            entry_attrs['krbmaxpwdlife'] = entry_attrs['krbmaxpwdlife'] * 86400
            del entry_attrs['krbmaxpwdlife']
        if 'krbminpwdlife' in entry_attrs:
            entry_attrs['krbminpwdlife'] = entry_attrs['krbminpwdlife'] * 3600
            del entry_attrs['krbminpwdlife']

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())

        _convert_time_for_output(entry_attrs)

        return (dn, entry_attrs)

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_plain('Password policy:')
        for (k, v) in _fields.iteritems():
            if k in entry_attrs:
                textui.print_attribute(v, entry_attrs[k])
        textui.print_dashed('Modified password policy.')

api.register(pwpolicy_mod)


class pwpolicy_show(Command):
    """
    Display password policy.
    """
    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2

        dn = self.api.env.container_accounts
        (dn, entry_attrs) = ldap.get_entry(dn)

        _convert_time_for_output(entry_attrs)

        return (dn, entry_attrs)

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_plain('Password policy:')
        for (k, v) in _fields.iteritems():
            if k in entry_attrs:
                textui.print_attribute(v, entry_attrs[k])

api.register(pwpolicy_show)

