# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Frontend plugins for password policy.
"""

from ipalib import api
from ipalib import Command  # Plugin base classes
from ipalib import Int  # Parameter types


class pwpolicy_mod(Command):
    'Edit existing password policy.'
    takes_options = (
        Int('krbmaxpwdlife?',
            cli_name='maxlife',
            doc='Max. Password Lifetime (days)',
            minvalue=0,
        ),
        Int('krbminpwdlife?',
            cli_name='minlife',
            doc='Min. Password Lifetime (hours)',
            minvalue=0,
        ),
        Int('krbpwdhistorylength?',
            cli_name='history',
            doc='Password History Size',
            minvalue=0,
        ),
        Int('krbpwdmindiffchars?',
            cli_name='minclasses',
            doc='Min. Number of Character Classes',
            minvalue=0,
        ),
        Int('krbpwdminlength?',
            cli_name='minlength',
            doc='Min. Length of Password',
            minvalue=0,
        ),
    )
    def execute(self, *args, **kw):
        """
        Execute the pwpolicy-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param args: This function takes no positional arguments
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", "accounts", "krbPwdPolicy")

        # The LDAP routines want strings, not ints, so convert a few
        # things. Otherwise it sees a string -> int conversion as a change.
        for k in kw.iterkeys():
            if k.startswith("krb", 0, 3) and type(kw[k]) is int:
                kw[k] = str(kw[k])

        # Convert hours and days to seconds
        if kw.get('krbmaxpwdlife'):
            kw['krbmaxpwdlife'] = str(int(kw.get('krbmaxpwdlife')) * 86400)
        if kw.get('krbminpwdlife'):
            kw['krbminpwdlife'] = str(int(kw.get('krbminpwdlife')) * 3600)

        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_plain("Policy modified")

api.register(pwpolicy_mod)


class pwpolicy_show(Command):
    'Retrieve current password policy'
    def execute(self, *args, **kw):
        """
        Execute the pwpolicy-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param args: Not used.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn", "accounts", "krbPwdPolicy")

        policy = ldap.retrieve(dn)

        # convert some values for display purposes
        policy['krbmaxpwdlife'] = str(int(policy.get('krbmaxpwdlife')) / 86400)
        policy['krbminpwdlife'] = str(int(policy.get('krbminpwdlife')) / 3600)

        return policy

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_plain("Password Policy")
        textui.print_plain("Min. Password Lifetime (hours): %s" % result.get('krbminpwdlife'))
        textui.print_plain("Max. Password Lifetime (days): %s" % result.get('krbmaxpwdlife'))
        textui.print_plain("Min. Number of Character Classes: %s" % result.get('krbpwdmindiffchars'))
        textui.print_plain("Min. Length of Password: %s" % result.get('krbpwdminlength'))
        textui.print_plain("Password History Size: %s" % result.get('krbpwdhistorylength'))

api.register(pwpolicy_show)
