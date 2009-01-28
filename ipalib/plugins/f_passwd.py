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
Frontend plugins for password changes.
"""

from ipalib import api, errors, util
from ipalib import Command  # Plugin base classes
from ipalib import Str, Password  # Parameter types


class passwd(Command):
    'Edit existing password policy.'

    takes_args = (
        Password('password'),
        Str('principal?',
            cli_name='user',
            primary_key=True,
            autofill=True,
            default_from=util.get_current_principal,
        ),
    )

    def execute(self, principal, password):
        """
        Execute the passwd operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param param uid: The login name of the user being updated.
        :param kw: Not used.
        """
        if principal.find('@') > 0:
            u = principal.split('@')
            if len(u) > 2:
                raise errors.InvalidUserPrincipal, principal
        else:
            principal = principal+"@"+self.api.env.realm
        dn = self.Backend.ldap.find_entry_dn(
            "krbprincipalname",
            principal,
            "posixAccount"
        )
        return self.Backend.ldap.modify_password(dn, newpass=password)

    def output_for_cli(self, textui, result, principal, password):
        assert password is None
        textui.print_plain('Changed password for "%s"' % principal)

api.register(passwd)
