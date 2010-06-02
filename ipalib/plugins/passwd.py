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
User password changes

Sets a user password. Normally a user can only change their own password.

If someone other than user changes a password (e.g. helpdesk resets it)
then the password will need to be changed the first time it is used.
This is so the end-user is the only one that knows the password.

Password policy will control how often a password may be changed,
what strength requirements there are and long the password history is.

EXAMPLES:

 Reset your own password:
   ipa passwd

 Change another user's password:
   ipa passwd tuser1
"""

from ipalib import api, errors, util
from ipalib import Command
from ipalib import Str, Password
from ipalib import _


class passwd(Command):
    """
    Change user password.
    """

    takes_args = (
        Str('principal',
            cli_name='user',
            label=_('User name'),
            primary_key=True,
            autofill=True,
            create_default=lambda **kw: util.get_current_principal(),
        ),
        Password('password'),
    )

    def execute(self, principal, password):
        """
        Execute the passwd operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param principal: The login name or principal of the user
        :param password: the new password
        """
        ldap = self.api.Backend.ldap2

        if principal.find('@') != -1:
            principal_parts = principal.split('@')
            if len(principal_parts) > 2:
                raise errors.MalformedUserPrincipal(principal=principal)
        else:
            principal = '%s@%s' % (principal, self.api.env.realm)

        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'krbprincipalname', principal, 'posixaccount', ['']
        )

        ldap.modify_password(dn, password)

        return dict(result=True)

    def output_for_cli(self, textui, result, principal, password):
        assert password is None
        textui.print_name(self.name)
        textui.print_dashed('Changed password for "%s."' % principal)

api.register(passwd)
