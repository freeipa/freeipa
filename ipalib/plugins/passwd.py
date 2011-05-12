# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Set a user's password

If someone other than a user changes that user's password (e.g., Helpdesk
resets it) then the password will need to be changed the first time it
is used. This is so the end-user is the only one who knows the password.

The IPA password policy controls how often a password may be changed,
what strength requirements exist, and the length of the password history.

EXAMPLES:

 To reset your own password:
   ipa passwd

 To change another user's password:
   ipa passwd tuser1
"""

from ipalib import api, errors, util
from ipalib import Command
from ipalib import Str, Password
from ipalib import _
from ipalib import output


class passwd(Command):
    """
    Set a user's password
    """

    takes_args = (
        Str('principal',
            cli_name='user',
            label=_('User name'),
            primary_key=True,
            autofill=True,
            create_default=lambda **kw: util.get_current_principal(),
        ),
        Password('password',
                 label=_('Password'),
        ),
    )

    has_output = output.standard_value
    msg_summary = _('Changed password for "%(value)s"')

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
            'krbprincipalname', principal, 'posixaccount', [''],
            ",".join([api.env.container_user, api.env.basedn])
        )

        ldap.modify_password(dn, password)

        return dict(
            result=True,
            value=principal,
        )

api.register(passwd)
