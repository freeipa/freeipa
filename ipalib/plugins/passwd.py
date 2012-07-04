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

from ipalib import api, errors, util
from ipalib import Command
from ipalib import Str, Password
from ipalib import _
from ipalib import output
from ipalib.plugins.user import split_principal, validate_principal, normalize_principal
from ipalib.request import context
from ipapython.dn import DN

__doc__ = _("""
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
""")

# We only need to prompt for the current password when changing a password
# for yourself, but the parameter is still required
MAGIC_VALUE = u'CHANGING_PASSWORD_FOR_ANOTHER_USER'

def get_current_password(principal):
    """
    If the user is changing their own password then return None so the
    current password is prompted for, otherwise return a fixed value to
    be ignored later.
    """
    current_principal = util.get_current_principal()
    if current_principal == normalize_principal(principal):
        return None
    else:
        return MAGIC_VALUE

class passwd(Command):
    __doc__ = _("Set a user's password.")

    takes_args = (
        Str('principal', validate_principal,
            cli_name='user',
            label=_('User name'),
            primary_key=True,
            autofill=True,
            default_from=lambda: util.get_current_principal(),
            normalizer=lambda value: normalize_principal(value),
        ),
        Password('password',
                 label=_('New Password'),
        ),
        Password('current_password',
                 label=_('Current Password'),
                 confirm=False,
                 default_from=lambda principal: get_current_password(principal),
                 autofill=True,
                 sortorder=-1,
        ),
    )

    has_output = output.standard_value
    msg_summary = _('Changed password for "%(value)s"')

    def execute(self, principal, password, current_password):
        """
        Execute the passwd operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param principal: The login name or principal of the user
        :param password: the new password
        :param current_password: the existing password, if applicable
        """
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.find_entry_by_attr(
            'krbprincipalname', principal, 'posixaccount', [''],
            DN(api.env.container_user, api.env.basedn)
        )

        if principal == getattr(context, 'principal') and \
            current_password == MAGIC_VALUE:
            # No cheating
            self.log.warn('User attempted to change password using magic value')
            raise errors.ACIError(info=_('Invalid credentials'))

        if current_password == MAGIC_VALUE:
            ldap.modify_password(dn, password)
        else:
            ldap.modify_password(dn, password, current_password)

        return dict(
            result=True,
            value=principal,
        )

api.register(passwd)
