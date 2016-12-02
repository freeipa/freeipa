# Authors:
#   Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib import api, errors
from ipalib import Str
from ipalib import Object, Command
from ipalib import _
from ipalib.plugable import Registry
from ipalib.constants import ANON_USER
from ipapython.dn import DN

__doc__ = _("""
Kerberos pkinit options

Enable or disable anonymous pkinit using the principal
WELLKNOWN/ANONYMOUS@REALM. The server must have been installed with
pkinit support.

EXAMPLES:

 Enable anonymous pkinit:
  ipa pkinit-anonymous enable

 Disable anonymous pkinit:
  ipa pkinit-anonymous disable

For more information on anonymous pkinit see:

http://k5wiki.kerberos.org/wiki/Projects/Anonymous_pkinit
""")

register = Registry()

@register()
class pkinit(Object):
    """
    PKINIT Options
    """
    object_name = _('pkinit')

    label=_('PKINIT')


def valid_arg(ugettext, action):
    """
    Accepts only Enable/Disable.
    """
    a = action.lower()
    if a != 'enable' and a != 'disable':
        raise errors.ValidationError(
            name='action',
            error=_('Unknown command %s') % action
        )

@register()
class pkinit_anonymous(Command):
    __doc__ = _('Enable or Disable Anonymous PKINIT.')

    princ_name = '%s@%s' % (ANON_USER, api.env.realm)
    default_dn = DN(('krbprincipalname', princ_name), ('cn', api.env.realm), ('cn', 'kerberos'), api.env.basedn)

    takes_args = (
        Str('action', valid_arg),
    )

    def execute(self, action, **options):
        ldap = self.api.Backend.ldap2
        set_lock = False
        lock = None

        entry_attrs = ldap.get_entry(self.default_dn, ['nsaccountlock'])

        if 'nsaccountlock' in entry_attrs:
            lock = entry_attrs['nsaccountlock'][0].lower()

        if action.lower() == 'enable':
            if lock == 'true':
                set_lock = True
                lock = None
        elif action.lower() == 'disable':
            if lock != 'true':
                set_lock = True
                lock = 'TRUE'

        if set_lock:
            entry_attrs['nsaccountlock'] = lock
            ldap.update_entry(entry_attrs)

        return dict(result=True)
