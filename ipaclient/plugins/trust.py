# Authors:
#     Alexander Bokovoy <abokovoy@redhat.com>
#     Martin Kosek <mkosek@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

from ipaclient.frontend import MethodOverride
from ipalib.plugable import Registry

register = Registry()


@register(override=True, no_fail=True)
class trust_add(MethodOverride):
    def interactive_prompt_callback(self, kw):
        """
        Also ensure that realm_admin is prompted for if --admin or
        --trust-secret is not specified when 'ipa trust-add' is run on the
        system.

        Also ensure that realm_passwd is prompted for if --password or
        --trust-secret is not specified when 'ipa trust-add' is run on the
        system.
        """

        trust_secret = kw.get('trust_secret')
        realm_admin = kw.get('realm_admin')
        realm_passwd = kw.get('realm_passwd')

        if trust_secret is None:
            if realm_admin is None:
                kw['realm_admin'] = self.prompt_param(
                           self.params['realm_admin'])

            if realm_passwd is None:
                kw['realm_passwd'] = self.Backend.textui.prompt_password(
                           self.params['realm_passwd'].label, confirm=False)
