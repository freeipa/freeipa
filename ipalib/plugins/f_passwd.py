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

from ipalib import frontend
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types
import krbV

def get_current_principal():
    try:
        return krbV.default_context().default_ccache().principal().name
    except krbV.Krb5Error:
        #TODO: do a kinit
        print "Unable to get kerberos principal"
        return None

class passwd(frontend.Command):
    'Edit existing password policy.'
    takes_args = (
        Param('principal',
            cli_name='user',
            primary_key=True,
            default_from=get_current_principal,
        ),
    )
    def execute(self, principal, **kw):
        """
        Execute the passwd operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param param uid: The login name of the user being updated.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap

        if principal.find('@') < 0:
            u = principal.split('@')
            if len(u) > 2 or len(u) == 0:
                print "Invalid user name (%s)" % principal
            if len(u) == 1:
                principal = principal+"@"+self.api.env.realm
            else:
                principal = principal

        dn = ldap.find_entry_dn("krbprincipalname", principal, "person")

        # FIXME: we need a way to prompt for passwords using getpass
        kw['newpass'] = "password"

        return ldap.modify_password(dn, **kw)

    def output_for_cli(self, ret):
        if ret:
            print "Password change successful"

api.register(passwd)
