# Authors: Tomas Babej <tbabej@redhat.com>
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
#

import krbV
import sys

from ipalib import api
from ipalib import errors
from ipapython import admintool
from ipapython.dn import DN
from ipapython.ipa_log_manager import log_mgr
from ipaserver.plugins.ldap2 import ldap2


class MigrateWinsync(admintool.AdminTool):
    """
    Tool to migrate winsync users.
    """

    command_name = 'ipa-migrate-winsync'
    usage = "ipa-migrate-winsync"
    description = (
        "This tool creates user ID overrides for all the users "
        "that were previously synced from AD domain using the "
        "winsync replication agreement. It requires that trust "
        "with the AD forest has already been established and "
        "the users in question are resolvable using SSSD. "
        "For more information, see `man ipa-migrate-winsync`."
        )

    def run(self):
        super(MigrateWinsync, self).run()

        # Finalize API
        api.bootstrap(in_server=True, context='server')
        api.finalize()

        # Setup LDAP connection
        try:
            ctx = krbV.default_context()
            ccache = ctx.default_ccache()
        except krbV.Krb5Error, e:
            sys.exit("Must have Kerberos credentials to migrate Winsync users.")

        try:
            api.Backend.ldap2.connect(ccache)
            self.ldap = api.Backend.ldap2
        except errors.ACIError, e:
            sys.exit("Outdated Kerberos credentials. Use kdestroy and kinit to update your ticket.")
        except errors.DatabaseError, e:
            sys.exit("Cannot connect to the LDAP database. Please check if IPA is running.")
