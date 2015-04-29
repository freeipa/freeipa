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

DEFAULT_TRUST_VIEW_NAME = u'Default Trust View'


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

    @classmethod
    def add_options(cls, parser):
        """
        Adds command line options to the tool.
        """
        super(MigrateWinsync, cls).add_options(parser)

        parser.add_option(
            "--realm",
            dest="realm",
            help="The AD realm the winsynced users belong to")
        parser.add_option(
            "-U", "--unattended",
            dest="interactive",
            action="store_false",
            default=True,
            help="Never prompt for user input")

    def validate_options(self):
        """
        Validates the options passed by the user:
            - Checks that trust has been established with
              the realm passed via --realm option
        """

        super(MigrateWinsync, self).validate_options()

        if self.options.realm is None:
            raise admintool.ScriptError(
                "AD realm the winsynced users belong to needs to be "
                "specified.")
        else:
            try:
                api.Command['trust_show'](unicode(self.options.realm))
            except errors.NotFound:
                raise admintool.ScriptError(
                    "Trust with the given realm %s could not be found. "
                    "Please establish the trust prior to migration."
                    % self.options.realm)
            except Exception as e:
                raise admintool.ScriptError(
                    "An error occured during detection of the established "
                    "trust with %s: %s" % (self.options.realm, str(e)))

    def create_id_user_override(self, entry):
        """
        Creates ID override corresponding to this user entry.
        """

        user_identifier = u"%s@%s" % (entry['uid'][0], self.options.realm)

        kwargs = {
            'uid': entry['uid'][0],
            'uidnumber': entry['uidnumber'][0],
            'gidnumber': entry['gidnumber'][0],
            'gecos': entry['gecos'][0],
            'loginshell': entry['loginshell'][0]
        }

        try:
            result = api.Command['idoverrideuser_add'](
                DEFAULT_TRUST_VIEW_NAME,
                user_identifier,
                **kwargs
            )
        except Exception as e:
            self.log.warning("Migration failed: %s (%s)"
                             % (user_identifier, str(e)))
        else:
            self.log.debug("Migrated: %s" % user_identifier)

    def find_winsync_users(self):
        """
        Finds all users that were mirrored from AD using winsync.
        """

        user_filter = "(&(objectclass=ntuser)(ntUserDomainId=*))"
        user_base = DN(api.env.container_user, api.env.basedn)
        entries, _ = self.ldap.find_entries(
            filter=user_filter,
            base_dn=user_base,
            paged_search=True)

        for entry in entries:
            self.log.debug("Discovered entry: %s" % entry)

        return entries

    def run(self):
        super(MigrateWinsync, self).run()

        # Finalize API
        api.bootstrap(in_server=True, context='server')
        api.finalize()

        # Setup LDAP connection
        try:
            ctx = krbV.default_context()
            ccache = ctx.default_ccache()
            api.Backend.ldap2.connect(ccache)
            self.ldap = api.Backend.ldap2
        except krbV.Krb5Error, e:
            sys.exit("Must have Kerberos credentials to migrate Winsync users.")
        except errors.ACIError, e:
            sys.exit("Outdated Kerberos credentials. Use kdestroy and kinit to update your ticket.")
        except errors.DatabaseError, e:
            sys.exit("Cannot connect to the LDAP database. Please check if IPA is running.")

        # Create ID overrides replacing the user winsync entries
        entries = self.find_winsync_users()
        for entry in entries:
            self.create_id_user_override(entry)
