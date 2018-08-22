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

from __future__ import absolute_import

import logging

import gssapi
import sys

import six

from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipapython import admintool
from ipapython.dn import DN
from ipapython.ipautil import realm_to_suffix, posixify
from ipaserver.install import replication, installutils

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

DEFAULT_TRUST_VIEW_NAME = u'Default Trust View'


class WinsyncMigrate(admintool.AdminTool):
    """
    Tool to migrate winsync users.
    """

    command_name = 'ipa-winsync-migrate'
    usage = "ipa-winsync-migrate"
    description = (
        "This tool creates user ID overrides for all the users "
        "that were previously synced from AD domain using the "
        "winsync replication agreement. It requires that trust "
        "with the AD forest has already been established and "
        "the users in question are resolvable using SSSD. "
        "For more information, see `man ipa-winsync-migrate`."
        )

    @classmethod
    def add_options(cls, parser):
        """
        Adds command line options to the tool.
        """
        super(WinsyncMigrate, cls).add_options(parser)

        parser.add_option(
            "--realm",
            dest="realm",
            help="The AD realm the winsynced users belong to")
        parser.add_option(
            "--server",
            dest="server",
            help="The AD DC the winsync agreement is established with")
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

        super(WinsyncMigrate, self).validate_options(needs_root=True)

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

        if self.options.server is None:
            raise admintool.ScriptError(
                "The AD DC the winsync agreement is established with "
                "needs to be specified.")
        else:
            # Validate the replication agreement between given host and localhost
            try:
                manager = replication.ReplicationManager(
                    api.env.realm,
                    api.env.host,
                    None)  # Use GSSAPI instead of raw directory manager access

                replica_type = manager.get_agreement_type(self.options.server)
            except errors.ACIError as e:
                raise admintool.ScriptError(
                    "Used Kerberos account does not have privileges to access "
                    "the replication agreement info: %s" % str(e))
            except errors.NotFound as e:
                raise admintool.ScriptError(
                    "The replication agreement between %s and %s could not "
                    "be detected" % (api.env.host, self.options.server))

            # Check that the replication agreement is indeed WINSYNC
            if replica_type != replication.WINSYNC:
                raise admintool.ScriptError(
                    "Replication agreement between %s and %s is not winsync."
                    % (api.env.host, self.options.server))

            # Save the reference to the replication manager in the object
            self.manager = manager

    def delete_winsync_agreement(self):
        """
        Deletes the winsync agreement between the current master and the
        given AD server.
        """

        try:
            self.manager.delete_agreement(self.options.server)
            self.manager.delete_referral(self.options.server)

            dn = DN(('cn', self.options.server),
                    ('cn', 'replicas'),
                    ('cn', 'ipa'),
                    ('cn', 'etc'),
                    realm_to_suffix(api.env.realm))
            entries = self.manager.conn.get_entries(dn,
                                                    self.ldap.SCOPE_SUBTREE)
            if entries:
                entries.sort(key=len, reverse=True)
                for entry in entries:
                    self.ldap.delete_entry(entry)

        except Exception as e:
            raise admintool.ScriptError(
                "Deletion of the winsync agreement failed: %s" % str(e))


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
            api.Command['idoverrideuser_add'](
                DEFAULT_TRUST_VIEW_NAME,
                user_identifier,
                **kwargs
            )
        except Exception as e:
            logger.warning("Migration failed: %s (%s)",
                           user_identifier, str(e))
        else:
            logger.debug("Migrated: %s", user_identifier)

    def find_winsync_users(self):
        """
        Finds all users that were mirrored from AD using winsync.
        """

        user_filter = "(&(objectclass=ntuser)(ntUserDomainId=*))"
        user_base = DN(api.env.container_user, api.env.basedn)
        entries, _truncated = self.ldap.find_entries(
            filter=user_filter,
            base_dn=user_base,
            paged_search=True)

        for entry in entries:
            logger.debug("Discovered entry: %s", entry)

        return entries

    def migrate_memberships(self, user_entry, winsync_group_prefix,
                            object_membership_command,
                            object_info_command,
                            user_dn_attribute,
                            object_group_membership_key,
                            object_container_dn):
        """
        Migrates user memberships to theier external identities.

        All migrated users for the given object are migrated to a common
        external group which is then assigned to the given object as a
        (user) member group.
        """

        def winsync_group_name(object_entry):
            """
            Returns the generated name of group containing migrated external
            users.

            The group name is of the form:
                 "<prefix>_<object name>_winsync_external"

            Object name is converted to posix-friendly string by omitting
            and/or replacing characters. This may lead to collisions, i.e.
            if both 'trust_admins' and 'trust admin' groups have winsync
            users being migrated.
            """

            return u"{0}_{1}_winsync_external".format(
                winsync_group_prefix,
                posixify(object_entry['cn'][0])
            )

        def create_winsync_group(object_entry, suffix=0):
            """
            Creates the group containing migrated external users that were
            previously available via winsync.
            """

            name = winsync_group_name(object_entry)

            # Only non-trivial suffix is appended at the end
            if suffix != 0:
                name += str(suffix)

            try:
                api.Command['group_add'](name, external=True)
            except errors.DuplicateEntry:
                # If there is a collision, let's try again with a higher suffix
                create_winsync_group(object_entry, suffix=suffix+1)
            else:
                # In case of no collision, add the membership
                api.Command[object_membership_command](object_entry['cn'][0], group=[name])

        # Search for all objects containing the given user as a direct member
        member_filter = self.ldap.make_filter_from_attr(user_dn_attribute,
                                                        user_entry.dn)

        try:
            objects, _truncated = self.ldap.find_entries(
                member_filter,
                base_dn=object_container_dn)
        except errors.EmptyResult:
            # If there's nothing to migrate, then let's get out of here
            return

        # The external user cannot be added directly as member of the IPA
        # objects, hence we need to wrap all the external users into one
        # new external group, which will be then added to the original IPA
        # object as a member.

        for obj in objects:
            # Check for existence of winsync external group
            name = winsync_group_name(obj)
            info = api.Command[object_info_command](obj['cn'][0])['result']

            # If it was not created yet, do it now
            if name not in info.get(object_group_membership_key, []):
                create_winsync_group(obj)

            # Add the user to the external group. Membership is migrated
            # at this point.
            user_identifier = u"%s@%s" % (user_entry['uid'][0], self.options.realm)
            api.Command['group_add_member'](name, ipaexternalmember=[user_identifier])

    def migrate_group_memberships(self, user_entry):
        return self.migrate_memberships(user_entry,
            winsync_group_prefix="group",
            user_dn_attribute="member",
            object_membership_command="group_add_member",
            object_info_command="group_show",
            object_group_membership_key="member_group",
            object_container_dn=DN(api.env.container_group, api.env.basedn),
        )

    def migrate_role_memberships(self, user_entry):
        return self.migrate_memberships(user_entry,
            winsync_group_prefix="role",
            user_dn_attribute="member",
            object_membership_command="role_add_member",
            object_info_command="role_show",
            object_group_membership_key="member_group",
            object_container_dn=DN(api.env.container_rolegroup, api.env.basedn),
        )

    def migrate_hbac_memberships(self, user_entry):
        return self.migrate_memberships(user_entry,
            winsync_group_prefix="hbacrule",
            user_dn_attribute="memberuser",
            object_membership_command="hbacrule_add_user",
            object_info_command="hbacrule_show",
            object_group_membership_key="memberuser_group",
            object_container_dn=DN(api.env.container_hbac, api.env.basedn),
        )

    def migrate_selinux_memberships(self, user_entry):
        return self.migrate_memberships(user_entry,
            winsync_group_prefix="selinux",
            user_dn_attribute="memberuser",
            object_membership_command="selinuxusermap_add_user",
            object_info_command="selinuxusermap_show",
            object_group_membership_key="memberuser_group",
            object_container_dn=DN(api.env.container_selinux, api.env.basedn),
        )

    def warn_passsync(self):
        logger.warning("Migration completed. Please note that if PassSync "
                       "was configured on the given Active Directory server, "
                       "it needs to be manually removed, otherwise it may try "
                       "to reset password for accounts that are no longer "
                       "existent.")

    @classmethod
    def main(cls, argv):
        """
        Sets up API and LDAP connection for the tool, then runs the rest of
        the plumbing.
        """

        # Check if the IPA server is configured before attempting to migrate
        try:
            installutils.check_server_configuration()
        except admintool.ScriptError as e:
            sys.exit(e)

        # Finalize API
        api.bootstrap(in_server=True, context='server', confdir=paths.ETC_IPA)
        api.finalize()

        # Setup LDAP connection
        try:
            api.Backend.ldap2.connect()
            cls.ldap = api.Backend.ldap2
        except gssapi.exceptions.GSSError as e:
            sys.exit("Must have Kerberos credentials to migrate Winsync users. Error: %s" % e)
        except errors.ACIError as e:
            sys.exit("Outdated Kerberos credentials. Use kdestroy and kinit to update your ticket.")
        except errors.DatabaseError as e:
            sys.exit("Cannot connect to the LDAP database. Please check if IPA is running.")

        super(WinsyncMigrate, cls).main(argv)

    def run(self):
        super(WinsyncMigrate, self).run()

        # Stop winsync agreement with the given host
        self.delete_winsync_agreement()

        # Create ID overrides replacing the user winsync entries
        entries = self.find_winsync_users()
        for entry in entries:
            self.create_id_user_override(entry)
            self.migrate_group_memberships(entry)
            self.migrate_role_memberships(entry)
            self.migrate_hbac_memberships(entry)
            self.migrate_selinux_memberships(entry)
            self.ldap.delete_entry(entry)

        self.warn_passsync()
