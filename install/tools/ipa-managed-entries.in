#!/usr/bin/python3
# Authors: Jr Aquino <jr.aquino@citrix.com>
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
#

from __future__ import print_function

import logging
import os
import re
import sys
from optparse import OptionParser  # pylint: disable=deprecated-module

from ipaplatform.paths import paths
from ipapython import config
from ipaserver.install import installutils
from ipalib import api, errors
from ipapython.ipa_log_manager import standard_logging_setup
from ipapython.dn import DN

logger = logging.getLogger(os.path.basename(__file__))


def parse_options():
    usage = "%prog [options] <status|enable|disable>\n"
    usage += "%prog [options]\n"
    parser = OptionParser(usage=usage, formatter=config.IPAFormatter())

    parser.add_option("-d", "--debug", action="store_true", dest="debug",
                      help="Display debugging information about the update(s)")
    parser.add_option("-e", "--entry", dest="managed_entry",
                      default=None, type="string",
                      help="DN for the Managed Entry Definition")
    parser.add_option("-l", "--list", dest="list_managed_entries",
                      action="store_true",
                      help="List available Managed Entries")
    parser.add_option("-p", "--password", dest="dirman_password",
                      help="Directory Manager password")

    options, args = parser.parse_args()

    return options, args

def get_dirman_password():
    """Prompt the user for the Directory Manager password and verify its
       correctness.
    """
    password = installutils.read_password("Directory Manager", confirm=False,
        validate=True)

    return password

def main():
    retval = 0
    def_dn = None

    installutils.check_server_configuration()

    options, args = parse_options()

    if options.list_managed_entries:
        pass
    elif len(args) != 1:
        sys.exit("You must specify an action, either status, enable or disable")
    elif args[0] != "enable" and args[0] != "disable" and args[0] != "status":
        sys.exit("Unrecognized action [" + args[0] + "]")
    standard_logging_setup(None, debug=options.debug)

    api.bootstrap(
        context='cli',
        in_server=True,
        debug=options.debug,
        confdir=paths.ETC_IPA)
    api.finalize()
    api.Backend.ldap2.connect(bind_pw=options.dirman_password)

    managed_entry_definitions_dn = DN(
        ('cn', 'Definitions'),
        ('cn', 'Managed Entries'),
        ('cn', 'etc'),
        api.env.basedn
    )

    filter = '(objectClass=extensibleObject)'

    if options.list_managed_entries:
        # List available Managed Entry Plugins
        managed_entries = None
        try:
            entries = api.Backend.ldap2.get_entries(
                managed_entry_definitions_dn, api.Backend.ldap2.SCOPE_SUBTREE, filter)
        except Exception as e:
            logger.debug("Search for managed entries failed: %s", str(e))
            sys.exit("Unable to find managed entries at %s" % managed_entry_definitions_dn)
        managed_entries = [entry.single_value['cn'] for entry in entries]
        if managed_entries:
            print("Available Managed Entry Definitions:")
            for managed_entry in managed_entries:
                print(managed_entry)
        retval = 0
        sys.exit()

    if not options.managed_entry:
        sys.exit("\nYou must specify a managed entry definition")
    else:
        def_dn = DN(('cn', options.managed_entry), managed_entry_definitions_dn)

        disabled = True
        try:
            entry = api.Backend.ldap2.get_entry(def_dn)
            disable_attr = '(objectclass=disable)'
            try:
                org_filter = entry.single_value.get('originfilter')
                disabled = re.search(r'%s' % disable_attr, org_filter)
            except KeyError:
                sys.exit("%s is not a valid Managed Entry" % def_dn)
        except errors.NotFound:
            sys.exit("%s is not a valid Managed Entry" % def_dn)
        except errors.ExecutionError as lde:
            print("An error occurred while talking to the server.")
            print(lde)

        if args[0] == "status":
            if not disabled:
                print("Plugin Enabled")
            else:
                print("Plugin Disabled")
            return 0

        if args[0] == "enable":
            try:
                if not disabled:
                    print("Plugin already Enabled")
                    retval = 2
                else:
                    # Remove disable_attr from filter
                    enable_attr = org_filter.replace(disable_attr, '')
                    #enable_attr = {'originfilter': enable_attr}
                    entry['originfilter'] = [enable_attr]
                    api.Backend.ldap2.update_entry(entry)
                    print("Enabling Plugin")
                    retval = 0
            except errors.NotFound:
                print("Enabling Plugin")
            except errors.ExecutionError as lde:
                print("An error occurred while talking to the server.")
                print(lde)
                retval = 1

        elif args[0] == "disable":
            # Set originFilter to objectclass=disabled
            # In future we should we should dedicate an attribute for enabling/
            # disabling.
            try:
                if disabled:
                    print("Plugin already disabled")
                    retval = 2
                else:
                    if org_filter[:2] == '(&' and org_filter[-1] == ')':
                        disable_attr = org_filter[:2] + disable_attr + org_filter[2:]
                    else:
                        disable_attr = '(&%s(%s))' % (disable_attr, org_filter)
                    entry['originfilter'] = [disable_attr]
                    api.Backend.ldap2.update_entry(entry)
                    print("Disabling Plugin")
            except errors.NotFound:
                print("Plugin is already disabled")
                retval = 2
            except errors.DatabaseError as dbe:
                print("An error occurred while talking to the server.")
                print(dbe)
                retval = 1
            except errors.ExecutionError as lde:
                print("An error occurred while talking to the server.")
                print(lde)
                retval = 1

        else:
            retval = 1

    api.Backend.ldap2.disconnect()

    return retval

if __name__ == '__main__':
    if not os.geteuid() == 0:
        sys.exit("\nMust be run as root\n")
    installutils.run_script(main, operation_name='ipa-managed-entries')
