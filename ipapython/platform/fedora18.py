# Author: Martin Kosek <mkosek@redhat.com>
#
# Copyright (C) 2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import stat
import sys
import socket
import os

from ipapython import ipautil
from ipapython.platform import fedora16, base

# All what we allow exporting directly from this module
# Everything else is made available through these symbols when they are
# directly imported into ipapython.services:
# authconfig -- class reference for platform-specific implementation of
#               authconfig(8)
# service    -- class reference for platform-specific implementation of a
#               PlatformService class
# knownservices -- factory instance to access named services IPA cares about,
#                  names are ipapython.services.wellknownservices
# backup_and_replace_hostname -- platform-specific way to set hostname and
#                                make it persistent over reboots
# restore_network_configuration -- platform-specific way of restoring network
#                                  configuration (e.g. static hostname)
# restore_context -- platform-sepcific way to restore security context, if
#                    applicable
# check_selinux_status -- platform-specific way to see if SELinux is enabled
#                         and restorecon is installed.
__all__ = ['authconfig', 'service', 'knownservices',
    'backup_and_replace_hostname', 'restore_context', 'check_selinux_status',
    'restore_network_configuration', 'timedate_services']

# Just copy a referential list of timedate services
timedate_services = list(base.timedate_services)

def backup_and_replace_hostname(fstore, statestore, hostname):
    old_hostname = socket.gethostname()
    try:
        ipautil.run(['/bin/hostname', hostname])
    except ipautil.CalledProcessError, e:
        print >>sys.stderr, "Failed to set this machine hostname to %s (%s)." % (hostname, str(e))

    filepath = '/etc/hostname'
    if os.path.exists(filepath):
        # read old hostname
        with open(filepath, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    # skip comment or empty line
                    continue
                old_hostname = line
                break
        fstore.backup_file(filepath)

    with open(filepath, 'w') as f:
        f.write("%s\n" % hostname)
    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    os.chown(filepath, 0, 0)
    restore_context(filepath)

    # store old hostname
    statestore.backup_state('network', 'hostname', old_hostname)

def restore_network_configuration(fstore, statestore):
    old_filepath = '/etc/sysconfig/network'
    old_hostname = statestore.get_state('network', 'hostname')
    hostname_was_configured = False

    if fstore.has_file(old_filepath):
        # This is Fedora >=18 instance that was upgraded from previous
        # Fedora version which held network configuration
        # in /etc/sysconfig/network
        old_filepath_restore = '/etc/sysconfig/network.ipabkp'
        fstore.restore_file(old_filepath, old_filepath_restore)
        print "Deprecated configuration file '%s' was restored to '%s'" \
                % (old_filepath, old_filepath_restore)
        hostname_was_configured = True

    filepath = '/etc/hostname'
    if fstore.has_file(filepath):
        fstore.restore_file(filepath)
        hostname_was_configured = True

    if not hostname_was_configured and old_hostname:
        # hostname was not configured before but was set by IPA. Delete
        # /etc/hostname to restore previous configuration
        try:
            os.remove(filepath)
        except OSError:
            pass

authconfig = fedora16.authconfig
service = fedora16.service
knownservices = fedora16.knownservices
restore_context = fedora16.restore_context
check_selinux_status = fedora16.check_selinux_status
