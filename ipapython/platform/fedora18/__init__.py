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
    'restore_network_configuration', 'timedate_services', 'FIREFOX_EXEC',
    'FIREFOX_INSTALL_DIRS', 'FIREFOX_PREFERENCES_REL_PATH']

# Just copy a referential list of timedate services
timedate_services = list(base.timedate_services)

authconfig = fedora16.authconfig
service = fedora16.service
knownservices = fedora16.knownservices
restore_context = fedora16.restore_context
check_selinux_status = fedora16.check_selinux_status

# Firefox paths
FIREFOX_EXEC = base.FIREFOX_EXEC
FIREFOX_INSTALL_DIRS = base.FIREFOX_INSTALL_DIRS
FIREFOX_PREFERENCES_REL_PATH = base.FIREFOX_PREFERENCES_REL_PATH
