# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2011-2014  Red Hat
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

'''
This module contains default platform-specific implementations of system tasks.
'''

from ipaplatform.paths import paths


# restore context default implementation  that does nothing
def restore_context(filepath):
    return


# Default implementation of backup and replace hostname that does nothing
def backup_and_replace_hostname(fstore, statestore, hostname):
    return


def insert_ca_cert_into_systemwide_ca_store(path):
    return True


def remove_ca_cert_from_systemwide_ca_store(path):
    return True


def get_svc_list_file():
    return paths.SVC_LIST_FILE


# See if SELinux is enabled and /usr/sbin/restorecon is installed.
# Default to a no-op. Those platforms that support SELinux should
# implement this function.
def check_selinux_status():
    return
