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


class BaseTaskNamespace(object):
    # restore context default implementation  that does nothing
    def restore_context(self, filepath):
        return

    # Default implementation of backup and replace hostname that does nothing
    def backup_and_replace_hostname(self, fstore, statestore, hostname):
        return

    def insert_ca_cert_into_systemwide_ca_store(self, path):
        return True

    def remove_ca_cert_from_systemwide_ca_store(self, path):
        return True

    def get_svc_list_file(self):
        return paths.SVC_LIST_FILE

    # See if SELinux is enabled and /usr/sbin/restorecon is installed.
    # Default to a no-op. Those platforms that support SELinux should
    # implement this function.
    def check_selinux_status(self):
        return

    def restore_network_configuration(self, fstore, statestore):
        return

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        return

    def set_nisdomain(self, nisdomain):
        return

    def modify_nsswitch_pam_stack(sssd, mkhomedir, statestore):
        return

    def modify_pam_to_use_krb5(statestore):
        return

task_namespace = BaseTaskNamespace()
