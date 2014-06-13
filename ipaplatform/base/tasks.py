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

    def restore_context(self, filepath):
        """
        Restore SELinux security context on the given filepath.

        No return value expected.
        """

        return

    def backup_and_replace_hostname(self, fstore, statestore, hostname):
        """
        Backs up the current hostname in the statestore (so that it can be
        restored by the restore_network_configuration platform task).

        Makes sure that new hostname (passed via hostname argument) is set
        as a new pemanent hostname for this host.

        No return value expected.
        """

        return

    def insert_ca_cert_into_systemwide_ca_store(self, path):
        """
        Adds the CA certificate located at 'path' to the systemwide CA store
        (if available on the platform).

        Returns True if the operation succeeded, False otherwise.
        """

        return True

    def remove_ca_cert_from_systemwide_ca_store(self, path):
        """
        Removes the CA certificate located at 'path' from the systemwide CA
        store (if available on the platform).

        Returns True if the operation succeeded, False otherwise.
        """

        return True

    def get_svc_list_file(self):
        """
        Returns the path to the IPA service list file.
        """

        return paths.SVC_LIST_FILE

    def check_selinux_status(self):
        """
        Checks if SELinux is available on the platform. If it is, this task
        also makes sure that restorecon tool is available.

        If SELinux is available, but restorcon tool is not installed, raises
        an RuntimeError, which suggest installing the package containing
        restorecon and rerunning the installation.
        """

        return

    def restore_network_configuration(self, fstore, statestore):
        """
        Restores the original hostname as backed up in the
        backup_and_replace_hostname platform task.
        """

        return

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        """
        Restores the pre-ipa-client configuration that was modified by the
        following platform tasks:
            modify_nsswitch_pam_stack
            modify_pam_to_use_krb5
        """

        return

    def set_nisdomain(self, nisdomain):
        """
        Sets the NIS domain name to 'nisdomain'.
        """

        return

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore):
        """
        If sssd flag is true, configure pam and nsswtich so that SSSD is used
        for retrieving user information and authentication.

        Otherwise, configure pam and nsswitch to leverage pure LDAP.
        """

        return

    def modify_pam_to_use_krb5(self, statestore):
        """
        Configure pam stack to allow kerberos authentication.
        """

        return

task_namespace = BaseTaskNamespace()
