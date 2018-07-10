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

from __future__ import absolute_import

import logging

from pkg_resources import parse_version

from ipaplatform.paths import paths
from ipapython import ipautil

logger = logging.getLogger(__name__)


class BaseTaskNamespace(object):

    def restore_context(self, filepath, force=False):
        """Restore SELinux security context on the given filepath.

        No return value expected.
        """
        raise NotImplementedError()

    def backup_hostname(self, fstore, statestore):
        """
        Backs up the current hostname in the statestore (so that it can be
        restored by the restore_hostname platform task).

        No return value expected.
        """

        raise NotImplementedError()

    def reload_systemwide_ca_store(self):
        """
        Reloads the systemwide CA store.

        Returns True if the operation succeeded, False otherwise.
        """

        raise NotImplementedError()

    def insert_ca_certs_into_systemwide_ca_store(self, ca_certs):
        """
        Adds CA certificates from 'ca_certs' to the systemwide CA store
        (if available on the platform).

        Returns True if the operation succeeded, False otherwise.
        """

        raise NotImplementedError()

    def remove_ca_certs_from_systemwide_ca_store(self):
        """
        Removes IPA CA certificates from the systemwide CA store
        (if available on the platform).

        Returns True if the operation succeeded, False otherwise.
        """

        raise NotImplementedError()

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

        raise NotImplementedError()

    def check_ipv6_stack_enabled(self):
        """Check whether IPv6 kernel module is loaded"""

        raise NotImplementedError()

    def restore_hostname(self, fstore, statestore):
        """
        Restores the original hostname as backed up in the
        backup_hostname platform task.
        """

        raise NotImplementedError()

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        """
        Restores the pre-ipa-client configuration that was modified by the
        following platform tasks:
            modify_nsswitch_pam_stack
            modify_pam_to_use_krb5
        """

        raise NotImplementedError()

    def set_nisdomain(self, nisdomain):
        """
        Sets the NIS domain name to 'nisdomain'.
        """

        raise NotImplementedError()

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore,
                                  sudo=True):
        """
        If sssd flag is true, configure pam and nsswitch so that SSSD is used
        for retrieving user information and authentication.

        Otherwise, configure pam and nsswitch to leverage pure LDAP.
        """

        raise NotImplementedError()

    def modify_pam_to_use_krb5(self, statestore):
        """
        Configure pam stack to allow kerberos authentication.
        """

        raise NotImplementedError()

    def is_nosssd_supported(self):
        """
        Check if the flag --no-sssd is supported for client install.
        """

        return True

    def backup_auth_configuration(self, path):
        """
        Create backup of access control configuration.
        :param path: store the backup here. This will be passed to
        restore_auth_configuration as well.
        """
        raise NotImplementedError()

    def restore_auth_configuration(self, path):
        """
        Restore backup of access control configuration.
        :param path: restore the backup from here.
        """
        raise NotImplementedError()

    def migrate_auth_configuration(self, statestore):
        """
        Migrate pam stack configuration to authselect.
        """
        pass

    def set_selinux_booleans(self, required_settings, backup_func=None):
        """Set the specified SELinux booleans

        :param required_settings: A dictionary mapping the boolean names
                                  to desired_values.
                                  The desired value can be 'on' or 'off',
                                  or None to leave the setting unchanged.

        :param backup_func: A function called for each boolean with two
                            arguments: the name and the previous value

        If SELinux is disabled, return False; on success returns True.

        If setting the booleans fails,
        an ipapython.errors.SetseboolError is raised.
        """

        raise NotImplementedError()

    @staticmethod
    def parse_ipa_version(version):
        """
        :param version: textual version
        :return: object implementing proper __cmp__ method for version compare
        """
        return parse_version(version)

    def set_hostname(self, hostname):
        """
        Set hostname for the system

        No return value expected, raise CalledProcessError when error occurred
        """
        raise NotImplementedError()

    def configure_httpd_service_ipa_conf(self):
        """Configure httpd service to work with IPA"""
        raise NotImplementedError()

    def configure_http_gssproxy_conf(self, ipauser):
        raise NotImplementedError()

    def remove_httpd_service_ipa_conf(self):
        """Remove configuration of httpd service of IPA"""
        raise NotImplementedError()

    def configure_httpd_wsgi_conf(self):
        """Configure WSGI for correct Python version"""
        raise NotImplementedError()

    def is_fips_enabled(self):
        return False

    def add_user_to_group(self, user, group):
        logger.debug('Adding user %s to group %s', user, group)
        args = [paths.USERMOD, '-a', '-G', group, user]
        try:
            ipautil.run(args)
            logger.debug('Done adding user to group')
        except ipautil.CalledProcessError as e:
            logger.debug('Failed to add user to group: %s', e)

    def setup_httpd_logging(self):
        raise NotImplementedError()


tasks = BaseTaskNamespace()
