# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
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
This module contains default Fedora-specific implementations of system tasks.
'''

import os
import ipautil

from ipaplatform.fedora.authconfig import FedoraAuthConfig
from ipaplatform.base.tasks import *


def restore_context(filepath, restorecon='/sbin/restorecon'):
    """
    restore security context on the file path
    SELinux equivalent is /path/to/restorecon <filepath>

    restorecon's return values are not reliable so we have to
    ignore them (BZ #739604).

    ipautil.run() will do the logging.
    """
    try:
        if os.path.exists('/usr/sbin/selinuxenabled'):
            ipautil.run(["/usr/sbin/selinuxenabled"])
        else:
            # No selinuxenabled, no SELinux
            return
    except ipautil.CalledProcessError:
        # selinuxenabled returns 1 if not enabled
        return

    if (os.path.exists(restorecon)):
        ipautil.run([restorecon, filepath], raiseonerr=False)


def check_selinux_status(restorecon='/sbin/restorecon'):
    """
    We don't have a specific package requirement for policycoreutils
    which provides restorecon. This is because we don't require
    SELinux on client installs. However if SELinux is enabled then
    this package is required.

    This function returns nothing but may raise a Runtime exception
    if SELinux is enabled but restorecon is not available.
    """
    try:
        if os.path.exists('/usr/sbin/selinuxenabled'):
            ipautil.run(["/usr/sbin/selinuxenabled"])
        else:
            # No selinuxenabled, no SELinux
            return
    except ipautil.CalledProcessError:
        # selinuxenabled returns 1 if not enabled
        return

    if not os.path.exists(restorecon):
        raise RuntimeError('SELinux is enabled but %s does not exist.\n'
                           'Install the policycoreutils package and start the '
                           'installation again.' % restorecon)


def restore_pre_ipa_client_configuration(fstore, statestore,
                                         was_sssd_installed,
                                         was_sssd_configured):

    auth_config = FedoraAuthConfig()
    if statestore.has_state('authconfig'):
        # disable only those configurations that we enabled during install
        for conf in ('ldap', 'krb5', 'sssd', 'sssdauth', 'mkhomedir'):
            cnf = statestore.restore_state('authconfig', conf)
            # Do not disable sssd, as this can cause issues with its later
            # uses. Remove it from statestore however, so that it becomes
            # empty at the end of uninstall process.
            if cnf and conf != 'sssd':
                auth_config.disable(conf)
    else:
        # There was no authconfig status store
        # It means the code was upgraded after original install
        # Fall back to old logic
        auth_config.disable("ldap")
        auth_config.disable("krb5")
        if not(was_sssd_installed and was_sssd_configured):
            # Only disable sssdauth. Disabling sssd would cause issues
            # with its later uses.
            auth_config.disable("sssdauth")
        auth_config.disable("mkhomedir")

    auth_config.execute()


def set_nisdomain(nisdomain):
    # Let authconfig setup the permanent configuration
    auth_config = FedoraAuthConfig()
    auth_config.add_parameter("nisdomain", nisdomain)
    auth_config.execute()


def modify_nsswitch_pam_stack(sssd, mkhomedir, statestore):
    auth_config = FedoraAuthConfig()

    if sssd:
        statestore.backup_state('authconfig', 'sssd', True)
        statestore.backup_state('authconfig', 'sssdauth', True)
        auth_config.enable("sssd")
        auth_config.enable("sssdauth")
    else:
        statestore.backup_state('authconfig', 'ldap', True)
        auth_config.enable("ldap")
        auth_config.enable("forcelegacy")

    if mkhomedir:
        statestore.backup_state('authconfig', 'mkhomedir', True)
        auth_config.enable("mkhomedir")

    auth_config.execute()


def modify_pam_to_use_krb5(statestore):
    auth_config = FedoraAuthConfig()
    statestore.backup_state('authconfig', 'krb5', True)
    auth_config.enable("krb5")
    auth_config.add_option("nostart")
    auth_config.execute()
