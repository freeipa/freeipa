# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Martin Kosek <mkosek@redhat.com>
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
import shutil
import stat
import socket
import sys

from subprocess import CalledProcessError

from ipapython.ipa_log_manager import root_logger
from ipapython import ipautil

from ipaplatform.paths import paths
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


def check_selinux_status(restorecon=paths.RESTORECON):
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


def insert_ca_cert_into_systemwide_ca_store(cacert_path):
    # Add the 'ipa-' prefix to cert name to avoid name collisions
    cacert_name = os.path.basename(cacert_path)
    new_cacert_path = os.path.join(paths.SYSTEMWIDE_CA_STORE,
                                   'ipa-%s' % cacert_name)

    # Add the CA to the systemwide CA trust database
    try:
        shutil.copy(cacert_path, new_cacert_path)
        ipautil.run(['/usr/bin/update-ca-trust'])
    except OSError, e:
        root_logger.info("Failed to copy %s to %s", cacert_path,
                         new_cacert_path)
    except CalledProcessError, e:
        root_logger.info("Failed to add CA to the systemwide "
                         "CA trust database: %s", e)
    else:
        root_logger.info('Added the CA to the systemwide CA trust database.')
        return True

    return False


def remove_ca_cert_from_systemwide_ca_store(cacert_path):
    # Derive the certificate name in the store
    cacert_name = os.path.basename(cacert_path)
    new_cacert_path = os.path.join(paths.SYSTEMWIDE_CA_STORE,
                                   'ipa-%s' % cacert_name)

    # Remove CA cert from systemwide store
    if os.path.exists(new_cacert_path):
        try:
            os.remove(new_cacert_path)
            ipautil.run(['/usr/bin/update-ca-trust'])
        except OSError, e:
            root_logger.error('Could not remove: %s, %s', new_cacert_path, e)
            return False
        except CalledProcessError, e:
            root_logger.error('Could not update systemwide CA trust '
                              'database: %s', e)
            return False
        else:
            root_logger.info('Systemwide CA database updated.')

    return True


def backup_and_replace_hostname(fstore, statestore, hostname):
    old_hostname = socket.gethostname()
    try:
        ipautil.run(['/bin/hostname', hostname])
    except ipautil.CalledProcessError, e:
        error_message = ("Failed to set this machine hostname to %s (%s)."
                         % (hostname, e))
        root_logger.error(error_message)
        print >>sys.stderr, error_message

    filepath = '/etc/hostname'
    if os.path.exists(filepath):
        # read old hostname
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    # skip comment or empty line
                    continue
                old_hostname = line
                break
        fstore.backup_file(filepath)

    with open(filepath, 'w') as f:
        f.write("%s\n" % hostname)
    os.chmod(filepath,
             stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
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
