# Author: Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013 Red Hat
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

import shutil
import os

from subprocess import CalledProcessError

from ipapython.ipa_log_manager import root_logger
from ipapython.ipautil import run

from ipapython.platform import fedora18, base

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
# insert_ca_cert_into_systemwide_ca_store - platform-specific way to insert our
#                                           CA certificate into the systemwide
#                                           CA store
# remove_ca_cert_from_systemwide_ca_store - platform-specific way to remove our
#                                           CA certificate from the systemwide
#                                           CA store


__all__ = ['authconfig', 'service', 'knownservices',
    'backup_and_replace_hostname', 'restore_context', 'check_selinux_status',
    'restore_network_configuration', 'timedate_services',
    'insert_ca_cert_into_systemwide_ca_store',
    'remove_ca_cert_from_systemwide_ca_store']

# Just copy a referential list of timedate services
timedate_services = list(base.timedate_services)

backup_and_replace_hostname = fedora18.backup_and_replace_hostname
restore_network_configuration = fedora18.restore_network_configuration
authconfig = fedora18.authconfig
service = fedora18.service
knownservices = fedora18.knownservices
restore_context = fedora18.restore_context
check_selinux_status = fedora18.check_selinux_status

systemwide_ca_store = '/etc/pki/ca-trust/source/anchors/'


def insert_ca_cert_into_systemwide_ca_store(cacert_path):
    # Add the 'ipa-' prefix to cert name to avoid name collisions
    cacert_name = os.path.basename(cacert_path)
    new_cacert_path = os.path.join(systemwide_ca_store, 'ipa-%s' % cacert_name)

    # Add the CA to the systemwide CA trust database
    try:
        shutil.copy(cacert_path, new_cacert_path)
        run(['/usr/bin/update-ca-trust'])
    except OSError, e:
        root_logger.info("Failed to copy %s to %s" % (cacert_path,
                                                      new_cacert_path))
    except CalledProcessError, e:
        root_logger.info("Failed to add CA to the systemwide "
                         "CA trust database: %s" % str(e))
    else:
        root_logger.info('Added the CA to the systemwide CA trust database.')
        return True

    return False


def remove_ca_cert_from_systemwide_ca_store(cacert_path):
    # Derive the certificate name in the store
    cacert_name = os.path.basename(cacert_path)
    new_cacert_path = os.path.join(systemwide_ca_store, 'ipa-%s' % cacert_name)

    # Remove CA cert from systemwide store
    if os.path.exists(new_cacert_path):
        try:
            os.remove(new_cacert_path)
            run(['/usr/bin/update-ca-trust'])
        except OSError, e:
            root_logger.error('Could not remove: %s, %s'
                               % (new_cacert_path, str(e)))
            return False
        except CalledProcessError, e:
            root_logger.error('Could not update systemwide CA trust '
                              'database: %s' % str(e))
            return False
        else:
            root_logger.info('Systemwide CA database updated.')

    return True
