# Authors: Karl MacMillan <kmacmillan@redhat.com>
#
# Copyright (C) 2007  Red Hat
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
from __future__ import absolute_import

import logging
import os
import shutil

from augeas import Augeas
from ipalib import api
from ipapython import ipautil
from ipaplatform.tasks import tasks
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython.ipautil import user_input

logger = logging.getLogger(__name__)


def __backup_config(path, fstore=None):
    if fstore:
        fstore.backup_file(path)
    else:
        shutil.copy(path, "%s.ipasave" % (path))


def get_time_source():
    """
    While in interactive installation user has to specify NTP server or pool
    to be used in chrony configuration. This method asks user input on these
    values in case that they were not specified before installation start.
    """
    ntp_servers = []
    ntp_pool = ""

    if ipautil.user_input("Do you want to configure chrony "
                          "with NTP server or pool address?", False):
        servers = user_input("Enter NTP source server addresses separated by "
                             "comma, or press Enter to skip", allow_empty=True)
        if servers:  # if user input is not '' (empty)
            logger.debug("User provided NTP server(s):")
            # cut possible multiple servers separated by comma into list
            for server in servers.split(","):
                # users tend to separate servers by ", " so strip() whitespaces
                server = server.strip()
                ntp_servers.append(server)
                logger.debug("\t%s", server)

        ntp_pool = user_input("Enter a NTP source pool address, "
                              "or press Enter to skip", allow_empty=True)
        if ntp_pool:  # if user input is not '' (empty)
            logger.debug("User provided NTP pool:\n\t%s", ntp_pool)

    return ntp_servers, ntp_pool


def sync_chrony():
    """
    This method enables chronyd service on boot and restarts it to reload
    chrony configuration file /etc/chrony.conf
    Then it tries to synchronize time with chrony's new or defaut configuration
    """
    # Set the chronyd to start on boot
    services.knownservices.chronyd.enable()

    # Restart chronyd
    services.knownservices.chronyd.restart()

    sync_attempt_count = 3
    # chrony attempt count to sync with configiured servers
    # each next attempt is tried after 10seconds of timeot
    # 3 attempts means: if first immidiate attempt fails
    # there is 10s delay between next attempts

    args = [paths.CHRONYC, 'waitsync', str(sync_attempt_count), '-d']

    try:
        logger.info('Attempting to sync time with chronyc.')
        ipautil.run(args)
        logger.info('Time synchronization was successful.')
        return True
    except ipautil.CalledProcessError:
        logger.warning('Process chronyc waitsync failed to sync time!')
        logger.warning(
            "Unable to sync time with chrony server, assuming the time "
            "is in sync. Please check that 123 UDP port is opened, "
            "and any time server is on network.")
        return False


def configure_chrony(ntp_servers, ntp_pool=None,
                     fstore=None, sysstore=None, debug=False):
    """
    This method only configures chrony client with ntp_servers or ntp_pool
    """

    module = "chrony"
    if sysstore:
        sysstore.backup_state(module, "enabled",
                              services.knownservices.chronyd.is_enabled())

    aug = Augeas(flags=Augeas.NO_LOAD | Augeas.NO_MODL_AUTOLOAD,
                 loadpath=paths.USR_SHARE_IPA_DIR)

    try:
        logger.debug("Configuring chrony")
        chrony_conf = os.path.abspath(paths.CHRONY_CONF)
        aug.transform(module, chrony_conf)  # loads chrony lens file
        aug.load()  # loads augeas tree
        # augeas needs to prepend path with '/files'
        path = '/files{path}'.format(path=chrony_conf)

        # remove possible conflicting configuration of servers
        aug.remove('{}/server'.format(path))
        aug.remove('{}/pool'.format(path))
        aug.remove('{}/peer'.format(path))
        if ntp_pool:
            logger.debug("Setting server pool:")
            logger.debug("'%s'", ntp_pool)
            aug.set('{}/pool[last()+1]'.format(path), ntp_pool)
            aug.set('{}/pool[last()]/iburst'.format(path), None)

        if ntp_servers:
            logger.debug("Setting time servers:")
            for server in ntp_servers:
                aug.set('{}/server[last()+1]'.format(path), server)
                aug.set('{}/server[last()]/iburst'.format(path), None)
                logger.debug("'%s'", server)

        # backup oginal conf file
        logger.debug("Backing up '%s'", chrony_conf)
        __backup_config(chrony_conf, fstore)

        logger.debug("Writing configuration to '%s'", chrony_conf)
        aug.save()

        logger.info('Configuration of chrony was changed by installer.')
        configured = True

    except IOError:
        logger.error("Augeas failed to configure file %s", chrony_conf)
        configured = False
    except RuntimeError as e:
        logger.error("Configuration failed with: %s", e)
        configured = False
    finally:
        aug.close()

    tasks.restore_context(chrony_conf)
    return configured


class NTPConfigurationError(Exception):
    pass


class NTPConflictingService(NTPConfigurationError):
    def __init__(self, message='', conflicting_service=None):
        super(NTPConflictingService, self).__init__(self, message)
        self.conflicting_service = conflicting_service


def check_timedate_services():
    """
    System may contain conflicting services used for time&date synchronization.
    As IPA server/client supports only chronyd, make sure that other services
    are not enabled to prevent conflicts.
    """
    for service in services.timedate_services:
        if service == 'chronyd':
            continue
        # Make sure that the service is not enabled
        instance = services.service(service, api)
        if instance.is_enabled() or instance.is_running():
            raise NTPConflictingService(
                    conflicting_service=instance.service_name)


def force_chrony(statestore):
    """
    Force chronyd configuration and disable and stop any other conflicting
    time&date service
    """
    for service in services.timedate_services:
        if service == 'chronyd':
            continue
        instance = services.service(service, api)
        enabled = instance.is_enabled()
        running = instance.is_running()

        if enabled or running:
            statestore.backup_state(instance.service_name, 'enabled', enabled)
            statestore.backup_state(instance.service_name, 'running', running)

            if running:
                instance.stop()

            if enabled:
                instance.disable()


def restore_forced_timeservices(statestore, skip_service='chronyd'):
    """
    Restore from installation and enable/start service that
    were disabled/stopped during installation
    """
    for service in services.timedate_services:
        if service == skip_service:
            continue
        if statestore.has_state(service):
            instance = services.service(service, api)
            enabled = statestore.restore_state(instance.service_name,
                                               'enabled')
            running = statestore.restore_state(instance.service_name,
                                               'running')
            if enabled:
                instance.enable()
            if running:
                instance.start()
