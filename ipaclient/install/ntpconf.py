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
import logging
import os
import shutil

from ipalib import api
from ipapython import ipautil
from ipaplatform.tasks import tasks
from ipaplatform import services
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

ntp_conf = """# Permit time synchronization with our time source, but do not
# permit the source to query or modify the service on this system.
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery

# Permit all access over the loopback interface.  This could
# be tightened as well, but to do so would effect some of
# the administrative functions.
restrict 127.0.0.1
restrict -6 ::1

# Hosts on local network are less restricted.
#restrict 192.168.1.0 mask 255.255.255.0 nomodify notrap

# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
$SERVERS_BLOCK

#broadcast 192.168.1.255 key 42		# broadcast server
#broadcastclient			# broadcast client
#broadcast 224.0.1.1 key 42		# multicast server
#multicastclient 224.0.1.1		# multicast client
#manycastserver 239.255.254.254		# manycast server
#manycastclient 239.255.254.254 key 42	# manycast client

# Undisciplined Local Clock. This is a fake driver intended for backup
# and when no outside source of synchronized time is available.
server	127.127.1.0	# local clock
#fudge	127.127.1.0 stratum 10

# Drift file.  Put this in a directory which the daemon can write to.
# No symbolic links allowed, either, since the daemon updates the file
# by creating a temporary in the same directory and then rename()'ing
# it to the file.
driftfile /var/lib/ntp/drift

# Key file containing the keys and key identifiers used when operating
# with symmetric key cryptography.
keys /etc/ntp/keys

# Specify the key identifiers which are trusted.
#trustedkey 4 8 42

# Specify the key identifier to use with the ntpdc utility.
#requestkey 8

# Specify the key identifier to use with the ntpq utility.
#controlkey 8
"""

ntp_sysconfig = """OPTIONS="-x -p /var/run/ntpd.pid"

# Set to 'yes' to sync hw clock after successful ntpdate
SYNC_HWCLOCK=yes

# Additional options for ntpdate
NTPDATE_OPTIONS=""
"""
ntp_step_tickers = """# Use IPA-provided NTP server for initial time
$TICKER_SERVERS_BLOCK
"""
def __backup_config(path, fstore = None):
    if fstore:
        fstore.backup_file(path)
    else:
        shutil.copy(path, "%s.ipasave" % (path))

def __write_config(path, content):
    fd = open(path, "w")
    fd.write(content)
    fd.close()

def config_ntp(ntp_servers, fstore = None, sysstore = None):
    path_step_tickers = paths.NTP_STEP_TICKERS
    path_ntp_conf = paths.NTP_CONF
    path_ntp_sysconfig = paths.SYSCONFIG_NTPD
    sub_dict = {}
    sub_dict["SERVERS_BLOCK"] = "\n".join("server %s" % s for s in ntp_servers)
    sub_dict["TICKER_SERVERS_BLOCK"] = "\n".join(ntp_servers)

    nc = ipautil.template_str(ntp_conf, sub_dict)
    config_step_tickers = False


    if os.path.exists(path_step_tickers):
        config_step_tickers = True
        ns = ipautil.template_str(ntp_step_tickers, sub_dict)
        __backup_config(path_step_tickers, fstore)
        __write_config(path_step_tickers, ns)
        tasks.restore_context(path_step_tickers)

    if sysstore:
        module = 'ntp'
        sysstore.backup_state(module, "enabled", services.knownservices.ntpd.is_enabled())
        if config_step_tickers:
            sysstore.backup_state(module, "step-tickers", True)

    __backup_config(path_ntp_conf, fstore)
    __write_config(path_ntp_conf, nc)
    tasks.restore_context(path_ntp_conf)

    __backup_config(path_ntp_sysconfig, fstore)
    __write_config(path_ntp_sysconfig, ntp_sysconfig)
    tasks.restore_context(path_ntp_sysconfig)

    # Set the ntpd to start on boot
    services.knownservices.ntpd.enable()

    # Restart ntpd
    services.knownservices.ntpd.restart()


def synconce_ntp(server_fqdn, debug=False):
    """
    Syncs time with specified server using ntpd.
    Primarily designed to be used before Kerberos setup
    to get time following the KDC time

    Returns True if sync was successful
    """
    ntpd = paths.NTPD
    if not os.path.exists(ntpd):
        return False

    # The ntpd command will never exit if it is unable to reach the
    # server, so timeout after 15 seconds.
    timeout = 15

    tmp_ntp_conf = ipautil.write_tmp_file('server %s' % server_fqdn)
    args = [paths.BIN_TIMEOUT, str(timeout), ntpd, '-qgc', tmp_ntp_conf.name]
    if debug:
        args.append('-d')
    try:
        logger.info('Attempting to sync time using ntpd.  '
                    'Will timeout after %d seconds', timeout)
        ipautil.run(args)
        return True
    except ipautil.CalledProcessError as e:
        if e.returncode == 124:
            logger.debug('Process did not complete before timeout')
        return False


class NTPConfigurationError(Exception):
    pass

class NTPConflictingService(NTPConfigurationError):
    def __init__(self, message='', conflicting_service=None):
        super(NTPConflictingService, self).__init__(self, message)
        self.conflicting_service = conflicting_service

def check_timedate_services():
    """
    System may contain conflicting services used for time&date synchronization.
    As IPA server/client supports only ntpd, make sure that other services are
    not enabled to prevent conflicts. For example when both chronyd and ntpd
    are enabled, systemd would always start only chronyd to manage system
    time&date which would make IPA configuration of ntpd ineffective.

    Reference links:
      https://fedorahosted.org/freeipa/ticket/2974
      http://fedoraproject.org/wiki/Features/ChronyDefaultNTP
    """
    for service in services.timedate_services:
        if service == 'ntpd':
            continue
        # Make sure that the service is not enabled
        instance = services.service(service, api)
        if instance.is_enabled() or instance.is_running():
            raise NTPConflictingService(conflicting_service=instance.service_name)

def force_ntpd(statestore):
    """
    Force ntpd configuration and disable and stop any other conflicting
    time&date service
    """
    for service in services.timedate_services:
        if service == 'ntpd':
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

def restore_forced_ntpd(statestore):
    """
    Restore from --force-ntpd installation and enable/start service that were
    disabled/stopped during installation
    """
    for service in services.timedate_services:
        if service == 'ntpd':
            continue
        if statestore.has_state(service):
            instance = services.service(service, api)
            enabled = statestore.restore_state(instance.service_name, 'enabled')
            running = statestore.restore_state(instance.service_name, 'running')
            if enabled:
                instance.enable()
            if running:
                instance.start()
