#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import shutil
import re

from ipaclient import discovery  # pylint: disable=W9901
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipapython import ipautil
from ipapython.admintool import ScriptError
from ipalib import api  # pylint: disable=W9901


def service_command():
    timedata_srv = {
        'OPENNTPD': {
            'api': services.knownservices.ntpd,
            'service': 'ntpd',
        },
        'NTPD': {
            'api': services.knownservices.ntpd,
            'service': 'ntpd',
        },
        'CHRONY': {
            'api': services.knownservices.chronyd,
            'service': 'chronyd'
        }
    }

    return timedata_srv[TIME_SERVER]


def detect_time_server():
    for ts, struct in constants.TIME_SERVER_STRUCTURE.items():
        sys_ts = ipautil.run(
            [
                paths.PACKAGE_MANAGER,
                constants.CHECK_PACKAGE_OPT,
                struct['package_name']
            ],
            raiseonerr=False
        )
        if sys_ts.returncode == 0:
            return ts

    return None


def search_ntp_servers(cli_domain):
    ds = discovery.IPADiscovery()
    ntp_servers = ds.ipadns_search_srv(
        cli_domain,
        '_ntp._udp',
        None, False
    )

    return ntp_servers


def backup_config(ntp_confile, fstore=None):
    if fstore:
        fstore.backup_file(ntp_confile)
    else:
        shutil.copy(ntp_confile, "%s.ipasave" % ntp_confile)


def restore_state(statestore, fstore, ntp_confile, logger):
    try:
        fstore.restore_file(ntp_confile)
    except ValueError:
        logger.debug("Configuration file %s was not restored.", ntp_confile)

    SERVICE_API.stop()
    SERVICE_API.disable()

    if statestore:
        enabled = statestore.restore_state(SERVICE_NAME, 'enabled')
        running = statestore.restore_state(SERVICE_NAME, 'running')

        if enabled:
            SERVICE_API.enable()

        if running:
            SERVICE_API.start()


def check_timedate_services():
    for service in services.timedate_services:
        if service == SERVICE_NAME:
            continue
        instance = services.service(service, api)
        if instance.is_enabled() or instance.is_running():
            raise NTPConflictingService(
                conflicting_service=service
            )


def get_time_source(logger):
    ntp_servers = []
    ntp_pool = ""

    if ipautil.user_input("Do you want to configure {} "
                          "with NTP server or pool address?"
                          "".format(TIME_SERVER), False):
        servers = ipautil.user_input(
            "Enter NTP source server addresses separated by "
            "comma, or press Enter to skip", allow_empty=True
        )
        if servers:
            logger.debug("User provided NTP server(s):")
            for server in servers.split(","):
                server = server.strip()
                ntp_servers.append(server)
                logger.debug("\t%s", server)

        ntp_pool = ipautil.user_input(
            "Enter a NTP source pool address, "
            "or press Enter to skip", allow_empty=True
        )
        if ntp_pool:
            logger.debug("User provided NTP pool:\t%s", ntp_pool)

    return ntp_servers, ntp_pool


def set_config(path, pool=None, servers=None, opts=None, logger=None):
    confile_params = {
        'NTPD': {
            'server_label': 'server',
            'pool_label': 'server',
            'option': 'iburst',
        },
        'OPENNTPD': {
            'server_label': 'server',
            'pool_label': 'servers',
            'option': '',
        },
        'CHRONY': {
            'server_label': 'server',
            'pool_label': 'pool',
            'option': 'iburst',
        },
    }

    confile_list = []

    with open(path, 'r+') as confile:
        for line in confile:
            search_ = re.findall(
                re.compile(r"^(server|servers|pool|restrict)\s.*"), line
            )
            if not search_:
                confile_list.append(line)

        confile_params = confile_params[TIME_SERVER]

        confile_list.append("\n### Added by IPA Installer ###\n")

        if pool:
            confile_list.append('{pool_label} {host} {option}\n'.format(
                pool_label=confile_params['pool_label'],
                host=pool,
                option=confile_params['option'],
            ))

        if servers:
            for srv in servers:
                confile_list.append('{server_label} {host} {option}\n'.format(
                    server_label=confile_params['server_label'],
                    host=srv,
                    option=confile_params['option'],
                ))

        if opts:
            for opt in opts:
                confile_list.append('{}\n'.format(opt))

        # checking if there are parameters other than the header
        if len(confile_list) == 1:
            raise ScriptError("Can not configure ntp configuration file. "
                              "Configuration file is empty.")

        conf_content = ''.join(confile_list)

        if logger:
            logger.debug("Writing configuration to %s", path)

        confile.seek(0)
        confile.write(conf_content)


def force_service(statestore):
    for service in services.timedate_services:
        if service == SERVICE_NAME:
            continue
        enabled = SERVICE_API.is_enabled()
        running = SERVICE_API.is_running()

        if enabled or running:
            statestore.backup_state(SERVICE_NAME, 'enabled', enabled)
            statestore.backup_state(SERVICE_NAME, 'running', running)

            if running:
                SERVICE_API.stop()

            if enabled:
                SERVICE_API.disable()


def uninstall(statestore, fstore, ntp_confile, logger):
    if statestore:
        if statestore.has_state(SERVICE_NAME):
            restore_state(statestore, fstore, ntp_confile, logger)


TIME_SERVER = detect_time_server()
if TIME_SERVER is not None:
    SERVICE_API = service_command()['api']
    SERVICE_NAME = service_command()['service']


class NTPConfigurationError(Exception):
    pass


class NTPConflictingService(NTPConfigurationError):
    def __init__(self, message='', conflicting_service=None):
        super(NTPConflictingService, self).__init__(self, message)
        self.conflicting_service = conflicting_service
