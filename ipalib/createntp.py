#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from logging import getLogger

from importlib import import_module
from ipapython.ntpmethods import TIME_SERVER
from ipaplatform.constants import constants

logger = getLogger(__name__)


def detect_ntp_daemon(type_):
    if TIME_SERVER is None:
        return False

    clintplib = import_module("ipaclient.install.clintplib")

    try:
        servntplib = import_module("ipaserver.install.servntplib")
    except ImportError:
        servntplib = None

    ntp_class_name = \
        constants.TIME_SERVER_STRUCTURE[TIME_SERVER]['class_name']

    servts = None
    if servntplib:
        servts = getattr(servntplib, ntp_class_name + 'Server')

    clits = getattr(clintplib, ntp_class_name + 'Client')

    return {'server': servts, 'client': clits}.get(type_)


def sync_time_server(fstore, sstore, ntp_servers, ntp_pool):
    cl = NTP_SERVER()

    cl.fstore = fstore
    cl.sstore = sstore
    cl.ntp_servers = ntp_servers
    cl.ntp_pool = ntp_pool

    try:
        cl.sync_time()
        return True
    except Exception:
        return False


def sync_time_client(fstore, statestore, cli_domain, ntp_servers, ntp_pool):
    cl = NTP_CLIENT()

    cl.fstore = fstore
    cl.statestore = statestore
    cl.cli_domain = cli_domain
    cl.ntp_servers = ntp_servers
    cl.ntp_pool = ntp_pool

    return cl.sync_time()


def uninstall_server(fstore, sstore):
    if NTP_SERVER is False:
        logger.debug('NTP daemon not found in your system. '
                     'Configuration cannot be restored.')
        return

    cl = NTP_SERVER()

    cl.sstore = sstore
    cl.fstore = fstore

    cl.uninstall()


def uninstall_client(fstore, sstore):
    if NTP_CLIENT is False:
        logger.debug('NTP daemon not found in your system. '
                     'Configuration cannot be restored.')
        return

    cl = NTP_CLIENT()

    cl.statestore = sstore
    cl.fstore = fstore

    cl.uninstall()


NTP_SERVER = detect_ntp_daemon('server')
NTP_CLIENT = detect_ntp_daemon('client')
