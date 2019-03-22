#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""Helpers services in for cn=masters,cn=ipa,cn=etc
"""

from __future__ import absolute_import

import collections
import logging
import random

from ipapython.dn import DN
from ipalib import api
from ipalib import errors

logger = logging.getLogger(__name__)

# constants for ipaConfigString
CONFIGURED_SERVICE = u'configuredService'
ENABLED_SERVICE = u'enabledService'
HIDDEN_SERVICE = u'hiddenService'

# The service name as stored in cn=masters,cn=ipa,cn=etc. The values are:
# 0: systemd service name
# 1: start order for system service
# 2: LDAP server entry CN, also used as SERVICE_LIST key
service_definition = collections.namedtuple(
    "service_definition",
    "systemd_name startorder service_entry"
)

SERVICES = [
    service_definition('krb5kdc', 10, 'KDC'),
    service_definition('kadmin', 20, 'KPASSWD'),
    service_definition('named', 30, 'DNS'),
    service_definition('httpd', 40, 'HTTP'),
    service_definition('ipa-custodia', 41, 'KEYS'),
    service_definition('ntpd', 45, 'NTP'),
    service_definition('pki-tomcatd', 50, 'CA'),
    service_definition('pki-tomcatd', 51, 'KRA'),
    service_definition('smb', 60, 'ADTRUST'),
    service_definition('winbind', 70, 'EXTID'),
    service_definition('ipa-otpd', 80, 'OTPD'),
    service_definition('ipa-ods-exporter', 90, 'DNSKeyExporter'),
    service_definition('ods-enforcerd', 100, 'DNSSEC'),
    service_definition('ipa-dnskeysyncd', 110, 'DNSKeySync'),
]

SERVICE_LIST = {s.service_entry: s for s in SERVICES}


def find_providing_servers(svcname, conn=None, preferred_hosts=(), api=api):
    """Find servers that provide the given service.

    :param svcname: The service to find
    :param preferred_hosts: preferred servers
    :param conn: a connection to the LDAP server
    :param api: ipalib.API instance
    :return: list of host names in randomized order (possibly empty)

    Preferred servers are moved to the front of the list if and only if they
    are found as providing servers.
    """
    assert isinstance(preferred_hosts, (tuple, list))
    if svcname not in SERVICE_LIST:
        raise ValueError("Unknown service '{}'.".format(svcname))
    if conn is None:
        conn = api.Backend.ldap2

    dn = DN(api.env.container_masters, api.env.basedn)

    query_filter = conn.combine_filters(
        [
            conn.make_filter(
                {
                    'objectClass': 'ipaConfigObject',
                    'cn': svcname
                },
                rules=conn.MATCH_ALL,
            ),
            conn.make_filter(
                {
                    'ipaConfigString': [ENABLED_SERVICE, HIDDEN_SERVICE]
                },
                rules=conn.MATCH_ANY
            ),
        ],
        rules=conn.MATCH_ALL
    )

    try:
        entries, _trunc = conn.find_entries(
            filter=query_filter,
            attrs_list=['ipaConfigString'],
            base_dn=dn
        )
    except errors.NotFound:
        return []

    # DNS is case insensitive
    preferred_hosts = list(host_name.lower() for host_name in preferred_hosts)
    servers = []
    for entry in entries:
        servername = entry.dn[1].value.lower()
        cfgstrings = entry.get('ipaConfigString', [])
        # always consider enabled services
        if ENABLED_SERVICE in cfgstrings:
            servers.append(servername)
        # use hidden services on preferred hosts
        elif HIDDEN_SERVICE in cfgstrings and servername in preferred_hosts:
            servers.append(servername)
    # unique list of host names
    servers = list(set(servers))
    # shuffle the list like DNS SRV would randomize it
    random.shuffle(servers)
    # Move preferred hosts to front
    for host_name in reversed(preferred_hosts):
        try:
            servers.remove(host_name)
        except ValueError:
            # preferred server not found, log and ignore
            logger.warning(
                "Lookup failed: Preferred host %s does not provide %s.",
                host_name, svcname
            )
        else:
            servers.insert(0, host_name)
    return servers


def find_providing_server(svcname, conn=None, preferred_hosts=(), api=api):
    """Find a server that provides the given service.

    :param svcname: The service to find
    :param conn: a connection to the LDAP server
    :param host_name: the preferred server
    :param api: ipalib.API instance
    :return: the selected host name or None
    """
    servers = find_providing_servers(
        svcname, conn=conn, preferred_hosts=preferred_hosts, api=api
    )
    if not servers:
        return None
    else:
        return servers[0]


def get_masters(conn=None, api=api):
    """Get all master hostnames

    :param conn: a connection to the LDAP server
    :param api: ipalib.API instance
    :return: list of hostnames
    """
    if conn is None:
        conn = api.Backend.ldap2

    dn = DN(api.env.container_masters, api.env.basedn)
    entries = conn.get_entries(dn, conn.SCOPE_ONELEVEL, None, ['cn'])
    return list(e['cn'][0] for e in entries)


def is_service_enabled(svcname, conn=None, api=api):
    """Check if service is enabled on any master

    The check function only looks for presence of service entries. It
    ignores enabled/hidden flags.

    :param svcname: The service to find
    :param conn: a connection to the LDAP server
    :param api: ipalib.API instance
    :return: True/False
    """
    if svcname not in SERVICE_LIST:
        raise ValueError("Unknown service '{}'.".format(svcname))
    if conn is None:
        conn = api.Backend.ldap2

    dn = DN(api.env.container_masters, api.env.basedn)
    query_filter = conn.make_filter(
        {
            'objectClass': 'ipaConfigObject',
            'cn': svcname
        },
        rules='&'
    )
    try:
        conn.find_entries(
            filter=query_filter,
            attrs_list=[],
            base_dn=dn
        )
    except errors.NotFound:
        return False
    else:
        return True
