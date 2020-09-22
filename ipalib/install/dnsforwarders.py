#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""DNS forwarder and systemd-resolve1 helpers
"""
import ipaddress
import logging
import os
import socket

import dbus

from ipaplatform.paths import paths
from ipapython.dnsutil import get_ipa_resolver


logger = logging.getLogger(__name__)


_SYSTEMD_RESOLV_CONF = {
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/lib/systemd/resolv.conf",
    "/usr/lib/systemd/resolv.conf",
}

_DBUS_RESOLVE1_NAME = "org.freedesktop.resolve1"
_DBUS_RESOLVE1_PATH = "/org/freedesktop/resolve1"
_DBUS_RESOLVE1_MANAGER_IF = "org.freedesktop.resolve1.Manager"
_DBUS_PROPERTY_IF = "org.freedesktop.DBus.Properties"

# netlink interface index for resolve1 global settings and loopback
IFINDEX_GLOBAL = 0
IFINDEX_LOOPBACK = 1


def detect_resolve1_resolv_conf():
    """Detect if /etc/resolv.conf is managed by systemd-resolved

    See man(5) NetworkManager.conf
    """
    try:
        dest = os.readlink(paths.RESOLV_CONF)
    except OSError:
        # not a link
        return False
    # convert path relative to /etc/resolv.conf to abs path
    dest = os.path.normpath(
        os.path.join(os.path.dirname(paths.RESOLV_CONF), dest)
    )
    return dest in _SYSTEMD_RESOLV_CONF


def get_resolve1_nameservers(*, with_ifindex=False):
    """Get list of DNS nameservers from systemd-resolved

    :return: list of tuples (ifindex, ipaddress_obj)
    """
    bus = dbus.SystemBus()
    try:
        resolve1 = bus.get_object(_DBUS_RESOLVE1_NAME, _DBUS_RESOLVE1_PATH)
        prop_if = dbus.Interface(resolve1, _DBUS_PROPERTY_IF)
        dns_prop = prop_if.Get(_DBUS_RESOLVE1_MANAGER_IF, "DNSEx")
    finally:
        bus.close()

    results = []
    for ifindex, af, dns_arr, port, sniname in dns_prop:
        if port not in {0, 53} or sniname:
            # non-default port, non-standard port, or SNI name configuration
            # for DNS over TLS, e.g. 1.2.3.4:9953#example.com
            continue
        # convert packed format to IPAddress object (like inet_ntop)
        if af == socket.AF_INET:
            dnsip = ipaddress.IPv4Address(bytes(dns_arr))
        elif af == socket.AF_INET6:
            dnsip = ipaddress.IPv6Address(bytes(dns_arr))
        else:
            # neither IPv4 nor IPv6
            continue
        if with_ifindex:
            # netlink interface index, see socket.if_nameindex()
            ifindex = int(ifindex)
            results.append((ifindex, dnsip))
        else:
            results.append(dnsip)

    return results


def get_dnspython_nameservers(*, with_ifindex=False):
    """Get list of DNS nameservers from dnspython

    On Linux dnspython parses /etc/resolv.conf for us

    :return: list of tuples (ifindex, ipaddress_obj)
    """
    results = []
    for nameserver in get_ipa_resolver().nameservers:
        nameserver = ipaddress.ip_address(nameserver)
        if with_ifindex:
            results.append((IFINDEX_GLOBAL, nameserver))
        else:
            results.append(nameserver)
    return results


def get_nameservers():
    """Get list of unique, non-loopback DNS nameservers

    :return: list of strings
    """
    if detect_resolve1_resolv_conf():
        logger.debug(
            "systemd-resolved detected, fetching nameservers from D-Bus"
        )
        nameservers = get_resolve1_nameservers(with_ifindex=True)
    else:
        logger.debug(
            "systemd-resolved not detected, parsing %s", paths.RESOLV_CONF
        )
        nameservers = get_dnspython_nameservers(with_ifindex=True)

    logger.debug("Detected nameservers: %r", nameservers)

    result = []
    seen = set()
    for ifindex, ip in nameservers:
        # unique entries
        if ip in seen:
            continue
        seen.add(ip)
        # skip loopback
        if ifindex == IFINDEX_LOOPBACK or ip.is_loopback:
            continue
        result.append(str(ip))

    logger.debug("Use nameservers %r", result)

    return result


if __name__ == "__main__":
    from pprint import pprint

    print("systemd-resolved detected:", detect_resolve1_resolv_conf())
    print("Interfaces:", socket.if_nameindex())
    print("dnspython nameservers:")
    pprint(get_dnspython_nameservers(with_ifindex=True))
    print("resolve1 nameservers:")
    try:
        pprint(get_resolve1_nameservers(with_ifindex=True))
    except Exception as e:
        print(e)
    print("nameservers:", get_nameservers())
