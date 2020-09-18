#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Get host's FQDN
"""
import socket


def gethostfqdn():
    """Get the fully qualified domain name of current host from glibc

    This function may return an FQDN with up to MAXHOSTFQDNLEN characters
    (253). The effective hostname is still limited to MAXHOSTNAMELEN (64).

    :return: FQDN as str
    """
    hostname = socket.gethostname()
    # this call can never fail except for misconfigured nsswitch.conf
    # without nss-myhostname provider. The myhostname provider translates
    # gethostname() to local interfaces.
    gai = socket.getaddrinfo(
        hostname,
        None,  # service/port is irrelevant
        family=socket.AF_UNSPEC,  # IPv4 or IPv6
        type=socket.SOCK_DGRAM,  # optimization, TCP/RAW gives same result
        # include canonical name in first addrinfo struct
        # only use address family when at least one non-local interface
        # is configured with that address family
        flags=socket.AI_CANONNAME | socket.AI_ADDRCONFIG
    )
    # first addrinfo struct, fourth field is canonical name
    # getaddrinfo() either raises an exception or returns at least one entry
    return gai[0][3]
