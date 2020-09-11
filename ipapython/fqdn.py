#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Get host's FQDN
"""
import socket


def gethostfqdn():
    hostname = socket.gethostname()

    # optional optimization, consider hostname with dot as FQDN
    if "." in hostname:
        return hostname

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
    return gai[0][3]
