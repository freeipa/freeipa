#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
Host name installer module
"""

from ipapython.install import typing
from ipapython.install.core import knob
from ipapython.ipautil import CheckedIPAddress

from . import service
from .service import prepare_only


class HostNameInstallInterface(service.ServiceInstallInterface):
    """
    Interface common to all service installers which create DNS address
    records for `host_name`
    """

    ip_addresses = knob(
        # pylint: disable=invalid-sequence-index
        typing.List[CheckedIPAddress], None,
        description="Specify IP address that should be added to DNS. This "
                    "option can be used multiple times",
        cli_names='--ip-address',
        cli_metavar='IP_ADDRESS',
    )
    ip_addresses = prepare_only(ip_addresses)

    @ip_addresses.validator
    def ip_addresses(self, values):
        for value in values:
            try:
                CheckedIPAddress(value, match_local=True)
            except Exception as e:
                raise ValueError("invalid IP address {0}: {1}".format(
                    value, e))

    all_ip_addresses = knob(
        None,
        description="All routable IP addresses configured on any interface "
                    "will be added to DNS",
    )
    all_ip_addresses = prepare_only(all_ip_addresses)

    no_host_dns = knob(
        None,
        description="Do not use DNS for hostname lookup during installation",
    )
    no_host_dns = prepare_only(no_host_dns)

    no_wait_for_dns = knob(
        None,
        description="do not wait until the host is resolvable in DNS",
    )
    no_wait_for_dns = prepare_only(no_wait_for_dns)
