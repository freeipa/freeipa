# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

"""List of, and utilities for working with, client capabilities by API version

The API version is given in ipapython.version.API_VERSION.

This module defines a dict, ``capabilities``, that maps feature names to API
versions they were introduced in.
"""

from ipapython.ipautil import APIVersion

VERSION_WITHOUT_CAPABILITIES = u'2.51'

capabilities = dict(
    # messages: Server output may include an extra key, "messages", that
    # contains a list of warnings and other messages.
    # http://freeipa.org/page/V3/Messages
    messages=u'2.52',

    # optional_uid_params: Before this version, UID & GID parameter defaults
    # were 999, which meant "assign dynamically", so was not possible to get
    # a user with UID=999. With the capability, these parameters are optional
    # and 999 really means 999.
    # https://fedorahosted.org/freeipa/ticket/2886
    optional_uid_params=u'2.54',

    # permissions2: Reworked permission system
    # http://www.freeipa.org/page/V3/Permissions_V2
    permissions2=u'2.69',

    # primary_key_types: Non-unicode primary keys in command output
    primary_key_types=u'2.83',

    # support for datetime values on the client
    datetime_values=u'2.84',

    # dns_name_values: dnsnames as objects
    dns_name_values=u'2.88',
)


def client_has_capability(client_version, capability):
    """Determine whether the client has the given capability

    :param capability: Name of the capability to test
    :param client_version: The API version string reported by the client
    """

    version = APIVersion(client_version)

    return version >= APIVersion(capabilities[capability])
