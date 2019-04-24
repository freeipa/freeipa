# Authors:
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

'''
This Red Hat OS family base platform module exports default filesystem paths as
common in Red Hat OS family-based systems.
'''

from __future__ import absolute_import

import sys

# Fallback to default path definitions
from ipaplatform.base.paths import BasePathNamespace


class RedHatPathNamespace(BasePathNamespace):
    # https://docs.python.org/2/library/platform.html#cross-platform
    if sys.maxsize > 2**32:
        LIBSOFTHSM2_SO = BasePathNamespace.LIBSOFTHSM2_SO_64
        PAM_KRB5_SO = BasePathNamespace.PAM_KRB5_SO_64
        BIND_LDAP_SO = BasePathNamespace.BIND_LDAP_SO_64
    AUTHCONFIG = '/usr/sbin/authconfig'
    AUTHSELECT = '/usr/bin/authselect'
    SYSCONF_NETWORK = '/etc/sysconfig/network'
    CRYPTO_POLICY_P11_KIT_CONFIG = \
        "/etc/crypto-policies/local.d/nss-p11-kit.config"
    UPDATE_CRYPTO_POLICY = "/usr/bin/update-crypto-policies"


paths = RedHatPathNamespace()
