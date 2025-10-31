# Authors:
#   Jan Cholasta <jcholast@redhat.com>
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
This RHEL base platform module exports default filesystem paths as common
in RHEL-based systems.
'''

# Fallback to default path definitions
from __future__ import absolute_import

from ipaplatform.redhat.paths import RedHatPathNamespace
from ipaplatform.rhel.constants import HAS_NFS_CONF
from ipaplatform.osinfo import osinfo


class RHELPathNamespace(RedHatPathNamespace):
    NAMED_CRYPTO_POLICY_FILE = "/etc/crypto-policies/back-ends/bind.config"
    if HAS_NFS_CONF:
        SYSCONFIG_NFS = '/etc/nfs.conf'
    if osinfo.version_number >= (10,1):
        BIN_TOMCAT = "/usr/share/tomcat/bin/version.sh"


paths = RHELPathNamespace()
