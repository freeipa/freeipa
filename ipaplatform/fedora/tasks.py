# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Martin Kosek <mkosek@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
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
This module contains default Fedora-specific implementations of system tasks.
'''

from __future__ import absolute_import

from ipapython import directivesetter
from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths


class FedoraTaskNamespace(RedHatTaskNamespace):

    def configure_httpd_protocol(self):
        # On Fedora 31 and earlier DEFAULT crypto-policy has TLS 1.0 and 1.1
        # enabled.
        directivesetter.set_directive(
            paths.HTTPD_SSL_CONF,
            'SSLProtocol',
            "all -SSLv3 -TLSv1 -TLSv1.1",
            False
        )


tasks = FedoraTaskNamespace()
