# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib import api
from ipalib import Command
from ipalib import output
from ipalib import _, ngettext
from ipapython.version import VERSION, API_VERSION

__doc__ = _("""
Ping the remote IPA server to ensure it is running.

The ping command sends an echo request to an IPA server. The server
returns its version information. This is used by an IPA client
to confirm that the server is available and accepting requests.

The server from xmlrpc_uri in /etc/ipa/default.conf is contacted first.
If it does not respond then the client will contact any servers defined
by ldap SRV records in DNS.

EXAMPLES:

 Ping an IPA server:
   ipa ping
   ------------------------------------------
   IPA server version 2.1.9. API version 2.20
   ------------------------------------------

 Ping an IPA server verbosely:
   ipa -v ping
   ipa: INFO: trying https://ipa.example.com/ipa/xml
   ipa: INFO: Forwarding 'ping' to server u'https://ipa.example.com/ipa/xml'
   -----------------------------------------------------
   IPA server version 2.1.9. API version 2.20
   -----------------------------------------------------
""")

class ping(Command):
    __doc__ = _('Ping a remote server.')

    has_output = (
        output.summary,
    )

    def execute(self):
        """
        A possible enhancement would be to take an argument and echo it
        back but a fixed value works for now.
        """
        return dict(summary=u'IPA server version %s. API version %s' % (VERSION, API_VERSION))

api.register(ping)
