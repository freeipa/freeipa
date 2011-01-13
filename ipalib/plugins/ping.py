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
"""
Ping the remote IPA server
"""

from ipalib import api
from ipalib import Command
from ipalib import output
from ipapython.version import VERSION, API_VERSION

class ping(Command):
    """
    ping a remote server
    """
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
