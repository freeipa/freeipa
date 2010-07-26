# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Ping the remote IPA server
"""

from ipalib import api
from ipalib import Command
from ipalib import output

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
        return dict(summary=u'pong')

api.register(ping)
