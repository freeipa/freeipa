# Authors:
#   Martin Kosek <mkosek@redhat.com>
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
"""
Base class for HTTP request tests
"""

import urllib
import httplib

from ipalib import api

class Unauthorized_HTTP_test(object):
    """
    Base class for simple HTTP request tests executed against URI
    with no required authorization
    """
    app_uri = ''
    host = api.env.host
    content_type = 'application/x-www-form-urlencoded'

    def send_request(self, method='POST', params=None):
        """
        Send a request to HTTP server

        :param key When not None, overrides default app_uri
        """
        if params is not None:
            params = urllib.urlencode(params, True)
        url = 'https://' + self.host + self.app_uri

        headers = {'Content-Type' : self.content_type,
                   'Referer' : url}

        conn = httplib.HTTPSConnection(self.host)
        conn.request(method, self.app_uri, params, headers)
        return conn.getresponse()
