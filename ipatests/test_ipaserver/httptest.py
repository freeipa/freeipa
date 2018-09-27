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

from ipalib import api, util


class Unauthorized_HTTP_test:
    """
    Base class for simple HTTP request tests executed against URI
    with no required authorization
    """
    app_uri = ''
    host = api.env.host
    cacert = api.env.tls_ca_cert
    content_type = 'application/x-www-form-urlencoded'
    accept_language = 'en-us'

    def send_request(self, method='POST', params=None):
        """
        Send a request to HTTP server

        :param key When not None, overrides default app_uri
        """
        if params is not None:
            if self.content_type == 'application/x-www-form-urlencoded':
                # urlencode *can* take two arguments
                # pylint: disable=too-many-function-args
                params = urllib.parse.urlencode(params, True)
        url = 'https://' + self.host + self.app_uri

        headers = {'Content-Type': self.content_type,
                   'Accept-Language': self.accept_language,
                   'Referer': url}

        conn = util.create_https_connection(
                self.host, cafile=self.cacert)
        conn.request(method, self.app_uri, params, headers)
        return conn.getresponse()
