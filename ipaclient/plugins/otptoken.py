# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

from ipalib import api, Str, Password, _
from ipalib.plugable import Registry
from ipalib.frontend import Local
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.nsslib import NSSConnection

import six
from six.moves import urllib

if six.PY3:
    unicode = str

register = Registry()


class HTTPSHandler(urllib.request.HTTPSHandler):
    "Opens SSL HTTPS connections that perform hostname validation."

    def __init__(self, **kwargs):
        self.__kwargs = kwargs

        # Can't use super() because the parent is an old-style class.
        urllib.request.HTTPSHandler.__init__(self)

    def __inner(self, host, **kwargs):
        tmp = self.__kwargs.copy()
        tmp.update(kwargs)
        # NSSConnection doesn't support timeout argument
        tmp.pop('timeout', None)
        return NSSConnection(host, **tmp)

    def https_open(self, req):
        # pylint: disable=no-member
        return self.do_open(self.__inner, req)

@register()
class otptoken_sync(Local):
    __doc__ = _('Synchronize an OTP token.')

    header = 'X-IPA-TokenSync-Result'

    takes_options = (
        Str('user', label=_('User ID')),
        Password('password', label=_('Password'), confirm=False),
        Password('first_code', label=_('First Code'), confirm=False),
        Password('second_code', label=_('Second Code'), confirm=False),
    )

    takes_args = (
        Str('token?', label=_('Token ID')),
    )

    def forward(self, *args, **kwargs):
        status = {'result': {self.header: 'unknown'}}

        # Get the sync URI.
        segments = list(urllib.parse.urlparse(self.api.env.xmlrpc_uri))
        assert segments[0] == 'https' # Ensure encryption.
        segments[2] = segments[2].replace('/xml', '/session/sync_token')
        # urlunparse *can* take one argument
        # pylint: disable=too-many-function-args
        sync_uri = urllib.parse.urlunparse(segments)

        # Prepare the query.
        query = {k: v for k, v in kwargs.items()
                    if k in {x.name for x in self.takes_options}}
        if args and args[0] is not None:
            obj = self.api.Object.otptoken
            query['token'] = DN((obj.primary_key.name, args[0]),
                                obj.container_dn, self.api.env.basedn)
        query = urllib.parse.urlencode(query)

        # Sync the token.
        # pylint: disable=E1101
        handler = HTTPSHandler(dbdir=paths.IPA_NSSDB_DIR,
                               tls_version_min=api.env.tls_version_min,
                               tls_version_max=api.env.tls_version_max)
        rsp = urllib.request.build_opener(handler).open(sync_uri, query)
        if rsp.getcode() == 200:
            status['result'][self.header] = rsp.info().get(self.header, 'unknown')
        rsp.close()

        return status

    def output_for_cli(self, textui, result, *keys, **options):
        textui.print_plain({
            'ok': 'Token synchronized.',
            'error': 'Error contacting server!',
            'invalid-credentials': 'Invalid Credentials!',
        }.get(result['result'][self.header], 'Unknown Error!'))
