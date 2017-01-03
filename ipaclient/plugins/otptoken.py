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

from __future__ import print_function
import sys

from ipaclient.frontend import MethodOverride
from ipalib import api, Str, Password, _
from ipalib.messages import add_message, ResultFormattingError
from ipalib.plugable import Registry
from ipalib.frontend import Local
from ipalib.util import create_https_connection
from ipapython.dn import DN
from ipapython.version import API_VERSION

import locale
import qrcode

import six
from six import StringIO
from six.moves import urllib

if six.PY3:
    unicode = str

register = Registry()


@register(override=True, no_fail=True)
class otptoken_add(MethodOverride):
    def _get_qrcode(self, output, uri, version):
        # Print QR code to terminal if specified
        qr_output = StringIO()
        qr = qrcode.QRCode()
        qr.add_data(uri)
        qr.make()
        qr.print_ascii(out=qr_output, tty=False)

        encoding = getattr(sys.stdout, 'encoding', None)
        if encoding is None:
            encoding = locale.getpreferredencoding(False)

        try:
            qr_code = qr_output.getvalue().encode(encoding)
        except UnicodeError:
            add_message(
                version,
                output,
                message=ResultFormattingError(
                    message=_("Unable to display QR code using the configured "
                              "output encoding. Please use the token URI to "
                              "configure your OTP device")
                )
            )
            return None

        if sys.stdout.isatty():
            output_width = self.api.Backend.textui.get_tty_width()
            qr_code_width = len(qr_code.splitlines()[0])
            if qr_code_width > output_width:
                add_message(
                    version,
                    output,
                    message=ResultFormattingError(
                        message=_(
                            "QR code width is greater than that of the output "
                            "tty. Please resize your terminal.")
                    )
                )

        return qr

    def output_for_cli(self, textui, output, *args, **options):
        # copy-pasted from ipalib/Frontend.__do_call()
        # because option handling is broken on client-side
        if 'version' in options:
            pass
        elif self.api.env.skip_version_check:
            options['version'] = u'2.0'
        else:
            options['version'] = API_VERSION

        uri = output['result'].get('uri', None)

        if uri is not None and not options.get('no_qrcode', False):
            qr = self._get_qrcode(output, uri, options['version'])
        else:
            qr = None

        rv = super(otptoken_add, self).output_for_cli(
                textui, output, *args, **options)

        if qr is not None:
            print("\n")
            qr.print_ascii(tty=sys.stdout.isatty())
            print("\n")

        return rv


class HTTPSHandler(urllib.request.HTTPSHandler):
    "Opens SSL HTTPS connections that perform hostname validation."

    def __init__(self, **kwargs):
        self.__kwargs = kwargs

        # Can't use super() because the parent is an old-style class.
        urllib.request.HTTPSHandler.__init__(self)

    def __inner(self, host, **kwargs):
        tmp = self.__kwargs.copy()
        tmp.update(kwargs)
        return create_https_connection(host, **tmp)

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
        handler = HTTPSHandler(
            cafile=api.env.tls_ca_cert,
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
