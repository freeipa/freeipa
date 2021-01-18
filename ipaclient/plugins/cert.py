# Authors:
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

import base64

from ipaclient.frontend import MethodOverride
from ipalib import errors
from ipalib import x509
from ipalib import util
from ipalib.parameters import BinaryFile, File, Flag, Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


class CertRetrieveOverride(MethodOverride):
    takes_options = (
        Str(
            'certificate_out?',
            doc=_('Write certificate (chain if --chain used) to file'),
            include='cli',
            cli_metavar='FILE',
        ),
    )

    def forward(self, *args, **options):
        if 'certificate_out' in options:
            certificate_out = options.pop('certificate_out')
            try:
                util.check_writable_file(certificate_out)
            except errors.FileError as e:
                raise errors.ValidationError(name='certificate-out',
                                             error=str(e))
        else:
            certificate_out = None

        result = super(CertRetrieveOverride, self).forward(*args, **options)

        if certificate_out is not None:
            if options.get('chain', False):
                certs = result['result']['certificate_chain']
            else:
                certs = [base64.b64decode(result['result']['certificate'])]
            certs = (x509.load_der_x509_certificate(cert) for cert in certs)
            x509.write_certificate_list(certs, certificate_out)

        return result


@register(override=True, no_fail=True)
class cert_request(CertRetrieveOverride):
    def get_args(self):
        for arg in super(cert_request, self).get_args():
            if arg.name == 'csr':
                arg = arg.clone_retype(arg.name, File, required=False)
            yield arg


@register(override=True, no_fail=True)
class cert_show(CertRetrieveOverride):
    def get_options(self):
        for option in super(cert_show, self).get_options():
            if option.name == 'out':
                # skip server-defined --out
                continue
            if option.name == 'certificate_out':
                # add --out as a deprecated alias of --certificate-out
                option = option.clone_rename(
                    'out',
                    cli_name='certificate_out',
                    deprecated_cli_aliases={'out'},
                )
            yield option

    def forward(self, *args, **options):
        try:
            options['certificate_out'] = options.pop('out')
        except KeyError:
            pass

        return super(cert_show, self).forward(*args, **options)


@register(override=True, no_fail=True)
class cert_remove_hold(MethodOverride):
    has_output_params = (
        Flag('unrevoked',
            label=_('Unrevoked'),
        ),
        Str('error_string',
            label=_('Error'),
        ),
    )


@register(override=True, no_fail=True)
class cert_find(MethodOverride):
    takes_options = (
        BinaryFile(
            'file?',
            label=_("Input filename"),
            doc=_('File to load the certificate from.'),
            include='cli',
        ),
    )

    def forward(self, *args, **options):
        if self.api.env.context == 'cli':
            if 'certificate' in options and 'file' in options:
                raise errors.MutuallyExclusiveError(
                    reason=_("cannot specify both raw certificate and file"))
            if 'certificate' not in options and 'file' in options:
                options['certificate'] = x509.load_unknown_x509_certificate(
                                            options.pop('file'))

        return super(cert_find, self).forward(*args, **options)
