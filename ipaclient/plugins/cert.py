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

from ipaclient.frontend import MethodOverride
from ipalib import errors
from ipalib import x509
from ipalib import util
from ipalib.parameters import File
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


@register(override=True)
class cert_request(MethodOverride):
    def get_args(self):
        for arg in super(cert_request, self).get_args():
            if arg.name == 'csr':
                arg = arg.clone_retype(arg.name, File)
            yield arg


@register(override=True)
class cert_show(MethodOverride):
    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(cert_show, self).forward(*keys, **options)
            if 'certificate' in result['result']:
                x509.write_certificate(result['result']['certificate'], options['out'])
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(cert_show, self).forward(*keys, **options)


@register(override=True)
class cert_find(MethodOverride):
    takes_options = (
        File(
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
                options['certificate'] = x509.strip_header(options.pop('file'))

        return super(cert_find, self).forward(*args, **options)
