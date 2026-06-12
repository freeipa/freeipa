# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
from ipalib import errors, Str
from ipalib.plugable import Registry
from ipalib import x509
from ipalib import _
from ipalib import util

register = Registry()


@register(override=True, no_fail=True)
class service_show(MethodOverride):
    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])
            result = super(service_show, self).forward(*keys, **options)
            if 'usercertificate' in result['result']:
                certs = (x509.load_der_x509_certificate(c)
                         for c in result['result']['usercertificate'])
                x509.write_certificate_list(certs, options['out'])
                result['summary'] = (
                    _('Certificate(s) stored in file \'%(file)s\'')
                    % dict(file=options['out'])
                )
                return result
            else:
                raise errors.NoCertificateError(entry=keys[-1])
        else:
            return super(service_show, self).forward(*keys, **options)


@register(override=True, no_fail=True)
class service_add_attestation_key(MethodOverride):
    def get_options(self):
        for option in super(service_add_attestation_key, self).get_options():
            if option.name == 'ipakrbserviceattestationkey':
                continue
            yield option
        yield Str(
            'pubkeyfile*',
            cli_name='pubkey',
            label=_('Public key file'),
            doc=_('PEM file containing the SubjectPublicKeyInfo public key'),
            include='cli',
        )

    def forward(self, *keys, **options):
        pubkeyfiles = options.pop('pubkeyfile', None)
        if pubkeyfiles:
            if not isinstance(pubkeyfiles, (list, tuple)):
                pubkeyfiles = [pubkeyfiles]
            options['ipakrbserviceattestationkey'] = [
                x509.load_public_key_from_file(f) for f in pubkeyfiles
            ]
        return super(service_add_attestation_key, self).forward(
            *keys, **options)


@register(override=True, no_fail=True)
class service_remove_attestation_key(MethodOverride):
    def get_options(self):
        for option in super(service_remove_attestation_key,
                            self).get_options():
            if option.name == 'ipakrbserviceattestationkey':
                continue
            yield option
        yield Str(
            'pubkeyfile*',
            cli_name='pubkey',
            label=_('Public key file'),
            doc=_('PEM file containing the SubjectPublicKeyInfo public key'),
            include='cli',
        )

    def forward(self, *keys, **options):
        pubkeyfiles = options.pop('pubkeyfile', None)
        if pubkeyfiles:
            if not isinstance(pubkeyfiles, (list, tuple)):
                pubkeyfiles = [pubkeyfiles]
            options['ipakrbserviceattestationkey'] = [
                x509.load_public_key_from_file(f) for f in pubkeyfiles
            ]
        return super(service_remove_attestation_key, self).forward(
            *keys, **options)
