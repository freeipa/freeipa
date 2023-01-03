#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import errors
from ipalib import x509
from ipalib import util
from ipalib.parameters import Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


class CACertRetrieveOverride(MethodOverride):
    takes_options = (
        Str(
            'cacertificate_out?',
            doc=_('Write CA certificates to file'),
            include='cli',
            cli_metavar='FILE',
        ),
    )

    def forward(self, *args, **options):
        if 'cacertificate_out' in options:
            cacertificate_out = options.pop('cacertificate_out')
            try:
                util.check_writable_file(cacertificate_out)
            except errors.FileError as e:
                raise errors.ValidationError(name='cacertificate-out',
                                             error=str(e))
        else:
            cacertificate_out = None

        result = super(CACertRetrieveOverride, self).forward(*args, **options)

        if cacertificate_out is not None:
            if isinstance(result['result'], (list, tuple)):
                cacerts_der = [
                    entry['cacertificate;binary'][0]
                    for entry in result['result']
                ]
            else:
                cacerts_der = [result['result']['cacertificate;binary'][0]]
            cacerts = [
                x509.load_der_x509_certificate(der)
                for der in cacerts_der
            ]
            x509.write_certificate_list(cacerts, cacertificate_out)

        return result


@register(override=True, no_fail=True)
class trustedca_show(CACertRetrieveOverride):
    pass


@register(override=True, no_fail=True)
class trustedca_find(CACertRetrieveOverride):
    pass
