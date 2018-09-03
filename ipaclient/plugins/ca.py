#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
import base64

from ipaclient.frontend import MethodOverride
from ipalib import errors, util, x509, Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


class WithCertOutArgs(MethodOverride):

    takes_options = (
        Str(
            'certificate_out?',
            doc=_('Write certificate (chain if --chain used) to file'),
            include='cli',
            cli_metavar='FILE',
        ),
    )

    def forward(self, *keys, **options):
        filename = None
        if 'certificate_out' in options:
            filename = options.pop('certificate_out')
            try:
                util.check_writable_file(filename)
            except errors.FileError as e:
                raise errors.ValidationError(name='certificate-out',
                                             error=str(e))

        result = super(WithCertOutArgs, self).forward(*keys, **options)
        if filename:
            if options.get('chain', False):
                certs = result['result']['certificate_chain']
            else:
                certs = [result['result']['certificate']]
            certs = (x509.load_der_x509_certificate(base64.b64decode(cert))
                     for cert in certs)
            x509.write_certificate_list(certs, filename)

        return result


@register(override=True, no_fail=True)
class ca_add(WithCertOutArgs):
    pass


@register(override=True, no_fail=True)
class ca_show(WithCertOutArgs):
    pass
