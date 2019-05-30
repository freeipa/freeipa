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
            # if result certificate / certificate_chain not present in result,
            # it means Dogtag did not provide it (probably due to LWCA key
            # replication lag or failure.  The server transmits a warning
            # message in this case, which the client automatically prints.
            # So in this section we just ignore it and move on.
            certs = None
            if options.get('chain', False):
                if 'certificate_chain' in result['result']:
                    certs = result['result']['certificate_chain']
            else:
                if 'certificate' in result['result']:
                    certs = [base64.b64decode(result['result']['certificate'])]
            if certs:
                x509.write_certificate_list(
                    (x509.load_der_x509_certificate(cert) for cert in certs),
                    filename)

        return result


@register(override=True, no_fail=True)
class ca_add(WithCertOutArgs):
    pass


@register(override=True, no_fail=True)
class ca_show(WithCertOutArgs):
    pass
