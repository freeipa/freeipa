#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import errors
from ipalib import util
from ipalib import x509
from ipalib.parameters import BinaryFile, Str
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


class IdpOverride(MethodOverride):
    takes_options = (
        BinaryFile(
            'client_cert_p12_file?',
            label=_("Input filename"),
            doc=_('File to load the PKCS12 bundle from.'),
            include='cli',
        ),
    )

    def interactive_prompt_callback(self, kw):
        # Password is required when the PKCS12 bundle is provided
        if kw.get('client_cert_p12_file', None) and \
           not kw.get('ipaidpclientsecret', None):
            kw['ipaidpclientsecret'] = self.Backend.textui.prompt_password(
                _("PKCS#12 password"), confirm=False,
            )

    def forward(self, *args, **options):
        if self.api.env.context == 'cli':
            if 'client_cert_p12_file' in options:
                # Secret is required to open the PKCS12 bundle
                if 'ipaidpclientsecret' not in options:
                    raise errors.RequirementError(name='secret')

                # Fill the client_cert_p12 option with the bytes
                p12file_data = options.get('client_cert_p12_file')
                options['userpkcs12'] = p12file_data
                del options['client_cert_p12_file']

        return super(IdpOverride, self).forward(*args, **options)


@register(override=True, no_fail=True)
class idp_add(IdpOverride):
    pass


@register(override=True, no_fail=True)
class idp_mod(IdpOverride):
    pass


@register(override=True, no_fail=True)
class idp_show(MethodOverride):
    takes_options = (
        Str(
            'out?',
            doc=_('Write certificate to file'),
            include='cli',
            cli_metavar='FILE',
        ),
    )

    def forward(self, *args, **options):
        filename = None
        if 'out' in options:
            filename = options.pop('out')

        result = super(idp_show, self).forward(*args, **options)

        if filename is not None:
            try:
                util.check_writable_file(filename)
            except errors.FileError as e:
                raise errors.ValidationError(name='out',
                                             error=str(e))
            try:
                cert = result['result']['usercertificate'][0]
                x509cert = x509.load_der_x509_certificate(cert)
                x509.write_certificate(x509cert, filename)
            except KeyError:
                self.Backend.textui.print_plain(_(
                    "Idp has no certificate, ignoring --out option"))
        return result
