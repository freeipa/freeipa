#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import errors, x509
from ipalib.parameters import BinaryFile
from ipalib.plugable import Registry
from ipalib.text import _

register = Registry()


@register(override=True, no_fail=True)
class certmap_match(MethodOverride):
    takes_args = (
        BinaryFile(
            'file?',
            label=_("Input file"),
            doc=_("File to load the certificate from"),
            include='cli',
        ),
    )

    def get_args(self):
        for arg in super(certmap_match, self).get_args():
            if arg.name != 'certificate' or self.api.env.context != 'cli':
                yield arg

    def get_options(self):
        for arg in super(certmap_match, self).get_args():
            if arg.name == 'certificate' and self.api.env.context == 'cli':
                yield arg.clone(required=False)
        for option in super(certmap_match, self).get_options():
            yield option

    def forward(self, *args, **options):
        if self.api.env.context == 'cli':
            if args and 'certificate' in options:
                raise errors.MutuallyExclusiveError(
                    reason=_("cannot specify both raw certificate and file"))
            if args:
                args = [x509.load_unknown_x509_certificate(args[0])]
            elif 'certificate' in options:
                args = [options.pop('certificate')]
            else:
                args = []

        return super(certmap_match, self).forward(*args, **options)
