#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import six

from ipaclient.csrgen import CSRGenerator, FileRuleProvider
from ipalib import api
from ipalib import errors
from ipalib import output
from ipalib import util
from ipalib.frontend import Local, Str
from ipalib.parameters import Principal
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython import dogtag

if six.PY3:
    unicode = str

register = Registry()

__doc__ = _("""
Commands to build certificate requests automatically
""")


@register()
class cert_get_requestdata(Local):
    __doc__ = _('Gather data for a certificate signing request.')

    NO_CLI = True

    takes_options = (
        Principal(
            'principal',
            label=_('Principal'),
            doc=_('Principal for this certificate (e.g.'
                  ' HTTP/test.example.com)'),
        ),
        Str(
            'profile_id?',
            label=_('Profile ID'),
            doc=_('CSR Generation Profile to use'),
        ),
        Str(
            'helper',
            label=_('Name of CSR generation tool'),
            doc=_('Name of tool (e.g. openssl, certutil) that will be used to'
                  ' create CSR'),
        ),
        Str(
            'out?',
            doc=_('Write CSR generation script to file'),
        ),
    )

    has_output = (
        output.Output(
            'result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    has_output_params = (
        Str(
            'script',
            label=_('Generation script'),
        )
    )

    def execute(self, *args, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])

        principal = options.get('principal')
        profile_id = options.get('profile_id')
        if profile_id is None:
            profile_id = dogtag.DEFAULT_PROFILE
        helper = options.get('helper')

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect()

        try:
            if principal.is_host:
                principal_obj = api.Command.host_show(
                    principal.hostname, all=True)
            elif principal.is_service:
                principal_obj = api.Command.service_show(
                    unicode(principal), all=True)
            elif principal.is_user:
                principal_obj = api.Command.user_show(
                    principal.username, all=True)
        except errors.NotFound:
            raise errors.NotFound(
                reason=_("The principal for this request doesn't exist."))
        principal_obj = principal_obj['result']
        config = api.Command.config_show()['result']

        generator = CSRGenerator(FileRuleProvider())

        script = generator.csr_script(
            principal_obj, config, profile_id, helper)

        result = {}
        if 'out' in options:
            with open(options['out'], 'wb') as f:
                f.write(script)
        else:
            result = dict(script=script)

        return dict(
            result=result
        )
