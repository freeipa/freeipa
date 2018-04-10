#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import base64

import six

from ipalib import api
from ipalib import errors
from ipalib import output
from ipalib import util
from ipalib.frontend import Local, Str
from ipalib.parameters import Bytes, Principal
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
        Bytes(
            'public_key_info',
            label=_('Subject Public Key Info'),
            doc=_('DER-encoded SubjectPublicKeyInfo structure'),
        ),
        Str(
            'out?',
            doc=_('Write CertificationRequestInfo to file'),
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
            'request_info',
            label=_('CertificationRequestInfo structure'),
        )
    )

    def execute(self, *args, **options):
        # Deferred import, ipaclient.csrgen is expensive to load.
        # see https://pagure.io/freeipa/issue/7484
        from ipaclient import csrgen
        from ipaclient import csrgen_ffi

        if 'out' in options:
            util.check_writable_file(options['out'])

        principal = options.get('principal')
        profile_id = options.get('profile_id')
        if profile_id is None:
            profile_id = dogtag.DEFAULT_PROFILE
        public_key_info = options.get('public_key_info')
        public_key_info = base64.b64decode(public_key_info)

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

        generator = csrgen.CSRGenerator(csrgen.FileRuleProvider())

        csr_config = generator.csr_config(principal_obj, config, profile_id)
        request_info = base64.b64encode(csrgen_ffi.build_requestinfo(
            csr_config.encode('utf8'), public_key_info))

        result = {}
        if 'out' in options:
            with open(options['out'], 'wb') as f:
                f.write(request_info)
        else:
            result = dict(request_info=request_info)

        return dict(
            result=result
        )
