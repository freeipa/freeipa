#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from ipalib import Object
from ipalib import _, ngettext
from ipalib.crud import Search
from ipalib.parameters import Int, Str, StrEnum
from ipalib.plugable import Registry

register = Registry()

__doc__ = _("""
Kerberos PKINIT feature status reporting tools.

Report IPA masters on which Kerberos PKINIT is enabled or disabled

EXAMPLES:
 List PKINIT status on all masters:
   ipa pkinit-status

 Check PKINIT status on `ipa.example.com`:
   ipa pkinit-status --server ipa.example.com

 List all IPA masters with disabled PKINIT:
   ipa pkinit-status --status='disabled'

For more info about PKINIT support see:

https://www.freeipa.org/page/V4/Kerberos_PKINIT
""")


@register()
class pkinit(Object):
    """
    PKINIT Options
    """
    object_name = _('pkinit')

    label = _('PKINIT')

    takes_params = (
        Str(
            'server_server?',
            cli_name='server',
            label=_('Server name'),
            doc=_('IPA server hostname'),
        ),
        StrEnum(
            'status?',
            cli_name='status',
            label=_('PKINIT status'),
            doc=_('Whether PKINIT is enabled or disabled'),
            values=(u'enabled', u'disabled'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        )
    )


@register()
class pkinit_status(Search):
    __doc__ = _('Report PKINIT status on the IPA masters')

    msg_summary = ngettext('%(count)s server matched',
                           '%(count)s servers matched', 0)

    takes_options = Search.takes_options + (
        Int(
            'timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
        Int(
            'sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
    )

    def get_pkinit_status(self, server, status):
        backend = self.api.Backend.serverroles
        ipa_master_config = backend.config_retrieve("IPA master")

        if server is not None:
            servers = [server]
        else:
            servers = ipa_master_config.get('ipa_master_server', [])

        pkinit_servers = ipa_master_config.get('pkinit_server_server')
        if pkinit_servers is None:
            return

        for s in servers:
            pkinit_status = {
                u'server_server': s,
                u'status': (
                    u'enabled' if s in pkinit_servers else u'disabled'
                )
            }
            if status is not None and pkinit_status[u'status'] != status:
                continue

            yield pkinit_status

    def execute(self, *keys, **options):
        if keys:
            return dict(
                result=[],
                count=0,
                truncated=False
            )

        server = options.get('server_server', None)
        status = options.get('status', None)

        if server is not None:
            self.api.Object.server_role.ensure_master_exists(server)

        result = sorted(self.get_pkinit_status(server, status),
                        key=lambda d: d.get('server_server'))

        return dict(result=result, count=len(result), truncated=False)
