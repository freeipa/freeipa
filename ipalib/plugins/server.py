#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import string
import os

from ipalib import api
from ipalib import Int, Str
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib.plugins import baseldap
from ipalib import _, ngettext

__doc__ = _("""
IPA servers
""") + _("""
Get information about installed IPA servers.
""") + _("""
EXAMPLES:
""") + _("""
  Find all servers:
    ipa server-find
""") + _("""
  Show specific server:
    ipa server-show ipa.example.com
""")

register = Registry()


@register()
class server(LDAPObject):
    """
    IPA server
    """
    container_dn = api.env.container_masters
    object_name = _('server')
    object_name_plural = _('servers')
    object_class = ['top']
    default_attributes = [
        'cn', 'iparepltopomanagedsuffix', 'ipamindomainlevel',
        'ipamaxdomainlevel'
    ]
    label = _('IPA Servers')
    label_singular = _('IPA Server')
    takes_params = (
        Str(
            'cn',
            cli_name='name',
            primary_key=True,
            label=_('Server name'),
            doc=_('IPA server hostname'),
        ),
        Str(
            'iparepltopomanagedsuffix',
            cli_name='suffix',
            label=_('Managed suffix'),
        ),
        Int(
            'ipamindomainlevel',
            cli_name='minlevel',
            label=_('Min domain level'),
            doc=_('Minimum domain level'),
            flags={'no_create', 'no_update'},
        ),
        Int(
            'ipamaxdomainlevel',
            cli_name='maxlevel',
            label=_('Max domain level'),
            doc=_('Maximum domain level'),
            flags={'no_create', 'no_update'},
        ),
    )


@register()
class server_find(LDAPSearch):
    __doc__ = _('Search for IPA servers.')

    msg_summary = ngettext(
        '%(count)d IPA server matched',
        '%(count)d IPA servers matched', 0
    )


@register()
class server_show(LDAPRetrieve):
    __doc__ = _('Show IPA server.')


@register()
class server_del(LDAPDelete):
    __doc__ = _('Delete IPA server.')
    NO_CLI = True
    msg_summary = _('Deleted IPA server "%(value)s"')
