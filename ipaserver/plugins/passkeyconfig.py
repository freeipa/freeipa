#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

import logging

from ipalib import api
from ipalib.parameters import Bool
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPRetrieve,
    LDAPUpdate)
from ipalib import _


logger = logging.getLogger(__name__)

__doc__ = _("""
Passkey configuration
""") + _("""
Manage Passkey configuration.
""") + _("""
IPA supports the use of passkeys for authentication. A passkey
device has to be registered to SSSD and the resulting authentication mapping
stored in the user entry.
The passkey authentication supports the following configuration option:
require user verification. When set, the method for user verification depends
on the type of device (PIN, fingerprint, external pad...)
""") + _("""
EXAMPLES:
""") + _("""
 Display the Passkey configuration:
   ipa passkeyconfig-show
""") + _("""
 Modify the Passkey configuration to always require user verification:
   ipa passkeyconfig-mod --require-user-verification=TRUE
""")

register = Registry()


@register()
class passkeyconfig(LDAPObject):
    """
    Passkey configuration object
    """
    object_name = _('Passkey configuration options')
    default_attributes = ['iparequireuserverification']

    container_dn = api.env.container_passkey
    label = _('Passkey Configuration')
    label_singular = _('Passkey Configuration')

    takes_params = (
        Bool(
            'iparequireuserverification',
            cli_name="require_user_verification",
            label=_("Require user verification"),
            doc=_('Require user verification during authentication'),
        ),
    )

    permission_filter_objectclasses = ['ipapasskeyconfigobject']
    managed_permissions = {
        'System: Read Passkey Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'iparequireuserverification',
                'cn',
            },
        },
        'System: Modify Passkey Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'iparequireuserverification',
            },
            'default_privileges': {
                'Passkey Administrators'},
        },
    }


@register()
class passkeyconfig_mod(LDAPUpdate):
    __doc__ = _("Modify Passkey configuration.")


@register()
class passkeyconfig_show(LDAPRetrieve):
    __doc__ = _("Show the current Passkey configuration.")
