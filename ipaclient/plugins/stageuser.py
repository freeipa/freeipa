#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#
from ipaclient.plugins.baseuser import baseuser_add_passkey
from ipalib.plugable import Registry
from ipalib import _


register = Registry()


@register(override=True, no_fail=True)
class stageuser_add_passkey(baseuser_add_passkey):
    __doc__ = _("Add one or more passkey mappings to the user entry.")
