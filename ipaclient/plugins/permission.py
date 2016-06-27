#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib.plugable import Registry

register = Registry()


class PermissionMethodOverride(MethodOverride):
    def get_options(self):
        for option in super(PermissionMethodOverride, self).get_options():
            if option.name == 'ipapermright':
                option = option.clone(deprecated_cli_aliases={'permissions'})
            yield option


@register(override=True, no_fail=True)
class permission_add(PermissionMethodOverride):
    pass


@register(override=True, no_fail=True)
class permission_mod(PermissionMethodOverride):
    pass


@register(override=True, no_fail=True)
class permission_find(PermissionMethodOverride):
    pass
