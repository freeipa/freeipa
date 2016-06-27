#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import CommandOverride
from ipalib.plugable import Registry

register = Registry()


@register(override=True, no_fail=True)
class passwd(CommandOverride):
    def get_args(self):
        for arg in super(passwd, self).get_args():
            if arg.name == 'current_password':
                arg = arg.clone(sortorder=-1)
            yield arg
