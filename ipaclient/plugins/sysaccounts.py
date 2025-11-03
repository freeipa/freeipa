# Copyright (C) 2025  Red Hat
# see file 'COPYING' for use and warranty information

from ipaclient.frontend import MethodOverride
from ipalib.plugable import Registry

register = Registry()


@register(override=True, no_fail=True)
class sysaccount_add(MethodOverride):
    def interactive_prompt_callback(self, kw):
        if not (kw.get('random', False) or kw.get('userpassword', False)):
            kw['userpassword'] = self.Backend.textui.prompt_password(
                self.params['userpassword'].label
            )
