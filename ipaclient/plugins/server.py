#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import _, errors
from ipalib.plugable import Registry

register = Registry()


@register(override=True, no_fail=True)
class server_del(MethodOverride):
    def interactive_prompt_callback(self, kw):
        server_list = kw.get('cn')
        if not server_list:
            raise errors.RequirementError(name='cn')

        self.api.Backend.textui.print_plain(
            _("Removing %(servers)s from replication topology, "
              "please wait...") % {'servers': ', '.join(server_list)})
