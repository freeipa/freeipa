#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import _
from ipalib.plugable import Registry

register = Registry()


@register(override=True)
class server_del(MethodOverride):
    def interactive_prompt_callback(self, kw):
        self.api.Backend.textui.print_plain(
            _("Removing %(servers)s from replication topology, "
              "please wait...") % {'servers': ', '.join(kw['cn'])})
