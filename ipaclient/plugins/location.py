#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import MethodOverride
from ipalib import _
from ipalib.plugable import Registry


register = Registry()


@register(override=True, no_fail=True)
class location_show(MethodOverride):
    def output_for_cli(self, textui, output, *keys, **options):
        rv = super(location_show, self).output_for_cli(
            textui, output, *keys, **options)

        servers = output.get('servers', {})
        first = True
        for details in servers.values():
            if first:
                textui.print_indented(_("Servers details:"), indent=1)
                first = False
            else:
                textui.print_line("")

            for param in self.api.Command.server_find.output_params():
                if param.name in details:
                    textui.print_indented(
                        u"{}: {}".format(
                            param.label, u', '.join(details[param.name])),
                        indent=2)

        return rv
