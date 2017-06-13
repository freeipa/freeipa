#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import six

from ipaclient.frontend import MethodOverride
from ipalib.plugable import Registry
from ipalib import _

if six.PY3:
    unicode = str

register = Registry()


@register(override=True, no_fail=True)
class topologysuffix_verify(MethodOverride):
    def output_for_cli(self, textui, output, *args, **options):

        connect_errors = output['result']['connect_errors']
        max_agmts_errors = output['result']['max_agmts_errors']

        if not connect_errors and not max_agmts_errors:
            header = _('Replication topology of suffix "%(suffix)s" '
                       'is in order.')
            textui.print_h1(header % {'suffix': args[0]})

        if connect_errors:
            header = _('Replication topology of suffix "%(suffix)s" contains '
                       'errors.')
            textui.print_h1(header % {'suffix': args[0]})
            textui.print_dashed(unicode(_('Topology is disconnected')))
            for err in connect_errors:
                msg = _("Server %(srv)s can't contact servers: %(replicas)s")
                msg = msg % {'srv': err[0], 'replicas': ', '.join(err[2])}
                textui.print_indented(msg)

        if max_agmts_errors:
            textui.print_dashed(unicode(_('Recommended maximum number of '
                                          'agreements per replica exceeded')))
            textui.print_attribute(
                unicode(_("Maximum number of agreements per replica")),
                [output['result']['max_agmts']]
            )
            for err in max_agmts_errors:
                msg = _('Server "%(srv)s" has %(n)d agreements with servers:')
                msg = msg % {'srv': err[0], 'n': len(err[1])}
                textui.print_indented(msg)
                for replica in err[1]:
                    textui.print_indented(replica, 2)

        return 0
