# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Misc plugins
"""

import re
from ipalib import api, LocalOrRemote, _, ngettext
from ipalib.output import Output, summary

# FIXME: We should not let env return anything in_server
# when mode == 'production'.  This would allow an attacker to see the
# configuration of the server, potentially revealing compromising
# information.  However, it's damn handy for testing/debugging.


class env(LocalOrRemote):
    """Show environment variables"""

    msg_summary = _('%(count)d variables')

    takes_args = (
        'variables*',
    )

    has_output = (
        Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
        Output('total',
            type=int,
            doc=_('Total number of variables env (>= count)'),
        ),
        Output('count',
            type=int,
            doc=_('Number of variables returned (<= total)'),
        ),
        summary,
    )

    def __find_keys(self, variables):
        keys = set()
        for query in variables:
            if '*' in query:
                pat = re.compile(query.replace('*', '.*') + '$')
                for key in self.env:
                    if pat.match(key):
                        keys.add(key)
            elif query in self.env:
                keys.add(query)
        return keys

    def execute(self, variables, **options):
        if variables is None:
            keys = self.env
        else:
            keys = self.__find_keys(variables)
        ret = dict(
            result=dict(
                (key, self.env[key]) for key in keys
            ),
            count=len(keys),
            total=len(self.env),
        )
        if len(keys) > 1:
            ret['summary'] = self.msg_summary % ret
        else:
            ret['summary'] = None
        return ret

api.register(env)


class plugins(LocalOrRemote):
    """Show all loaded plugins"""

    msg_summary = ngettext(
        '%(count)d plugin loaded', '%(count)d plugins loaded'
    )

    has_output = (
        Output('result', dict, 'Dictionary mapping plugin names to bases'),
        Output('count',
            type=int,
            doc=_('Number of plugins loaded'),
        ),
        summary,
    )

    def execute(self, **options):
        plugins = sorted(self.api.plugins, key=lambda o: o.plugin)
        return dict(
            result=dict(
                (p.plugin, p.bases) for p in plugins
            ),
            count=len(plugins),
        )

api.register(plugins)
