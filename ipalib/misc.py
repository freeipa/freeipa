#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import re
from ipalib import LocalOrRemote, _, ngettext
from ipalib.output import Output, summary
from ipalib import Flag
from ipalib.plugable import Registry

register = Registry()

# FIXME: We should not let env return anything in_server
# when mode == 'production'.  This would allow an attacker to see the
# configuration of the server, potentially revealing compromising
# information.  However, it's damn handy for testing/debugging.


class env(LocalOrRemote):
    __doc__ = _('Show environment variables.')

    msg_summary = _('%(count)d variables')

    takes_args = (
        'variables*',
    )

    takes_options = LocalOrRemote.takes_options + (
        Flag(
            'all',
            cli_name='all',
            doc=_('retrieve and print all attributes from the server. '
                  'Affects command output.'),
            exclude='webui',
            flags=['no_option', 'no_output'],
            default=True,
        ),
    )

    has_output = (
        Output(
            'result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
        Output(
            'total',
            type=int,
            doc=_('Total number of variables env (>= count)'),
            flags=['no_display'],
        ),
        Output(
            'count',
            type=int,
            doc=_('Number of variables returned (<= total)'),
            flags=['no_display'],
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

    def execute(self, variables=None, **options):
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


class plugins(LocalOrRemote):
    __doc__ = _('Show all loaded plugins.')

    msg_summary = ngettext(
        '%(count)d plugin loaded', '%(count)d plugins loaded', 0
    )

    takes_options = LocalOrRemote.takes_options + (
        Flag(
            'all',
            cli_name='all',
            doc=_('retrieve and print all attributes from the server. '
                  'Affects command output.'),
            exclude='webui',
            flags=['no_option', 'no_output'],
            default=True,
        ),
    )

    has_output = (
        Output('result', dict, 'Dictionary mapping plugin names to bases'),
        Output(
            'count',
            type=int,
            doc=_('Number of plugins loaded'),
        ),
        summary,
    )

    def execute(self, **options):
        result = {}
        for namespace in self.api:
            for plugin in self.api[namespace]():
                cls = type(plugin)
                key = '{}.{}'.format(cls.__module__, cls.__name__)
                result.setdefault(key, []).append(namespace.decode('utf-8'))

        return dict(
            result=result,
            count=len(result),
        )
