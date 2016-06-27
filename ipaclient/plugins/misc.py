#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipaclient.frontend import CommandOverride
from ipalib.plugable import Registry

register = Registry()


@register(override=True, no_fail=True)
class env(CommandOverride):
    def output_for_cli(self, textui, output, *args, **options):
        output = dict(output)
        output.pop('count', None)
        output.pop('total', None)
        options['all'] = True
        return super(env, self).output_for_cli(textui, output,
                                               *args, **options)


@register(override=True, no_fail=True)
class plugins(CommandOverride):
    def output_for_cli(self, textui, output, *args, **options):
        options['all'] = True
        return super(plugins, self).output_for_cli(textui, output,
                                                   *args, **options)
