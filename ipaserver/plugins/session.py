#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import Command
from ipalib.request import context
from ipalib.plugable import Registry

register = Registry()


@register()
class session_logout(Command):
    '''
    RPC command used to log the current user out of their session.
    '''
    NO_CLI = True

    def execute(self, *args, **options):
        ccache_name = getattr(context, 'ccache_name', None)
        if ccache_name is None:
            self.debug('session logout command: no ccache_name found')
        else:
            delattr(context, 'ccache_name')

        setattr(context, 'logout_cookie', 'MagBearerToken=')

        return dict(result=None)
