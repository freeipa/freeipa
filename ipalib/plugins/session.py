#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import Command
from ipalib.request import context
from ipalib.session import session_mgr
from ipalib.plugable import Registry

register = Registry()


@register()
class session_logout(Command):
    '''
    RPC command used to log the current user out of their session.
    '''
    NO_CLI = True

    def execute(self, *args, **options):
        session_data = getattr(context, 'session_data', None)
        if session_data is None:
            self.debug('session logout command: no session_data found')
        else:
            session_id = session_data.get('session_id')
            self.debug('session logout command: session_id=%s', session_id)

            # Notifiy registered listeners
            session_mgr.auth_mgr.logout(session_data)

        return dict(result=None)
