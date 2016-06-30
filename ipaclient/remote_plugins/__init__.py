#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from . import compat
from . import schema
from ipaclient.plugins.rpcclient import rpcclient


def get_package(api):
    if api.env.in_tree:
        from ipaserver import plugins
    else:
        client = rpcclient(api)
        client.finalize()
        try:
            plugins = schema.get_package(api, client)
        except schema.NotAvailable:
            plugins = compat.get_package(api, client)
        finally:
            if client.isconnected():
                client.disconnect()

    return plugins
