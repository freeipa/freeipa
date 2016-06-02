#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from . import schema


def get_package(api):
    if api.env.in_tree:
        from ipalib import plugins
    else:
        plugins = schema.get_package(api)

    return plugins
