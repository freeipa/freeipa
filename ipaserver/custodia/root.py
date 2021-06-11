# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import json

from custodia.plugin import HTTPConsumer, PluginOption
from custodia.secrets import Secrets


class Root(HTTPConsumer):
    store = PluginOption('store', None, None)

    def __init__(self, config, section):
        super(Root, self).__init__(config, section)
        if self.store_name is not None:
            self.add_sub('secrets', Secrets(config, section))

    def GET(self, request, response):
        msg = json.dumps({'message': "Quis custodiet ipsos custodes?"})
        return msg.encode('utf-8')
