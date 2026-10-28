# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import os

from ipaserver.custodia import log
from ipaserver.custodia.plugin import HTTPAuthorizer


class SimplePathAuthz(HTTPAuthorizer):
    # keep SimplePathAuthz an old-style plugin for now.
    # KEMKeysStore and IPAKEMKeys haven't been ported.

    def __init__(self, config):
        super(SimplePathAuthz, self).__init__(config)
        self.paths = []
        if 'paths' in self.config:
            self.paths = self.config['paths'].split()

    def handle(self, request):
        reqpath = path = request.get('path', '')

        # if an authorized path does not end in /
        # check if it matches fullpath for strict match
        for authz in self.paths:
            if authz.endswith('/'):
                continue
            if authz.endswith('.'):
                # special case to match a path ending in /
                authz = authz[:-1]
            if authz == path:
                self.audit_svc_access(log.AUDIT_SVC_AUTHZ_PASS,
                                      request['client_id'], path)
                return True

        while path != '':
            if path in self.paths:
                self.audit_svc_access(log.AUDIT_SVC_AUTHZ_PASS,
                                      request['client_id'], path)
                return True
            if path == '/':
                path = ''
            else:
                path, _head = os.path.split(path)

        self.logger.debug('No path in %s matched %s', self.paths, reqpath)
        return None
