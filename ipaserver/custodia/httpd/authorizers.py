# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import os

from custodia import log
from custodia.plugin import HTTPAuthorizer, PluginOption


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
        for authz in self.paths:  # pylint: disable=not-an-iterable
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
            # pylint: disable=unsupported-membership-test
            if path in self.paths:
                self.audit_svc_access(log.AUDIT_SVC_AUTHZ_PASS,
                                      request['client_id'], path)
                return True
            if path == '/':
                path = ''
            else:
                path, _ = os.path.split(path)

        self.logger.debug('No path in %s matched %s', self.paths, reqpath)
        return None


class UserNameSpace(HTTPAuthorizer):
    path = PluginOption(str, '/', 'User namespace path')
    store = PluginOption('store', None, None)

    def handle(self, request):
        # Only check if we are in the right (sub)path
        path = request.get('path', '/')
        if not path.startswith(self.path):
            self.logger.debug('%s is not contained in %s', path, self.path)
            return None

        name = request.get('remote_user', None)
        if name is None:
            # UserNameSpace requires a user ...
            self.audit_svc_access(log.AUDIT_SVC_AUTHZ_FAIL,
                                  request['client_id'], path)
            return False

        # pylint: disable=no-member
        namespace = self.path.rstrip('/') + '/' + name + '/'
        if not path.startswith(namespace):
            # Not in the namespace
            self.audit_svc_access(log.AUDIT_SVC_AUTHZ_FAIL,
                                  request['client_id'], path)
            return False

        request['default_namespace'] = name
        self.audit_svc_access(log.AUDIT_SVC_AUTHZ_PASS,
                              request['client_id'], path)
        return True
