# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

from ipaserver.custodia import log
from ipaserver.custodia.plugin import HTTPAuthenticator, PluginOption


class SimpleCredsAuth(HTTPAuthenticator):
    uid = PluginOption('pwd_uid', -1, "User id or name, -1 ignores user")
    gid = PluginOption('grp_gid', -1, "Group id or name, -1 ignores group")

    def handle(self, request):
        creds = request.get('creds')
        if creds is None:
            self.logger.debug('SCA: Missing "creds" from request')
            return False
        uid = int(creds['uid'])
        gid = int(creds['gid'])
        uid_match = self.uid != -1 and self.uid == uid
        gid_match = self.gid != -1 and self.gid == gid
        if uid_match or gid_match:
            self.audit_svc_access(log.AUDIT_SVC_AUTH_PASS,
                                  request['client_id'],
                                  "%d, %d" % (uid, gid))
            return True
        else:
            self.audit_svc_access(log.AUDIT_SVC_AUTH_FAIL,
                                  request['client_id'],
                                  "%d, %d" % (uid, gid))
            return False


class SimpleHeaderAuth(HTTPAuthenticator):
    header = PluginOption(str, 'REMOTE_USER', "header name")
    value = PluginOption('str_set', None,
                         "Comma-separated list of required values")

    def handle(self, request):
        if self.header not in request['headers']:
            self.logger.debug('SHA: No "headers" in request')
            return None
        value = request['headers'][self.header]
        if self.value is not None:
            if value not in self.value:
                self.audit_svc_access(log.AUDIT_SVC_AUTH_FAIL,
                                      request['client_id'], value)
                return False

        self.audit_svc_access(log.AUDIT_SVC_AUTH_PASS,
                              request['client_id'], value)
        request['remote_user'] = value
        return True
