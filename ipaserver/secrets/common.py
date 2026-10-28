# Copyright (C) 2015  IPA Project Contributors, see COPYING for license
from __future__ import print_function
import ldap
import ldap.sasl
import ldap.filter

from ipapython.ipaldap import ldap_initialize


class iSecLdap:

    def __init__(self, uri, auth_type=None):
        self.uri = uri
        if auth_type is not None:
            self.auth_type = auth_type
        else:
            if uri.startswith('ldapi'):
                self.auth_type = 'EXTERNAL'
            else:
                self.auth_type = 'GSSAPI'
        self._basedn = None

    @property
    def basedn(self):
        if self._basedn is None:
            conn = self.connect()
            r = conn.search_s('', ldap.SCOPE_BASE)
            self._basedn = r[0][1]['defaultnamingcontext'][0].decode('utf-8')
        return self._basedn

    def connect(self):
        conn = ldap_initialize(self.uri)
        if self.auth_type == 'EXTERNAL':
            auth_tokens = ldap.sasl.external(None)
        elif self.auth_type == 'GSSAPI':
            auth_tokens = ldap.sasl.sasl({}, 'GSSAPI')
        else:
            raise ValueError(
                'Invalid authentication type: %s' % self.auth_type)
        conn.sasl_interactive_bind_s('', auth_tokens)
        return conn

    def build_filter(self, formatstr, args):
        escaped_args = dict()
        for key, value in args.items():
            escaped_args[key] = ldap.filter.escape_filter_chars(value)
        return formatstr.format(**escaped_args)
