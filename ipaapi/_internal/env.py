#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FreeIPA API package -- internal API wrapper
"""
from __future__ import absolute_import

from .common import APIMapping


class Env(APIMapping):
    """IPA API environment variables
    """

    __slots__ = ()

    _attributes = frozenset(
        [
            "api_version",
            "basedn",
            "ca_host",
            "conf",
            "confdir",
            "context",
            "debug",
            "domain",
            "fips_mode",
            "force_schema_check",
            "host",
            "in_server",
            "jsonrpc_uri",
            "ldap_uri",
            "realm",
            "server",
            "tls_ca_cert",
            "verbose",
            "version",
            "verbose",
            "xmlrpc_uri",
        ]
    )

    def __dir__(self):
        items = set(super(Env, self).__dir__())
        items.update(self._attributes)
        return sorted(items)

    def __getattr__(self, item):
        if item in self._attributes:
            return getattr(self._api.env, item, None)
        else:
            raise AttributeError(item)

    def __getitem__(self, item):
        if item in self._attributes:
            return getattr(self._api.env, item, None)
        else:
            raise KeyError(item)

    def __len__(self):
        return len(self._attributes)

    def __iter__(self):
        return iter(self._attributes)
