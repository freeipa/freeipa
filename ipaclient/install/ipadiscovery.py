#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import warnings

from ipaclient.discovery import (
    NOT_FQDN, NO_LDAP_SERVER, REALM_NOT_FOUND, NOT_IPA_SERVER,
    NO_ACCESS_TO_LDAP, NO_TLS_LDAP, BAD_HOST_CONFIG,
    UNKNOWN_ERROR, IPA_BASEDN_INFO, error_names, get_ipa_basedn,
    IPADiscovery
)

__all__ = (
    'NOT_FQDN', 'NO_LDAP_SERVER', 'REALM_NOT_FOUND',
    'NOT_IPA_SERVER', 'NO_ACCESS_TO_LDAP', 'NO_TLS_LDAP',
    'BAD_HOST_CONFIG', 'UNKNOWN_ERROR', 'IPA_BASEDN_INFO',
    'error_names', 'get_ipa_basedn', 'IPADiscovery')

warnings.warn(
    "ipaclient.install.ipadiscovery is deprecated, use ipaclient.discovery",
    DeprecationWarning
)
