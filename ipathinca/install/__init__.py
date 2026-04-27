# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""ipathinca installation interface.

Provides helper classes consumed by the IPA installer
(``ipaserver/install/ipathincainstance.py``):

- ``NSSDB``        — NSS database creation and certificate import
- ``Certs``        — CA / subsystem / server / RA certificate generation
- ``LDAPSetup``    — LDAP schema, storage init, profile and ACL import
- ``Replication``  — clone / replica replication setup
- ``ServiceMgmt``  — directories, systemd, certmonger, Apache proxy
- ``KRAInstall``   — KRA subsystem (enable_kra, vault, service entry)
- ``ACME``         — ACME LDAP schema and configuration
- ``LWCA``         — Lightweight CA key retrieval infrastructure

PKI configuration loading (the four-layer ``PKIIniLoader`` equivalent) now
lives entirely in ``_PKIConfigBuilder`` inside
``ipaserver/install/ipathincainstance.py``, where it is appropriate to
reference PKI-specific names and file paths.
"""

from __future__ import absolute_import

import logging

from .acme import ACME
from .certs import (
    Certs,
    get_cert_params_from_config,
    convert_signing_algorithm,
)
from .db import NSSDB
from .kra import KRAInstall
from .ldap_setup import LDAPSetup
from .lwca import LWCA
from .replica import Replication
from .service_mgmt import ServiceMgmt

logger = logging.getLogger(__name__)

__all__ = [
    "ACME",
    "Certs",
    "KRAInstall",
    "LDAPSetup",
    "LWCA",
    "NSSDB",
    "Replication",
    "ServiceMgmt",
    "get_cert_params_from_config",
    "convert_signing_algorithm",
]
