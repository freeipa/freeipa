# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Replication helper for IPAThinCAInstance.

Handles clone/replica installation: setting up o=ipaca replication,
activating topology segments, and finalising replica configuration.
"""

from __future__ import absolute_import

import logging

logger = logging.getLogger(__name__)


class Replication:
    """Helper providing clone/replica installation methods."""

    def __init__(self, basedn, ldap_mod_fn):
        self.basedn = basedn
        self._ldap_mod = ldap_mod_fn

    def update_topology(self):
        """Activate the o=ipaca topology segment in LDAP."""
        self._ldap_mod("ca-topology.ldif", {"SUFFIX": self.basedn})
