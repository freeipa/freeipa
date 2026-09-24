# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Replication helper for IpactaInstance.

Activates the o=ipaca topology segment in LDAP once replication is set up.

Note: the actual replication-agreement setup (creating the bidirectional
o=ipaca agreements and finalizing replica config) is done directly in
``IpactaInstance._setup_replication()`` / ``finalize_replica_config()``
using ``ipaserver.install.replication.CAReplicationManager`` — it is not
part of this helper because that manager cannot be constructed without
``ipaserver`` imports, which this ``ipacta.install`` package avoids.
"""

from __future__ import absolute_import

import logging

from ipaplatform.paths import paths

logger = logging.getLogger(__name__)


class Replication:
    """Helper that activates the o=ipaca topology segment after
    replication is established (see module docstring)."""

    def __init__(self, basedn, ldap_update_fn):
        self.basedn = basedn
        self._ldap_update = ldap_update_fn

    def update_topology(self):
        """Activate the o=ipaca topology segment in LDAP."""
        self._ldap_update(
            [paths.CA_TOPOLOGY_ULDIF], basedir=None
        )
