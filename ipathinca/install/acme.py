# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""ACME setup helper for IPAThinCAInstance."""

from __future__ import absolute_import

import logging

from ipalib import errors
from ipapython.dn import DN

from ipathinca.storage_acme import ACMEStorageBackend

logger = logging.getLogger(__name__)


class ACME:
    """Helper providing ACME service setup methods."""

    def __init__(self, ldap, config, ldap_mod_fn):
        self.ldap = ldap
        self.config = config
        self._ldap_mod = ldap_mod_fn

    def setup_acme(self):
        """Set up ACME service with LDAP storage backend.

        This method:
        1. Installs ACME LDAP schema from PKI
        2. Creates ACME container structure in LDAP (ou=acme,o=ipaca)
        3. Creates ACME configuration entry (disabled by default)
        """
        logger.info("Setting up ACME service with LDAP storage")

        # Install ACME LDAP schema from pki-acme package
        logger.debug("Installing ACME LDAP schema from PKI")
        self._ldap_mod("/usr/share/pki/acme/database/ds/schema.ldif")
        logger.debug("ACME LDAP schema installed successfully")

        # Initialize ACME LDAP schema (creates ou=acme,o=ipaca containers)
        acme_storage = ACMEStorageBackend(self.config)
        acme_storage.init_schema()
        logger.debug("ACME LDAP container structure created successfully")

        # Create ACME configuration entry (disabled by default)
        self._create_acme_config()

        logger.info("ACME service setup completed successfully")

    def _create_acme_config(self):
        """Create ACME configuration entry (disabled by default)."""
        logger.debug("Creating ACME configuration entry")

        if not self.ldap.isconnected():
            self.ldap.connect()

        ldap = self.ldap

        # Configuration entry DN
        config_dn = DN(("ou", "config"), ("ou", "acme"), ("o", "ipaca"))

        try:
            # Check if configuration already exists
            entry = ldap.get_entry(config_dn)
            logger.debug("ACME configuration entry already exists")

            # Ensure acmeEnabled attribute is set
            if "acmeEnabled" not in entry:
                entry["acmeEnabled"] = ["FALSE"]
                ldap.update_entry(entry)
                logger.debug("Added acmeEnabled=FALSE to existing config")
        except errors.NotFound:
            # Create configuration entry with extensibleObject to allow
            # custom attributes
            logger.debug(f"Creating ACME configuration entry at {config_dn}")
            entry = ldap.make_entry(
                config_dn,
                objectClass=["top", "organizationalUnit", "extensibleObject"],
                ou=["config"],
                acmeEnabled=["FALSE"],
            )
            ldap.add_entry(entry)
            logger.debug(
                "ACME configuration entry created (disabled by default)"
            )

        logger.debug("ACME configuration completed")
