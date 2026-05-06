# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Lightweight CA (LWCA) infrastructure helper for IPAThinCAInstance."""

from __future__ import absolute_import

import logging

from ipalib import errors
from ipalib.constants import IPA_CA_CN, IPA_CA_NICKNAME, RENEWAL_CA_NAME
from ipaplatform.paths import paths
from ipapython.dn import DN

logger = logging.getLogger(__name__)


class LWCA:
    """Helper providing lightweight CA (LWCA) key retrieval infrastructure."""

    def __init__(self, ldap, basedn):
        self.ldap = ldap
        self.basedn = basedn

    def ensure_lightweight_cas_container(self):
        """Create the LDAP container for lightweight CA authority objects.

        Creates ``ou=authorities,ou=ca,o=ipaca`` if it does not exist.
        This is where Dogtag (and ipathinca) store sub-CA authority entries.
        """
        dn = DN(("ou", "authorities"), ("ou", "ca"), ("o", "ipaca"))
        entry = self.ldap.make_entry(
            dn,
            objectclass=["top", "organizationalUnit"],
            ou=["authorities"],
        )
        try:
            self.ldap.add_entry(entry)
            logger.debug("Created LWCA authorities container: %s", dn)
        except errors.DuplicateEntry:
            logger.debug("LWCA authorities container already exists: %s", dn)

    def add_lightweight_ca_tracking_requests(self):
        """Register lightweight CA signing certs with certmonger for renewal.

        Queries LDAP for all ipaca entries (sub-CAs), then adds certmonger
        tracking requests for each one so their signing certificates are
        automatically renewed.  The IPA CA itself is skipped.
        """
        from ipalib.install import certmonger

        try:
            lwcas = self.ldap.get_entries(
                base_dn=self.basedn,
                filter="(objectclass=ipaca)",
                attrs_list=["cn", "ipacaid"],
            )
        except errors.NotFound:
            logger.warning(
                "Did not find any lightweight CAs; nothing to track"
            )
            return

        for entry in lwcas:
            if IPA_CA_CN in entry["cn"]:
                continue  # skip the IPA CA itself

            ipacaid_list = entry.get("ipacaid", [])
            if not ipacaid_list:
                logger.warning(
                    "Entry %s has empty ipacaid, skipping", entry.dn
                )
                continue
            nickname = "{} {}".format(IPA_CA_NICKNAME, ipacaid_list[0])
            criteria = {
                "cert-database": paths.PKI_TOMCAT_ALIAS_DIR,
                "cert-nickname": nickname,
                "ca-name": RENEWAL_CA_NAME,
            }
            request_id = certmonger.get_request_id(criteria)
            if request_id is None:
                try:
                    certmonger.start_tracking(
                        certpath=paths.PKI_TOMCAT_ALIAS_DIR,
                        pin=certmonger.get_pin("internal"),
                        nickname=nickname,
                        ca=RENEWAL_CA_NAME,
                        profile="caCACert",
                        pre_command="stop_pkicad",
                        post_command='renew_ca_cert "%s"' % nickname,
                    )
                    logger.debug(
                        'Lightweight CA renewal: added tracking for "%s"',
                        nickname,
                    )
                except RuntimeError as e:
                    logger.error(
                        "Lightweight CA renewal: certmonger failed to "
                        'start tracking "%s": %s',
                        nickname,
                        e,
                    )
            else:
                logger.debug(
                    'Lightweight CA renewal: already tracking "%s"', nickname
                )
