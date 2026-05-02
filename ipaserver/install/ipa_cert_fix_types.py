#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Data types, constants, and string templates for ipa-cert-fix.

This module contains the pure-data definitions used across the ipa-cert-fix
subsystem: dataclasses, enums, registry dicts, timing constants, and display
strings.  It has no side effects on import.
"""

from dataclasses import dataclass
import datetime
from enum import Enum
from typing import Optional

from ipaplatform.paths import paths


@dataclass(frozen=True)
class CertIdentity:
    """Identity and metadata for a Dogtag certificate.

    Each entry in ``DOGTAG_CERTS`` captures the certificate's NSSDB nickname,
    shared/server-specific classification, CS.cfg directives, and CSR
    directive in one place.
    """
    id: str
    nickname: str
    is_shared: bool
    cfg_path: Optional[str] = None
    cs_cfg_directive: Optional[str] = None
    certreq_directive: Optional[str] = None

    @property
    def display_name(self):
        return self.nickname

    @property
    def is_dogtag(self):
        return True


DOGTAG_CERTS = {
    'ca_issuing': CertIdentity(
        id='ca_issuing',
        nickname='caSigningCert cert-pki-ca',
        is_shared=True,
    ),
    'sslserver': CertIdentity(
        id='sslserver',
        nickname='Server-Cert cert-pki-ca',
        is_shared=False,
        cfg_path=paths.CA_CS_CFG_PATH,
        certreq_directive='ca.sslserver.certreq',
    ),
    'subsystem': CertIdentity(
        id='subsystem',
        nickname='subsystemCert cert-pki-ca',
        is_shared=True,
        cfg_path=paths.CA_CS_CFG_PATH,
        cs_cfg_directive='ca.subsystem.cert',
        certreq_directive='ca.subsystem.certreq',
    ),
    'ca_ocsp_signing': CertIdentity(
        id='ca_ocsp_signing',
        nickname='ocspSigningCert cert-pki-ca',
        is_shared=True,
        cfg_path=paths.CA_CS_CFG_PATH,
        cs_cfg_directive='ca.ocsp_signing.cert',
        certreq_directive='ca.ocsp_signing.certreq',
    ),
    'ca_audit_signing': CertIdentity(
        id='ca_audit_signing',
        nickname='auditSigningCert cert-pki-ca',
        is_shared=True,
        cfg_path=paths.CA_CS_CFG_PATH,
        cs_cfg_directive='ca.audit_signing.cert',
        certreq_directive='ca.audit_signing.certreq',
    ),
    'kra_transport': CertIdentity(
        id='kra_transport',
        nickname='transportCert cert-pki-kra',
        is_shared=True,
        cfg_path=paths.KRA_CS_CFG_PATH,
        cs_cfg_directive='kra.transport.cert',
        certreq_directive='kra.transport.certreq',
    ),
    'kra_storage': CertIdentity(
        id='kra_storage',
        nickname='storageCert cert-pki-kra',
        is_shared=True,
        cfg_path=paths.KRA_CS_CFG_PATH,
        cs_cfg_directive='kra.storage.cert',
        certreq_directive='kra.storage.certreq',
    ),
    'kra_audit_signing': CertIdentity(
        id='kra_audit_signing',
        nickname='auditSigningCert cert-pki-kra',
        is_shared=True,
        cfg_path=paths.KRA_CS_CFG_PATH,
        cs_cfg_directive='kra.audit_signing.cert',
        certreq_directive='kra.audit_signing.certreq',
    ),
}


# Certs expiring within this window are treated as expired.
CERT_EXPIRY_LOOKAHEAD = datetime.timedelta(weeks=2)

# Timeouts and delays for certmonger and D-Bus operations (seconds).
CERTMONGER_WAIT_TIMEOUT = 300
DBUS_RETRY_TIMEOUT = 120
DBUS_RETRY_DELAY = 5
HELPER_KILL_SETTLE = 2

RENEWED_CERT_PATH_TEMPLATE = "/etc/pki/pki-tomcat/certs/{}-renewed.crt"


class IPACertType(Enum):
    """Types of IPA service certificates."""
    IPARA = "Renewal Agent"
    HTTPS = "HTTPS"
    LDAPS = "LDAP"
    KDC = "KDC"


WARNING_BANNER = """
                          WARNING

ipa-cert-fix is intended for recovery when expired certificates
prevent the normal operation of IPA.  It should ONLY be used
in such scenarios, and backup of the system, especially certificates
and keys, is STRONGLY RECOMMENDED.

"""

RENEWAL_NOTE = """
Note: Monitor the certmonger-initiated renewal of certificates after
ipa-cert-fix and wait for its completion before any other administrative task.
"""


def _utcnow():
    """Current UTC time.  Mockable for testing."""
    return datetime.datetime.now(tz=datetime.timezone.utc)
