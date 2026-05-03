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
from ipapython.dn import DN


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


# Mapping from NSSDB nickname to (CS.cfg directive, config file path).
# Derived from DOGTAG_CERTS; only entries with a cs_cfg_directive are
# included (excludes sslserver and ca_issuing).
_CS_CFG_CERT_DIRECTIVES = {
    ci.nickname: (ci.cs_cfg_directive, ci.cfg_path)
    for ci in DOGTAG_CERTS.values()
    if ci.cs_cfg_directive is not None
}

# Certs expiring within this window are treated as expired.
CERT_EXPIRY_LOOKAHEAD = datetime.timedelta(weeks=2)

# Timeouts and delays for certmonger and D-Bus operations (seconds).
CERTMONGER_WAIT_TIMEOUT = 300
DBUS_RETRY_TIMEOUT = 120
DBUS_RETRY_DELAY = 5
HELPER_KILL_SETTLE = 2

# Profile used when renewing Dogtag certs through the IPA CA.
IPA_SERVICE_PROFILE = 'caIPAserviceCert'

DOGTAG_CERT_PATH_TEMPLATE = "/etc/pki/pki-tomcat/certs/{}.crt"
RENEWED_CERT_PATH_TEMPLATE = "/etc/pki/pki-tomcat/certs/{}-renewed.crt"


class IPACertType(Enum):
    """Types of IPA service certificates."""
    IPARA = "Renewal Agent"
    HTTPS = "HTTPS"
    LDAPS = "LDAP"
    KDC = "KDC"


class DeploymentType(Enum):
    """Classification of the local replica's deployment scenario."""
    CA_SELF_SIGNED = "CA-full, self-signed"
    CA_EXTERNALLY_SIGNED = "CA-full, externally-signed"
    CA_LESS = "CA-less (internal CA on other replicas)"
    CA_LESS_EXTERNAL = "CA-less (fully external)"


class FixScenario(Enum):
    """The fix path to execute based on deployment and topology."""
    RENEWAL_MASTER = "renewal_master"
    CA_FULL_WITH_MASTER = "ca_full_with_master"
    CA_FULL_PROMOTE = "ca_full_promote"
    CA_LESS_WITH_MASTER = "ca_less_with_master"
    EXTERNAL_CERTS = "external_certs"


@dataclass
class CertFixContext:
    """Shared context passed between fix methods.

    :param deployment_type: detected deployment classification
    :param scenario: the fix path being executed
    :param subject_base: certificate subject base DN
    :param ca_subject_dn: IPA CA subject DN
    :param dogtag_certs: expired Dogtag certs as ``[(certid, cert), ...]``
    :param ipa_certs: expired IPA-issued service certs as
        ``[(IPACertType, cert), ...]``
    :param external_certs: expired externally-signed service certs as
        ``[(IPACertType, cert), ...]``
    :param master_server: FQDN of the master to fetch certs from, or
        ``None`` for renewal master / external-only scenarios
    :param serverid: DS instance ID (e.g. ``EXAMPLE-COM``)
    :param ds_dbdir: DS NSS database directory (no trailing slash, matching
        certmonger convention)
    :param ds_nickname: DS server cert nickname
    :param hsm_enabled: whether HSM is configured for PKI
    :param hsm_token_name: HSM token name, or ``None``
    """
    deployment_type: DeploymentType
    scenario: FixScenario
    subject_base: DN
    ca_subject_dn: DN
    dogtag_certs: list
    ipa_certs: list
    external_certs: list
    master_server: Optional[str]
    serverid: str = ''
    ds_dbdir: str = ''
    ds_nickname: str = ''
    hsm_enabled: bool = False
    hsm_token_name: Optional[str] = None


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

PROMOTE_WARNING = """
                      WARNING

No working CA server was found.  Proceeding will promote this server to
the renewal master role.  This is a topology-wide change and should only be
done if the current renewal master is permanently unavailable.
"""


def _utcnow():
    """Current UTC time.  Mockable for testing."""
    return datetime.datetime.now(tz=datetime.timezone.utc)
