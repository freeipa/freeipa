#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
ipalib.x509_attestation — S4U2Self X.509 attestation support.

Implements the host-side attestation pipeline described in
doc/designs/krb-s4u-x509-assertion.md.  A service holding a host Kerberos
keytab uses this package to:

  1. Select the best AES keytab entry for a host principal.
  2. Derive a short-lived attestation signing key from the keytab key
     material (HKDF-SHA256, salt = "{service_type}-attestation-v1").
  3. Build a DER-encoded X.509 certificate attesting an authentication
     event, with an id-ce-kerberosServiceIssuerBinding extension that
     identifies the host and service type, and an optional service-specific
     authentication context extension.
  4. Exchange the certificate for a Kerberos service ticket via S4U2Self
     (PA-FOR-X509-USER / GSS_KRB5_NT_X509_CERT).
  5. Optionally perform S4U2Proxy (constrained delegation) toward a target
     service.

Public API
----------
  KeytabEntry                  dataclass returned by get_host_keytab_key()
  get_host_keytab_key()        open host keytab, select best AES entry
  build_attestation_cert()     SSH-specific attestation cert (backward compat)
  build_service_attestation_cert()
                               generic attestation cert for any service type
  acquire_s4u_creds()          GSSAPI S4U2Self acquisition
  request_s4u_proxy()          GSSAPI S4U2Proxy (constrained delegation)

Internal submodules (importable for advanced use):
  .keytab   keytab enumeration
  .crypto   HKDF key derivation and binding signature
  .asn1     DER encoding of extensions and PKINIT SAN
  .cert     X.509 certificate assembly
  .gss      GSSAPI S4U2Self / S4U2Proxy
"""

from .keytab import KeytabEntry, get_host_keytab_key
from .cert import (
    build_attestation_cert,
    build_oidc_attestation_cert,
    build_service_attestation_cert,
)
from .gss import acquire_s4u_creds, request_s4u_proxy

__all__ = [
    "KeytabEntry",
    "get_host_keytab_key",
    "build_attestation_cert",
    "build_oidc_attestation_cert",
    "build_service_attestation_cert",
    "acquire_s4u_creds",
    "request_s4u_proxy",
]
