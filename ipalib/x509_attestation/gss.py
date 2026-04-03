#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
GSSAPI S4U2Self and S4U2Proxy using an X.509 attestation certificate.

Uses python-gssapi with the MIT Kerberos GSS_KRB5_NT_X509_CERT name type
(OID 1.2.840.113554.1.2.2.7, defined in MIT Kerberos gssapi_ext.h, requires
MIT Kerberos ≥ 1.19).

S4U2Self flow
~~~~~~~~~~~~~
Client-side (import_name.c:189): gss_import_name() with GSS_KRB5_NT_X509_CERT
stores the raw certificate bytes as the principal's data components via
krb5_build_principal_ext() and sets name->is_cert = 1.  The GSSAPI code does
not parse, validate, or inspect the certificate in any way — no SAN extraction,
no X.509 processing.

gss_acquire_cred_impersonate_name() (s4u_gss_glue.c:56): kg_impersonate_name()
sees is_cert, extracts subject_cert = user->princ->data (the raw cert bytes
from the import step), and passes them verbatim to
krb5_get_credentials_for_user(..., subject_cert, ...).  The libkrb5 client
library builds PA-S4U-X509-USER with the cert blob as the subject_cert field.
The GSSAPI layer is purely a pass-through.

KDC-side: the KDC treats the certificate blob as opaque binary.  It verifies
only the checksum over the PA-S4U-X509-USER payload using the TGS session key,
then passes the raw cert bytes verbatim to the KDB plugin via
krb5_db_get_s4u_x509_principal().  No X.509 parsing, no chain validation, and
no PKINIT processing is performed by the KDC.  All certificate interpretation —
parsing the id-ce-kerberosServiceIssuerBinding extension, signature
verification, service key binding, and auth indicator gating — is done
exclusively by the IPA KDB plugin (ipa_kdb_s4u_x509.c).

S4U2Proxy flow
~~~~~~~~~~~~~~
After S4U2Self the host holds a service ticket for the impersonated user
(alice → host/server).  To delegate further — e.g. to access HTTP/ipa on
behalf of alice — the host performs S4U2Proxy: a TGS-REQ with
KDC_OPT_CNAME_IN_ADDL_TKT set and the S4U2Self service ticket in
additional-tickets as delegation evidence (RFC 4120 §7.5.7 / MS-SFU §3.2.5).

gss_init_sec_context() with the S4U2Self credentials toward the target service
triggers the S4U2Proxy TGS-REQ automatically inside libkrb5.  The KDC checks
the host's allowed-to-delegate list before issuing the proxy ticket.  The
resulting AP-REQ token can then be presented to the target service.
"""

import gssapi

# GSS_KRB5_NT_X509_CERT: 1.2.840.113554.1.2.2.7
# Imports raw X.509 cert DER as a Kerberos principal name for PA-FOR-X509-USER.
GSS_KRB5_NT_X509_CERT = gssapi.OID.from_int_seq(
    [1, 2, 840, 113554, 1, 2, 2, 7]
)


def acquire_s4u_creds(
    cert_der: bytes,
    host_principal: str,
    *,
    keytab_path: str | None = None,
) -> gssapi.Credentials:
    """
    Acquire S4U2Self credentials for the user identified by cert_der.

    Parameters
    ----------
    cert_der:       DER-encoded attestation certificate
                    (from cert.build_attestation_cert).
    host_principal: Host Kerberos principal,
                    e.g. "host/server.example.com@REALM".
    keytab_path:    Path to the host keytab; None uses the system default
                    (/etc/krb5.keytab or KRB5_KTNAME).

    Returns
    -------
    GSSAPI Credentials object for the impersonated user, suitable for
    initiating a security context or further delegation.
    """
    # 1. Acquire host service credentials (the S4U impersonator).
    host_name = gssapi.Name(
        host_principal,
        name_type=gssapi.NameType.kerberos_principal,
    )
    store = {'keytab': keytab_path} if keytab_path else {}
    host_creds = gssapi.Credentials(
        name=host_name,
        usage='initiate',
        mechs=[gssapi.MechType.kerberos],
        store=store or None,
    )

    # 2. Import the attestation certificate as a GSSAPI principal name.
    #    The GSSAPI code stores the raw cert bytes opaquely (is_cert=1);
    #    it does not parse, validate, or extract any field from the cert.
    cert_name = gssapi.Name(cert_der, name_type=GSS_KRB5_NT_X509_CERT)

    # 3. gss_acquire_cred_impersonate_name: S4U2Self TGS-REQ with the cert.
    s4u_creds = gssapi.Credentials(
        name=cert_name,
        usage='initiate',
        mechs=[gssapi.MechType.kerberos],
        impersonator=host_creds,
        store=store or None,
    )

    return s4u_creds


def request_s4u_proxy(
    s4u_creds: gssapi.Credentials,
    proxy_target: str,
) -> bytes:
    """
    Perform S4U2Proxy (constrained delegation) toward proxy_target.

    Uses the S4U2Self Credentials from acquire_s4u_creds() as delegation
    evidence to obtain a service ticket for proxy_target on behalf of the
    impersonated user, without requiring the user to participate.

    gss_init_sec_context() with the impersonated credentials causes MIT
    Kerberos to issue a TGS-REQ with KDC_OPT_CNAME_IN_ADDL_TKT set and the
    S4U2Self service ticket in additional-tickets.  The KDC checks the host's
    constrained-delegation policy and, if permitted, returns a service ticket
    for the impersonated user to proxy_target.

    Parameters
    ----------
    s4u_creds:    Credentials returned by acquire_s4u_creds().  The S4U2Self
                  ticket must be forwardable (set by KDC policy).
    proxy_target: Target service principal in Kerberos form, e.g.
                  "HTTP/ipa.example.com@REALM".

    Returns
    -------
    Initial GSSAPI token (AP-REQ) assembled from the proxy service ticket.
    The token is not sent to any server here; it is returned to confirm that
    the KDC accepted the S4U2Proxy TGS-REQ.

    Raises
    ------
    gssapi.exceptions.GSSError
        If the KDC rejects the delegation request (e.g. the target service is
        not in the host's allowed-to-delegate list, or the S4U2Self ticket was
        not issued as forwardable).
    """
    target_name = gssapi.Name(
        proxy_target,
        name_type=gssapi.NameType.kerberos_principal,
    )

    # Initiating a context with impersonated creds causes libkrb5 to perform
    # S4U2Proxy internally: a TGS-REQ with KDC_OPT_CNAME_IN_ADDL_TKT and the
    # S4U2Self ticket as additional-tickets evidence (MS-SFU §3.2.5).
    ctx = gssapi.SecurityContext(
        name=target_name,
        creds=s4u_creds,
        usage='initiate',
        mechs=[gssapi.MechType.kerberos],
    )

    # step() calls gss_init_sec_context().  The S4U2Proxy TGS-REQ is issued
    # before the AP-REQ token is assembled.  A GSSError here means the KDC
    # rejected the delegation request, not a network failure.
    token = ctx.step()

    return token
