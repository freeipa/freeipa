# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
X.509 Certificate Utilities for DN Conversion

This module provides helper functions to convert between python-cryptography's
x509.Name objects and IPA's DN representation, eliminating code duplication
across ipathinca modules.
"""

import logging
from typing import List, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from ipapython.dn import DN

logger = logging.getLogger(__name__)

# Standard OID to short name mapping for X.509 DNs
# This matches the format used in LDAP and IPA
OID_TO_SHORTNAME = {
    NameOID.COMMON_NAME: "CN",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COUNTRY_NAME: "C",
    NameOID.LOCALITY_NAME: "L",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.EMAIL_ADDRESS: "emailAddress",
    NameOID.STREET_ADDRESS: "street",
    NameOID.DOMAIN_COMPONENT: "DC",
    NameOID.USER_ID: "UID",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.SURNAME: "SN",
    NameOID.GIVEN_NAME: "givenName",
    NameOID.TITLE: "title",
    NameOID.GENERATION_QUALIFIER: "generationQualifier",
    NameOID.DN_QUALIFIER: "dnQualifier",
    NameOID.PSEUDONYM: "pseudonym",
}

# Reverse mapping: short name to NameOID
SHORTNAME_TO_OID = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C": NameOID.COUNTRY_NAME,
    "L": NameOID.LOCALITY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,  # Case variant
    "email": NameOID.EMAIL_ADDRESS,  # Alternate form
    "street": NameOID.STREET_ADDRESS,
    "DC": NameOID.DOMAIN_COMPONENT,
    "UID": NameOID.USER_ID,
    "serialNumber": NameOID.SERIAL_NUMBER,
    "SN": NameOID.SURNAME,
    "givenName": NameOID.GIVEN_NAME,
    "title": NameOID.TITLE,
    "generationQualifier": NameOID.GENERATION_QUALIFIER,
    "dnQualifier": NameOID.DN_QUALIFIER,
    "pseudonym": NameOID.PSEUDONYM,
}


def cert_name_to_ipa_dn(x509_name: x509.Name, reverse: bool = True) -> DN:
    """
    Convert cryptography x509.Name to IPA DN

    Args:
        x509_name: x509.Name object from a certificate
        reverse: If True (default), reverse the RDN order.
                 python-cryptography stores RDNs in least-specific-first order,
                 but IPA DN expects most-specific-first (standard RFC4514
                 display order).

    Returns:
        IPA DN object

    Example:
        >>> from cryptography import x509
        >>> cert = x509.load_pem_x509_certificate(cert_pem)
        >>> dn = cert_name_to_ipa_dn(cert.subject)
        >>> str(dn)
        'CN=Test User,O=EXAMPLE.COM'
    """
    components = []

    # python-cryptography's rdns are ordered least-specific to most-specific
    # (e.g., [O=EXAMPLE.COM, CN=Test User])
    # IPA DN expects most-specific-first, so we need to reverse
    rdns = reversed(x509_name.rdns) if reverse else x509_name.rdns

    for rdn in rdns:
        for attr in rdn:
            # Map OID to short attribute name
            attr_name = OID_TO_SHORTNAME.get(attr.oid, attr.oid._name)
            components.append((attr_name, attr.value))

    return DN(*components)


def ipa_dn_to_x509_name(dn_string: str) -> x509.Name:
    """
    Convert IPA DN string to cryptography x509.Name

    IMPORTANT: Each NameAttribute must be wrapped in its own RDN
    (RelativeDistinguishedName).
    Otherwise python-cryptography will group them all into a single
    multi-valued RDN.

    Args:
        dn_string: DN string in IPA/RFC4514 format (e.g.,
                   "CN=Test,O=EXAMPLE.COM")

    Returns:
        x509.Name object suitable for certificate creation

    Example:
        >>> name = ipa_dn_to_x509_name("CN=Test User,O=EXAMPLE.COM")
        >>> # Can be used in CertificateBuilder:
        >>> builder = builder.subject_name(name)
    """
    # Parse DN string to IPA DN object
    ipa_dn = DN(dn_string)

    # Build list of RDNs for x509.Name
    # CRITICAL: Each NameAttribute gets its own RDN wrapper
    subject_rdns = []

    # IPA DN iterates most-specific-first (e.g., CN, then O)
    # But x509.Name stores RDNs in reverse order (least-specific-first)
    # So we need to reverse the IPA DN order when building x509.Name
    for rdn in reversed(list(ipa_dn)):
        # Map short attribute name to NameOID
        # Try uppercase version if lowercase not found
        name_oid = SHORTNAME_TO_OID.get(rdn.attr) or SHORTNAME_TO_OID.get(
            rdn.attr.upper()
        )

        if name_oid:
            # Wrap each NameAttribute in its own RDN
            subject_rdns.append(
                x509.RelativeDistinguishedName(
                    [x509.NameAttribute(name_oid, rdn.value)]
                )
            )
        else:
            logger.warning(f"Unknown DN attribute type: {rdn.attr}, skipping")

    # x509.Name will store these RDNs in the order we provide them
    return x509.Name(subject_rdns)


def get_subject_dn_str(cert: x509.Certificate) -> str:
    """
    Get certificate subject DN as IPA DN string

    Args:
        cert: x509.Certificate object

    Returns:
        Subject DN string in IPA format (e.g., "CN=Test,O=EXAMPLE.COM")

    Example:
        >>> from cryptography import x509
        >>> cert = x509.load_pem_x509_certificate(cert_pem)
        >>> subject = get_subject_dn_str(cert)
        'CN=Test User,O=EXAMPLE.COM'
    """
    return str(cert_name_to_ipa_dn(cert.subject))


def get_issuer_dn_str(cert: x509.Certificate) -> str:
    """
    Get certificate issuer DN as IPA DN string

    Args:
        cert: x509.Certificate object

    Returns:
        Issuer DN string in IPA format

    Example:
        >>> from cryptography import x509
        >>> cert = x509.load_pem_x509_certificate(cert_pem)
        >>> issuer = get_issuer_dn_str(cert)
        'CN=Certificate Authority,O=EXAMPLE.COM'
    """
    return str(cert_name_to_ipa_dn(cert.issuer))


def get_subject_dn(cert: x509.Certificate) -> DN:
    """
    Get certificate subject DN as IPA DN object

    Args:
        cert: x509.Certificate object

    Returns:
        IPA DN object
    """
    return cert_name_to_ipa_dn(cert.subject)


def get_issuer_dn(cert: x509.Certificate) -> DN:
    """
    Get certificate issuer DN as IPA DN object

    Args:
        cert: x509.Certificate object

    Returns:
        IPA DN object
    """
    return cert_name_to_ipa_dn(cert.issuer)


def get_dn_components(x509_name: x509.Name) -> List[Tuple[str, str]]:
    """
    Extract DN components as list of (attribute, value) tuples

    Args:
        x509_name: x509.Name object

    Returns:
        List of (attribute_name, value) tuples in most-specific-first order

    Example:
        >>> components = get_dn_components(cert.subject)
        [('CN', 'Test User'), ('O', 'EXAMPLE.COM')]
    """
    components = []

    # Reverse order to get most-specific-first
    for rdn in reversed(x509_name.rdns):
        for attr in rdn:
            attr_name = OID_TO_SHORTNAME.get(attr.oid, attr.oid._name)
            components.append((attr_name, attr.value))

    return components


def get_ca_key_usage_extension() -> x509.KeyUsage:
    """
    Get standard CA KeyUsage extension

    This is the standard KeyUsage extension for Certificate Authority
    certificates, allowing certificate signing, CRL signing, and digital
    signatures.

    Returns:
        x509.KeyUsage extension configured for CA certificates

    Example:
        >>> builder = x509.CertificateBuilder()
        >>> builder = builder.add_extension(
        ...     get_ca_key_usage_extension(),
        ...     critical=True
        ... )
    """
    return x509.KeyUsage(
        digital_signature=True,
        key_cert_sign=True,
        crl_sign=True,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        content_commitment=False,
        encipher_only=False,
        decipher_only=False,
    )


def get_service_key_usage_extension() -> x509.KeyUsage:
    """
    Get standard service certificate KeyUsage extension

    For service and server certificates (caIPAserviceCert, caServerCert
    profiles).

    Allows digital signatures and key encipherment.

    Returns:
        x509.KeyUsage extension configured for service certificates

    Example:
        >>> builder = builder.add_extension(
        ...     get_service_key_usage_extension(),
        ...     critical=True
        ... )
    """
    return x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        content_commitment=False,
        data_encipherment=False,
        encipher_only=False,
        decipher_only=False,
    )


def get_ocsp_key_usage_extension() -> x509.KeyUsage:
    """
    Get OCSP signing certificate KeyUsage extension

    For OCSP responder certificates (caOCSPCert profile).

    Returns:
        x509.KeyUsage extension configured for OCSP signing

    Example:
        >>> builder = builder.add_extension(
        ...     get_ocsp_key_usage_extension(),
        ...     critical=True
        ... )
    """
    return x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        data_encipherment=True,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        content_commitment=False,
        encipher_only=False,
        decipher_only=False,
    )


def get_subsystem_key_usage_extension() -> x509.KeyUsage:
    """
    Get CA subsystem certificate KeyUsage extension

    For CA subsystem certificates (caSubsystemCert profile).

    Returns:
        x509.KeyUsage extension configured for subsystem certificates

    Example:
        >>> builder = builder.add_extension(
        ...     get_subsystem_key_usage_extension(),
        ...     critical=True
        ... )
    """
    return x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        content_commitment=False,
        data_encipherment=False,
        encipher_only=False,
        decipher_only=False,
    )


def get_audit_key_usage_extension() -> x509.KeyUsage:
    """
    Get audit signing certificate KeyUsage extension

    For audit log signing certificates (caSignedLogCert profile).
    Includes content_commitment (non-repudiation) for audit integrity.

    Returns:
        x509.KeyUsage extension configured for audit signing

    Example:
        >>> builder = builder.add_extension(
        ...     get_audit_key_usage_extension(),
        ...     critical=True
        ... )
    """
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=True,  # Non-repudiation for audit logs
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def get_server_extended_key_usage() -> x509.ExtendedKeyUsage:
    """
    Get standard server certificate ExtendedKeyUsage extension

    For server and service certificates that need both server and client
    authentication.

    Returns:
        x509.ExtendedKeyUsage extension for server certificates

    Example:
        >>> builder = builder.add_extension(
        ...     get_server_extended_key_usage(),
        ...     critical=False
        ... )
    """
    return x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    )


def get_ocsp_extended_key_usage() -> x509.ExtendedKeyUsage:
    """
    Get OCSP signing ExtendedKeyUsage extension

    For OCSP responder certificates.

    Returns:
        x509.ExtendedKeyUsage extension for OCSP signing

    Example:
        >>> builder = builder.add_extension(
        ...     get_ocsp_extended_key_usage(),
        ...     critical=True
        ... )
    """
    return x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING])


def get_subsystem_extended_key_usage() -> x509.ExtendedKeyUsage:
    """
    Get CA subsystem ExtendedKeyUsage extension

    For CA subsystem certificates that need client and server authentication.

    Returns:
        x509.ExtendedKeyUsage extension for subsystem certificates

    Example:
        >>> builder = builder.add_extension(
        ...     get_subsystem_extended_key_usage(),
        ...     critical=True
        ... )
    """
    return x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
    )


def get_pkinit_extended_key_usage() -> x509.ExtendedKeyUsage:
    """
    Get PKINIT KDC ExtendedKeyUsage extension

    For Kerberos KDC PKINIT certificates (KDCs_PKINIT_Certs profile).

    Returns:
        x509.ExtendedKeyUsage extension for PKINIT

    Example:
        >>> builder = builder.add_extension(
        ...     get_pkinit_extended_key_usage(),
        ...     critical=False
        ... )
    """
    return x509.ExtendedKeyUsage(
        [x509.ObjectIdentifier("1.3.6.1.5.2.3.5")]  # PKINIT KDC
    )


def build_x509_name(attributes, reverse: bool = False) -> x509.Name:
    """
    Build x509.Name from attributes with automatic RDN wrapping

    This utility simplifies creating x509.Name objects by handling the proper
    wrapping of each attribute in its own RDN and managing the ordering
    complexity.

    IMPORTANT: x509.Name stores RDNs in the order provided, but displays them
    in reverse order following RFC4514. To get "CN=Test,O=Example" display,
    you must provide attributes as [('O', 'Example'), ('CN', 'Test')].

    Args:
        attributes: Either:
                   - Dict: {'CN': 'Test', 'O': 'Example'}
                   - List of tuples: [('CN', 'Test'), ('O', 'Example')]
        reverse: If False (default), attributes are in natural/display order
                 (most-specific-first: CN, O, C) and will be reversed for x509
                 internal format.
                 If True, attributes are already in reverse order
                 (least-specific-first: C, O, CN) and will be used as-is.

    Returns:
        x509.Name object suitable for certificate building

    Examples:
        >>> # Method 1: Provide in natural order (most-specific-first)
        >>> # - DEFAULT
        >>> name = build_x509_name([('CN', 'Test'), ('O', 'Example')])
        >>> # Displays as: "CN=Test,O=Example"

        >>> # Method 2: Provide in reverse order (least-specific-first)
        >>> name = build_x509_name([('O', 'Example'), ('CN', 'Test')],
        >>>                        reverse=True)
        >>> # Displays as: "CN=Test,O=Example"

        >>> # Method 3: Using dict (automatically uses natural order)
        >>> name = build_x509_name({'CN': 'Test', 'O': 'Example', 'C': 'US'})
        >>> # Displays as: "CN=Test,O=Example,C=US"

        >>> # Use in certificate builder
        >>> builder = x509.CertificateBuilder()
        >>> builder = builder.subject_name(
        ...     build_x509_name([('CN', 'CA Subsystem'), ('O', 'IPA')])
        ... )
    """

    # Standard DN component ordering (most-specific to least-specific)
    # Always order DN components consistently, regardless of input order
    STANDARD_DN_ORDER = ["CN", "OU", "O", "L", "ST", "C", "DC", "UID"]

    # Convert to list of tuples if dict
    if isinstance(attributes, dict):
        attr_list = list(attributes.items())
    else:
        attr_list = list(attributes)

    # ALWAYS order components by standard DN order (most-specific-first: CN,
    # OU, O, L, ST, C)
    # This ensures consistent DN ordering regardless of input order
    ordered_attrs = []

    # First, add attributes in standard order
    for standard_name in STANDARD_DN_ORDER:
        for attr_name, attr_value in attr_list:
            # Case-insensitive comparison
            if attr_name.upper() == standard_name.upper():
                ordered_attrs.append((attr_name, attr_value))
                break

    # Then add any remaining attributes not in standard order
    for attr_name, attr_value in attr_list:
        if attr_name.upper() not in STANDARD_DN_ORDER:
            ordered_attrs.append((attr_name, attr_value))

    # Now reverse to get x509 internal format (least-specific-first)
    # because x509.Name displays in reverse order from how RDNs are provided
    # To get "CN=Test,O=Example" display, we provide [O, CN] to x509.Name
    # The reverse parameter allows overriding this behavior if needed
    if reverse:
        attributes = list(reversed(ordered_attrs))
    else:
        attributes = ordered_attrs

    # Build RDNs with proper wrapping
    # Each NameAttribute must be wrapped in its own RDN to avoid
    # creating a single multi-valued RDN
    rdns = []
    for attr_name, attr_value in attributes:
        # Map attribute name to NameOID
        name_oid = SHORTNAME_TO_OID.get(attr_name)

        if not name_oid:
            # Try uppercase version
            name_oid = SHORTNAME_TO_OID.get(attr_name.upper())

        if name_oid:
            # Wrap each NameAttribute in its own RDN
            rdns.append(
                x509.RelativeDistinguishedName(
                    [x509.NameAttribute(name_oid, attr_value)]
                )
            )
        else:
            logger.warning(f"Unknown DN attribute type: {attr_name}, skipping")

    return x509.Name(rdns)


def load_certificate_from_ldap_data(cert_data) -> x509.Certificate:
    """
    Load certificate from LDAP entry data (handles multiple formats)

    This utility eliminates code duplication in LDAP storage backends
    by handling all common certificate data formats from LDAP:
    - Raw bytes (DER or PEM encoded)
    - String (needs encoding)
    - IPACertificate objects (already parsed)

    Args:
        cert_data: Certificate data from LDAP entry
                  (bytes, str, or IPACertificate object)

    Returns:
        x509.Certificate object

    Raises:
        ValueError: If certificate data format is unsupported

    Example:
        >>> entry = ldap.get_entry(cert_dn)
        >>> cert_data = entry['userCertificate'][0]
        >>> certificate = load_certificate_from_ldap_data(cert_data)
    """

    # Handle different certificate formats
    # IPA LDAP may return IPACertificate objects, strings, or bytes
    if hasattr(cert_data, "public_bytes"):
        # It's already an IPACertificate/X509Certificate object
        return cert_data
    elif isinstance(cert_data, str):
        # It's a string, encode to bytes and try both formats
        cert_bytes = cert_data.encode("latin-1")
    else:
        # It's raw bytes
        cert_bytes = cert_data

    # Try DER format first (most common in LDAP)
    try:
        return x509.load_der_x509_certificate(cert_bytes)
    except Exception as der_error:
        logger.debug(
            "DER certificate loading failed, trying PEM: %s", der_error
        )
        # Fall back to PEM format
        try:
            return x509.load_pem_x509_certificate(cert_bytes)
        except Exception as e:
            raise ValueError(f"Could not load certificate from LDAP data: {e}")


def decode_ldap_attribute(value, expected_type: type = str):
    """
    Decode LDAP attribute value to expected Python type

    LDAP attributes may be returned as bytes or strings depending on the
    LDAP library version and configuration. This utility handles both cases.

    Args:
        value: LDAP attribute value (bytes, str, or other)
        expected_type: Expected Python type (default: str)

    Returns:
        Decoded value in expected type

    Example:
        >>> profile = decode_ldap_attribute(entry['certProfile'][0])
        'caIPAserviceCert'
        >>> serial = decode_ldap_attribute(entry['serialNumber'][0], int)
        12345
    """
    if value is None:
        return None

    # Handle bytes -> str conversion
    if isinstance(value, bytes) and expected_type == str:
        return value.decode("utf-8")

    # Handle str -> int conversion
    if isinstance(value, (str, bytes)) and expected_type == int:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        return int(value)

    # Handle str -> bool conversion
    if isinstance(value, (str, bytes)) and expected_type == bool:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        return value.upper() in ("TRUE", "1", "YES")

    # Already correct type or pass through
    return value


def parse_signature_algorithm(algorithm_string: str):
    """
    Parse Dogtag algorithm string to hash algorithm

    Converts Dogtag-style signature algorithm strings (e.g., "SHA256withRSA")
    to cryptography hash algorithm objects.

    Args:
        algorithm_string: Dogtag algorithm string like "SHA256withRSA",
                         "SHA384withEC", etc.

    Returns:
        Hash algorithm object from cryptography.hazmat.primitives.hashes

    Raises:
        ValueError: If algorithm string is not recognized

    Example:
        >>> hash_alg = parse_signature_algorithm("SHA256withRSA")
        >>> # Use for signing:
        >>> cert = builder.sign(private_key, hash_alg)
    """
    from cryptography.hazmat.primitives import hashes

    # Map algorithm strings to hash objects
    alg_upper = algorithm_string.upper()

    if "SHA1" in alg_upper:
        return hashes.SHA1()
    elif "SHA256" in alg_upper:
        return hashes.SHA256()
    elif "SHA384" in alg_upper:
        return hashes.SHA384()
    elif "SHA512" in alg_upper:
        return hashes.SHA512()
    elif "MD5" in alg_upper:
        return hashes.MD5()
    elif "MD2" in alg_upper:
        # MD2 is not supported by cryptography, use MD5 as fallback
        logger.warning("MD2 not supported, using MD5")
        return hashes.MD5()
    else:
        raise ValueError(f"Unknown signature algorithm: {algorithm_string}")


def get_default_algorithm_for_key(public_key) -> str:
    """
    Infer appropriate signature algorithm from public key type

    Args:
        public_key: Public key object from CSR or certificate

    Returns:
        Dogtag-style algorithm string (e.g., "SHA256withRSA")

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import rsa
        >>> public_key = csr.public_key()
        >>> algorithm = get_default_algorithm_for_key(public_key)
        'SHA256withRSA'
    """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

    if isinstance(public_key, rsa.RSAPublicKey):
        return "SHA256withRSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "SHA256withEC"
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "SHA256withDSA"
    else:
        logger.warning(
            f"Unknown key type {type(public_key).__name__}, using "
            "SHA256withRSA"
        )
        return "SHA256withRSA"


def get_certificate_signature_algorithm(certificate: x509.Certificate) -> str:
    """
    Extract the signature algorithm from an existing certificate

    Determines the Dogtag-style algorithm string that was used to sign
    a certificate, which should be used for signing related objects like
    CRLs and OCSP responses.

    Args:
        certificate: X.509 certificate object

    Returns:
        Dogtag-style algorithm string (e.g., "SHA256withRSA")

    Example:
        >>> algorithm = get_certificate_signature_algorithm(ca_cert)
        'SHA256withRSA'
        >>> # Use same algorithm for CRL signing
        >>> hash_alg = parse_signature_algorithm(algorithm)
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

    # Get hash algorithm from certificate
    hash_alg = certificate.signature_hash_algorithm

    # Get public key to determine key type
    public_key = certificate.public_key()

    # Map hash algorithm to string
    if isinstance(hash_alg, hashes.SHA1):
        hash_str = "SHA1"
    elif isinstance(hash_alg, hashes.SHA256):
        hash_str = "SHA256"
    elif isinstance(hash_alg, hashes.SHA384):
        hash_str = "SHA384"
    elif isinstance(hash_alg, hashes.SHA512):
        hash_str = "SHA512"
    elif isinstance(hash_alg, hashes.MD5):
        hash_str = "MD5"
    else:
        logger.warning(
            f"Unknown hash algorithm {type(hash_alg).__name__}, "
            "using SHA256"
        )
        hash_str = "SHA256"

    # Determine key type
    if isinstance(public_key, rsa.RSAPublicKey):
        key_str = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_str = "EC"
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_str = "DSA"
    else:
        logger.warning(
            f"Unknown key type {type(public_key).__name__}, using RSA"
        )
        key_str = "RSA"

    return f"{hash_str}with{key_str}"
