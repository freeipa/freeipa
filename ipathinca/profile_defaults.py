"""
Certificate profile default plugins

This module implements default plugins that provide values for certificate
fields during issuance.
"""

import logging
from typing import Dict, Any
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec

import ipathinca
from ipathinca import x509_utils
from ipathinca.profile import Default

logger = logging.getLogger(__name__)


class UserKeyDefault(Default):
    """userKeyDefaultImpl - uses public key from CSR"""

    def apply(self, builder, csr, context: dict):
        """Apply public key from CSR"""
        return builder.public_key(csr.public_key())


class SubjectNameDefault(Default):
    """subjectNameDefaultImpl - sets certificate subject DN"""

    def __init__(self, name: str = None, **kwargs):
        """Initialize subject name default

        Args:
            name: Subject DN template with variables
        """
        self.name_template = name or ""

    def apply(self, builder, csr, context: dict):
        """Apply subject DN with variable substitution"""
        from ipathinca.profile import extract_request_variable

        dn_str = extract_request_variable(self.name_template, csr, context)

        # Convert to x509.Name
        subject = x509_utils.ipa_dn_to_x509_name(dn_str)

        # Store final subject DN in context for constraint validation
        # This allows SubjectNameConstraint to validate the FINAL subject
        # that will go into the certificate, not just the CSR subject
        context["final_subject_dn"] = dn_str
        context["final_subject_name"] = subject

        return builder.subject_name(subject)


class ValidityDefault(Default):
    """validityDefaultImpl - sets certificate validity period"""

    def __init__(self, range: str = None, startTime: str = None, **kwargs):
        """Initialize validity default

        Args:
            range: Validity period in days
            startTime: Offset from now in seconds (usually 0)
        """
        self.range_days = int(range) if range else 365
        self.start_time = int(startTime) if startTime else 0

    def apply(self, builder, csr, context: dict):
        """Apply validity period from profile configuration

        Sets notBefore and notAfter based on the profile's range parameter.
        Does NOT clamp — matching Dogtag's ValidityDefault.populate() which
        simply applies the configured range.  Enforcement is done by the
        ValidityConstraint in the validation step.
        """
        now = datetime.now(timezone.utc)
        not_before = now + timedelta(seconds=self.start_time)
        not_after = not_before + timedelta(days=self.range_days)

        # Store in context for constraint validation
        context["validity_days"] = self.range_days

        return builder.not_valid_before(not_before).not_valid_after(not_after)


class SigningAlgDefault(Default):
    """signingAlgDefaultImpl - selects certificate signing algorithm"""

    def __init__(self, signingAlg: str = None, **kwargs):
        """Initialize signing algorithm default

        Args:
            signingAlg: Algorithm string or "-" for server decides
        """
        self.signing_alg = signingAlg or "-"

    def apply(self, builder, csr, context: dict):
        """Select signing algorithm"""
        if self.signing_alg == "-":
            # Server decides based on key type
            algorithm = self._infer_from_key(csr.public_key())
        else:
            algorithm = self.signing_alg

        # Store in context for signing and constraint validation
        context["signing_algorithm"] = algorithm

        return builder

    def _infer_from_key(self, public_key) -> str:
        """Infer appropriate algorithm from public key type

        Uses default_signing_algorithm from configuration (matching Dogtag's
        ca.signing.defaultSigningAlgorithm). Falls back to key-type inference
        if config not available.
        """
        # Read default from configuration (matches Dogtag CS.cfg behavior)
        try:
            default_alg = ipathinca.get_config_value(
                "ca", "default_signing_algorithm", default="SHA256withRSA"
            )
            logger.debug(
                "Using default signing algorithm from config: %s", default_alg
            )
            return default_alg
        except Exception as e:
            logger.warning(
                "Could not read default_signing_algorithm from config: %s", e
            )
            # Fallback: infer from key type
            if isinstance(public_key, rsa.RSAPublicKey):
                return "SHA256withRSA"
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return "SHA256withEC"
            else:
                return "SHA256withRSA"  # Safe default


class AuthorityKeyIdentifierExtDefault(Default):
    """authorityKeyIdentifierExtDefaultImpl - adds AKI extension"""

    def __init__(self, **kwargs):
        """Initialize AKI default"""

    def apply(self, builder, csr, context: dict):
        """Add Authority Key Identifier extension"""
        # Get CA certificate from context
        ca_cert = context.get("ca_certificate")
        if not ca_cert:
            return builder

        try:
            # Use CA's Subject Key Identifier
            ski = ca_cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
            aki = (
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ski.value
                )
            )
            builder = builder.add_extension(aki, critical=False)
        except Exception as e:
            logger.warning("Failed to add AKI: %s", e)

        return builder


class SubjectKeyIdentifierExtDefault(Default):
    """subjectKeyIdentifierExtDefaultImpl - adds SKI extension"""

    def __init__(self, critical: str = None, **kwargs):
        """Initialize SKI default"""
        self.critical = (critical or "false").lower() == "true"

    def apply(self, builder, csr, context: dict):
        """Add Subject Key Identifier extension"""
        ski = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
        return builder.add_extension(ski, critical=self.critical)


class KeyUsageExtDefault(Default):
    """keyUsageExtDefaultImpl - adds key usage extension"""

    def __init__(
        self,
        keyUsageCritical: str = None,
        keyUsageDigitalSignature: str = None,
        keyUsageNonRepudiation: str = None,
        keyUsageKeyEncipherment: str = None,
        keyUsageDataEncipherment: str = None,
        keyUsageKeyAgreement: str = None,
        keyUsageKeyCertSign: str = None,
        keyUsageCrlSign: str = None,
        keyUsageEncipherOnly: str = None,
        keyUsageDecipherOnly: str = None,
        **kwargs,
    ):
        """Initialize key usage default"""
        self.critical = (keyUsageCritical or "false").lower() == "true"
        self.digital_signature = (
            keyUsageDigitalSignature or "false"
        ).lower() == "true"
        self.content_commitment = (
            keyUsageNonRepudiation or "false"
        ).lower() == "true"
        self.key_encipherment = (
            keyUsageKeyEncipherment or "false"
        ).lower() == "true"
        self.data_encipherment = (
            keyUsageDataEncipherment or "false"
        ).lower() == "true"
        self.key_agreement = (
            keyUsageKeyAgreement or "false"
        ).lower() == "true"
        self.key_cert_sign = (keyUsageKeyCertSign or "false").lower() == "true"
        self.crl_sign = (keyUsageCrlSign or "false").lower() == "true"
        self.encipher_only = (
            keyUsageEncipherOnly or "false"
        ).lower() == "true"
        self.decipher_only = (
            keyUsageDecipherOnly or "false"
        ).lower() == "true"

    def apply(self, builder, csr, context: dict):
        """Add key usage extension"""
        key_usage = x509.KeyUsage(
            digital_signature=self.digital_signature,
            content_commitment=self.content_commitment,
            key_encipherment=self.key_encipherment,
            data_encipherment=self.data_encipherment,
            key_agreement=self.key_agreement,
            key_cert_sign=self.key_cert_sign,
            crl_sign=self.crl_sign,
            encipher_only=self.encipher_only,
            decipher_only=self.decipher_only,
        )

        # Store in context for constraint validation
        context["key_usage"] = key_usage

        return builder.add_extension(key_usage, critical=self.critical)


class ExtendedKeyUsageExtDefault(Default):
    """extendedKeyUsageExtDefaultImpl - adds extended key usage extension"""

    def __init__(
        self,
        exKeyUsageCritical: str = None,
        exKeyUsageOIDs: str = None,
        **kwargs,
    ):
        """Initialize extended key usage default

        Args:
            exKeyUsageCritical: "true" or "false"
            exKeyUsageOIDs: Comma-separated list of OIDs
        """
        self.critical = (exKeyUsageCritical or "false").lower() == "true"
        self.oids = []

        if exKeyUsageOIDs:
            for oid_str in exKeyUsageOIDs.split(","):
                oid_str = oid_str.strip()
                # Map common OIDs
                oid = self._parse_oid(oid_str)
                if oid:
                    self.oids.append(oid)

    def _parse_oid(self, oid_str: str):
        """Parse OID string to ObjectIdentifier"""
        # Common EKU OIDs
        eku_map = {
            "1.3.6.1.5.5.7.3.1": ExtendedKeyUsageOID.SERVER_AUTH,
            "1.3.6.1.5.5.7.3.2": ExtendedKeyUsageOID.CLIENT_AUTH,
            "1.3.6.1.5.5.7.3.3": ExtendedKeyUsageOID.CODE_SIGNING,
            "1.3.6.1.5.5.7.3.4": ExtendedKeyUsageOID.EMAIL_PROTECTION,
            "1.3.6.1.5.5.7.3.8": ExtendedKeyUsageOID.TIME_STAMPING,
            "1.3.6.1.5.5.7.3.9": ExtendedKeyUsageOID.OCSP_SIGNING,
        }

        oid = eku_map.get(oid_str)
        if oid:
            return oid

        # Try as raw OID
        try:
            return x509.ObjectIdentifier(oid_str)
        except Exception:
            logger.warning("Invalid OID: %s", oid_str)
            return None

    def apply(self, builder, csr, context: dict):
        """Add extended key usage extension"""
        if not self.oids:
            return builder

        eku = x509.ExtendedKeyUsage(self.oids)

        # Store in context for constraint validation
        context["extended_key_usage"] = eku

        return builder.add_extension(eku, critical=self.critical)


class CRLDistributionPointsExtDefault(Default):
    """crlDistributionPointsExtDefaultImpl - adds CRL distribution points"""

    def __init__(
        self,
        crlDistPointsCritical: str = None,
        crlDistPointsNum: str = None,
        **kwargs,
    ):
        """Initialize CRL distribution points default"""
        self.critical = (crlDistPointsCritical or "false").lower() == "true"
        self.num_points = int(crlDistPointsNum) if crlDistPointsNum else 0
        self.points = []

        # Parse distribution points
        for i in range(self.num_points):
            enabled = (
                kwargs.get(f"crlDistPointsEnable_{i}", "false").lower()
                == "true"
            )
            if not enabled:
                continue

            point_name = kwargs.get(f"crlDistPointsPointName_{i}", "")
            point_type = kwargs.get(f"crlDistPointsPointType_{i}", "")
            issuer_name = kwargs.get(f"crlDistPointsIssuerName_{i}", "")
            issuer_type = kwargs.get(f"crlDistPointsIssuerType_{i}", "")

            if point_name:
                self.points.append(
                    {
                        "point_name": point_name,
                        "point_type": point_type,
                        "issuer_name": issuer_name,
                        "issuer_type": issuer_type,
                    }
                )

    def apply(self, builder, csr, context: dict):
        """Add CRL distribution points extension"""
        if not self.points:
            return builder

        distribution_points = []
        for point_data in self.points:
            # Create distribution point
            if point_data["point_type"] == "URIName":
                full_name = [
                    x509.UniformResourceIdentifier(point_data["point_name"])
                ]
                dp = x509.DistributionPoint(
                    full_name=full_name,
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
                distribution_points.append(dp)

        if distribution_points:
            cdp = x509.CRLDistributionPoints(distribution_points)
            builder = builder.add_extension(cdp, critical=self.critical)

        return builder


class AuthInfoAccessExtDefault(Default):
    """authInfoAccessExtDefaultImpl - adds Authority Information Access"""

    def __init__(
        self,
        authInfoAccessCritical: str = None,
        authInfoAccessNumADs: str = None,
        **kwargs,
    ):
        """Initialize AIA default"""
        self.critical = (authInfoAccessCritical or "false").lower() == "true"
        self.num_ads = int(authInfoAccessNumADs) if authInfoAccessNumADs else 0
        self.access_descriptions = []

        # Parse access descriptions
        for i in range(self.num_ads):
            enabled = (
                kwargs.get(f"authInfoAccessADEnable_{i}", "false").lower()
                == "true"
            )
            if not enabled:
                continue

            method = kwargs.get(f"authInfoAccessADMethod_{i}", "")
            location = kwargs.get(f"authInfoAccessADLocation_{i}", "")
            location_type = kwargs.get(f"authInfoAccessADLocationType_{i}", "")

            if method and location:
                self.access_descriptions.append(
                    {
                        "method": method,
                        "location": location,
                        "location_type": location_type,
                    }
                )

    def apply(self, builder, csr, context: dict):
        """Add Authority Information Access extension"""
        if not self.access_descriptions:
            return builder

        descriptions = []
        for ad in self.access_descriptions:
            # Parse access method OID
            try:
                method_oid = x509.ObjectIdentifier(ad["method"])
            except Exception:
                logger.warning("Invalid AIA method OID: %s", ad["method"])
                continue

            # Parse access location
            if ad["location_type"] == "URIName":
                location = x509.UniformResourceIdentifier(ad["location"])
            else:
                logger.warning(
                    "Unsupported location type: %s", ad["location_type"]
                )
                continue

            descriptions.append(x509.AccessDescription(method_oid, location))

        if descriptions:
            aia = x509.AuthorityInformationAccess(descriptions)
            builder = builder.add_extension(aia, critical=self.critical)

        return builder


class UserExtensionDefault(Default):
    """userExtensionDefaultImpl - uses extension from CSR"""

    def __init__(self, userExtOID: str = None, **kwargs):
        """Initialize user extension default

        Args:
            userExtOID: OID of extension to copy from CSR
        """
        self.oid_str = userExtOID

    def apply(self, builder, csr, context: dict):
        """Copy extension from CSR to certificate"""
        if not self.oid_str:
            return builder

        try:
            oid = x509.ObjectIdentifier(self.oid_str)

            # Track which extensions have been added in context
            if "extensions_added" not in context:
                context["extensions_added"] = set()

            # Skip if this extension was already added by another policy
            if self.oid_str in context["extensions_added"]:
                logger.debug(
                    "Extension %s already added, skipping", self.oid_str
                )
                return builder

            # Try to get extension from CSR
            try:
                ext = csr.extensions.get_extension_for_oid(oid)
                builder = builder.add_extension(
                    ext.value, critical=ext.critical
                )
                # Mark this extension as added
                context["extensions_added"].add(self.oid_str)
                logger.debug("Added extension %s from CSR", self.oid_str)
            except x509.ExtensionNotFound:
                # Extension not in CSR, skip
                pass

        except Exception as e:
            logger.warning(
                "Failed to copy user extension %s: %s", self.oid_str, e
            )

        return builder


class CommonNameToSANDefault(Default):
    """commonNameToSANDefaultImpl - copies CN to Subject Alternative Name"""

    def __init__(self, **kwargs):
        """Initialize CN to SAN default"""

    def apply(self, builder, csr, context: dict):
        """Copy CN from subject to SAN as DNSName"""
        from cryptography.x509.oid import NameOID

        try:
            # Track which extensions have been added in context
            if "extensions_added" not in context:
                context["extensions_added"] = set()

            # SAN extension OID is 2.5.29.17
            san_oid = "2.5.29.17"

            # Skip if SAN extension was already added by another policy
            if san_oid in context["extensions_added"]:
                logger.debug(
                    "SAN extension already added by another policy, skipping "
                    "CN to SAN copy"
                )
                return builder

            # Get CN from subject
            cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_attrs:
                return builder

            cn = cn_attrs[0].value

            # Add as DNSName in SAN
            san = x509.SubjectAlternativeName([x509.DNSName(cn)])
            builder = builder.add_extension(san, critical=False)

            # Mark SAN extension as added
            context["extensions_added"].add(san_oid)
            logger.debug("Added SAN extension with CN=%s", cn)

        except Exception as e:
            logger.warning("Failed to copy CN to SAN: %s", e)

        return builder


class SANToCNDefault(Default):
    """sanToCNDefaultImpl - copies SAN to Common Name (inverse of
    commonNameToSAN)"""

    def __init__(self, **kwargs):
        """Initialize SAN to CN default"""

    def apply(self, builder, csr, context: dict):
        """Copy first DNS name from SAN to CN in subject"""

        try:
            # Get SAN extension from CSR
            san_ext = csr.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )

            # Find first DNS name
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    # Use SAN DNS name as CN
                    # This will be used if the profile sets subject from SAN
                    # For now, we just pass through - the subject will be set
                    # by another default plugin
                    break

        except x509.ExtensionNotFound:
            # No SAN in CSR
            pass
        except Exception as e:
            logger.warning("Failed to copy SAN to CN: %s", e)

        return builder


class UserSubjectNameDefault(Default):
    """userSubjectNameDefaultImpl - uses subject name from request/CSR"""

    def __init__(self, **kwargs):
        """Initialize user subject name default"""

    def apply(self, builder, csr, context: dict):
        """Use subject name directly from CSR

        This default simply uses the subject DN from the CSR as-is,
        without modification or variable substitution.
        """
        # Use subject from CSR directly
        subject = csr.subject

        # Store in context for constraint validation
        # Use rfc4514_string() to get standard DN format (CN first)
        context["final_subject_dn"] = subject.rfc4514_string()

        return builder.subject_name(subject)


class OCSPNoCheckExtDefault(Default):
    """ocspNoCheckExtDefaultImpl - adds OCSP No Check extension"""

    def __init__(self, critical: str = "false", **kwargs):
        """Initialize OCSP No Check extension default

        Args:
            critical: Whether extension is critical ("true"/"false")
        """
        self.critical = critical.lower() == "true"

    def apply(self, builder, csr, context: dict):
        """Add OCSP No Check extension

        This extension indicates that the certificate is an OCSP responder
        certificate and should not be checked for revocation.
        """
        # OCSP No Check is a null extension (no value, just presence)
        # In cryptography library, this is OCSPNoCheck()
        try:
            ext = x509.Extension(
                oid=ExtensionOID.OCSP_NO_CHECK,
                critical=self.critical,
                value=x509.OCSPNoCheck(),
            )
            builder = builder.add_extension(ext.value, critical=ext.critical)
        except Exception as e:
            logger.warning("Failed to add OCSP No Check extension: %s", e)

        return builder


# Default factory
def create_default(class_id: str, params: Dict[str, Any]) -> Default:
    """Factory to instantiate defaults from .cfg data

    Args:
        class_id: Default class identifier
        params: Default parameters

    Returns:
        Instantiated Default object
    """
    default_map = {
        "userKeyDefaultImpl": UserKeyDefault,
        "subjectNameDefaultImpl": SubjectNameDefault,
        "validityDefaultImpl": ValidityDefault,
        "signingAlgDefaultImpl": SigningAlgDefault,
        "authorityKeyIdentifierExtDefaultImpl": (
            AuthorityKeyIdentifierExtDefault
        ),
        "subjectKeyIdentifierExtDefaultImpl": SubjectKeyIdentifierExtDefault,
        "keyUsageExtDefaultImpl": KeyUsageExtDefault,
        "extendedKeyUsageExtDefaultImpl": ExtendedKeyUsageExtDefault,
        "crlDistributionPointsExtDefaultImpl": CRLDistributionPointsExtDefault,
        "authInfoAccessExtDefaultImpl": AuthInfoAccessExtDefault,
        "userExtensionDefaultImpl": UserExtensionDefault,
        "commonNameToSANDefaultImpl": CommonNameToSANDefault,
        "sanToCNDefaultImpl": SANToCNDefault,
        "userSubjectNameDefaultImpl": UserSubjectNameDefault,
        "ocspNoCheckExtDefaultImpl": OCSPNoCheckExtDefault,
    }

    default_class = default_map.get(class_id)
    if not default_class:
        logger.warning(
            "Unknown default class '%s', using UserKeyDefault", class_id
        )
        return UserKeyDefault()

    try:
        return default_class(**params)
    except Exception as e:
        logger.error("Failed to create default %s: %s", class_id, e)
        raise
