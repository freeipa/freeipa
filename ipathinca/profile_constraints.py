"""
Certificate profile constraint plugins

This module implements constraint plugins that validate certificate signing
requests according to profile-defined rules.
"""

import re
import logging
from typing import List, Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
import ipathinca

from ipathinca.profile import Constraint

logger = logging.getLogger(__name__)


class NoConstraint(Constraint):
    """noConstraintImpl - allows anything"""

    def validate(self, csr, context: dict) -> List[str]:
        """Always passes validation"""
        return []


class SubjectNameConstraint(Constraint):
    """subjectNameConstraintImpl - validates subject DN pattern"""

    def __init__(self, pattern: str = None, accept: str = None, **kwargs):
        """Initialize subject name constraint

        Args:
            pattern: Regular expression pattern to match
            accept: "true" to accept pattern, "false" to reject
        """
        self.pattern = pattern or ".*"
        self.accept = (accept or "true").lower() == "true"
        self.regex = re.compile(self.pattern)

    def validate(self, csr, context: dict) -> List[str]:
        """Validate subject DN matches pattern

        This validates the FINAL subject DN that will be in the certificate,
        which may be different from the CSR subject if SubjectNameDefault
        has modified it (e.g., adding O= from profile).
        """
        # Check if SubjectNameDefault has set the final subject DN
        # This is the subject that will actually go into the certificate
        if "final_subject_dn" in context:
            # Use the final subject DN from the default
            subject_dn = context["final_subject_dn"]
            logger.debug(
                f"SubjectNameConstraint validating final subject: {subject_dn}"
            )
        else:
            # Fall back to CSR subject if no final subject set yet
            # Use rfc4514_string() to get standard DN format
            # (most-specific-first, e.g., "CN=...,O=...")
            subject_dn = csr.subject.rfc4514_string()
            logger.debug(
                f"SubjectNameConstraint validating CSR subject: {subject_dn}"
            )

        # Use search() instead of match() to allow pattern anywhere in DN
        # Pattern "CN=.*" should match "O=TEST,CN=Foo" as well as "CN=Foo"
        matches = bool(self.regex.search(subject_dn))

        if matches != self.accept:
            if self.accept:
                return [
                    f"Subject DN '{subject_dn}' does not match required "
                    f"pattern '{self.pattern}'"
                ]
            else:
                return [
                    f"Subject DN '{subject_dn}' matches forbidden "
                    f"pattern '{self.pattern}'"
                ]

        return []


class ValidityConstraint(Constraint):
    """validityConstraintImpl - validates certificate validity period"""

    def __init__(
        self,
        range: str = None,
        notBeforeCheck: str = None,
        notAfterCheck: str = None,
        **kwargs,
    ):
        """Initialize validity constraint

        Args:
            range: Maximum validity period in days
            notBeforeCheck: "true" to check notBefore
            notAfterCheck: "true" to check notAfter
        """
        self.range_days = int(range) if range else None
        self.check_not_before = (notBeforeCheck or "false").lower() == "true"
        self.check_not_after = (notAfterCheck or "false").lower() == "true"

    def validate(self, csr, context: dict) -> List[str]:
        """Validate validity period is within constraints"""
        errors = []

        # Get requested validity from context (set by default plugin)
        requested_days = context.get("validity_days")
        if requested_days and self.range_days:
            if requested_days > self.range_days:
                errors.append(
                    f"Requested validity {requested_days} days exceeds "
                    f"maximum {self.range_days} days"
                )

        # Additional not_before/not_after checks can be added here
        # Currently we trust the default plugin to set appropriate values

        return errors


class KeyConstraint(Constraint):
    """keyConstraintImpl - validates key type and size"""

    def __init__(
        self, keyType: str = None, keyParameters: str = None, **kwargs
    ):
        """Initialize key constraint

        Args:
            keyType: Required key type (RSA, EC, DSA)
            keyParameters: Comma-separated list of allowed key sizes/curves
        """
        self.key_type = (keyType or "RSA").upper()
        self.key_parameters = []

        if keyParameters:
            # Parse comma-separated list of integers
            for param in keyParameters.split(","):
                try:
                    self.key_parameters.append(int(param.strip()))
                except ValueError:
                    # Might be EC curve name
                    self.key_parameters.append(param.strip())

    def validate(self, csr, context: dict) -> List[str]:
        """Validate key type and size"""
        errors = []
        public_key = csr.public_key()

        # Check key type
        if self.key_type == "RSA":
            if not isinstance(public_key, rsa.RSAPublicKey):
                errors.append(
                    f"Key type must be RSA, not {type(public_key).__name__}"
                )
            else:
                key_size = public_key.key_size
                if self.key_parameters:
                    # Check key size against profile-specified list
                    if key_size not in self.key_parameters:
                        errors.append(
                            f"RSA key size {key_size} not allowed. "
                            f"Allowed sizes: {self.key_parameters}"
                        )
                else:
                    # No profile-specific constraints, use global config
                    # (matching Dogtag ca.Policy.rule.RSAKeyRule.*)
                    min_size = int(
                        ipathinca.get_config_value(
                            "ca", "min_rsa_key_size", default="2048"
                        )
                    )
                    max_size = int(
                        ipathinca.get_config_value(
                            "ca", "max_rsa_key_size", default="8192"
                        )
                    )
                    if key_size < min_size or key_size > max_size:
                        errors.append(
                            f"RSA key size {key_size} out of range. "
                            f"Allowed: {min_size}-{max_size} bits"
                        )

                # Validate RSA exponent (matching Dogtag allowed_rsa_exponents)
                allowed_exponents_str = ipathinca.get_config_value(
                    "ca", "allowed_rsa_exponents", default="65537"
                )
                allowed_exponents = [
                    int(e.strip()) for e in allowed_exponents_str.split(",")
                ]
                public_numbers = public_key.public_numbers()
                if public_numbers.e not in allowed_exponents:
                    errors.append(
                        f"RSA exponent {public_numbers.e} not allowed. "
                        f"Allowed exponents: {allowed_exponents}"
                    )

        elif self.key_type == "EC":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                errors.append(
                    f"Key type must be EC, not {type(public_key).__name__}"
                )
            elif self.key_parameters:
                # Check curve (more complex, simplified here)
                curve_name = public_key.curve.name
                if curve_name not in self.key_parameters:
                    errors.append(
                        f"EC curve {curve_name} not allowed. "
                        f"Allowed curves: {self.key_parameters}"
                    )

        elif self.key_type == "DSA":
            if not isinstance(public_key, dsa.DSAPublicKey):
                errors.append(
                    f"Key type must be DSA, not {type(public_key).__name__}"
                )

        return errors


class SigningAlgConstraint(Constraint):
    """signingAlgConstraintImpl - validates signing algorithm"""

    def __init__(self, signingAlgsAllowed: str = None, **kwargs):
        """Initialize signing algorithm constraint

        Args:
            signingAlgsAllowed: Comma-separated list of allowed algorithms
        """
        if signingAlgsAllowed:
            self.allowed = [
                alg.strip() for alg in signingAlgsAllowed.split(",")
            ]
        else:
            # Read from config (matching Dogtag
            # ca.profiles.defaultSigningAlgsAllowed)
            try:
                config_allowed = ipathinca.get_config_value(
                    "ca",
                    "allowed_signing_algorithms",
                    default="SHA256withRSA,SHA384withRSA,SHA512withRSA",
                )
                self.allowed = [
                    alg.strip() for alg in config_allowed.split(",")
                ]
            except Exception:
                # Fallback to empty list (no validation)
                self.allowed = []

    def validate(self, csr, context: dict) -> List[str]:
        """Validate requested signing algorithm is allowed"""
        errors = []

        # Get algorithm from context (set by default plugin)
        signing_alg = context.get("signing_algorithm")

        if signing_alg and self.allowed:
            if signing_alg not in self.allowed:
                errors.append(
                    f"Signing algorithm '{signing_alg}' not allowed. "
                    f"Allowed algorithms: {', '.join(self.allowed)}"
                )

        return errors


class KeyUsageExtConstraint(Constraint):
    """keyUsageExtConstraintImpl - validates key usage extension"""

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
        """Initialize key usage constraint

        Each parameter is "true", "false", or None (don't check)
        """
        self.critical = self._parse_bool(keyUsageCritical)
        self.digital_signature = self._parse_bool(keyUsageDigitalSignature)
        self.non_repudiation = self._parse_bool(keyUsageNonRepudiation)
        self.key_encipherment = self._parse_bool(keyUsageKeyEncipherment)
        self.data_encipherment = self._parse_bool(keyUsageDataEncipherment)
        self.key_agreement = self._parse_bool(keyUsageKeyAgreement)
        self.key_cert_sign = self._parse_bool(keyUsageKeyCertSign)
        self.crl_sign = self._parse_bool(keyUsageCrlSign)
        self.encipher_only = self._parse_bool(keyUsageEncipherOnly)
        self.decipher_only = self._parse_bool(keyUsageDecipherOnly)

    def _parse_bool(self, value: str) -> bool | None:
        """Parse boolean parameter"""
        if value is None:
            return None
        return value.lower() == "true"

    def validate(self, csr, context: dict) -> List[str]:
        """Validate key usage extension matches requirements"""
        errors = []

        # Get key usage from context (set by default plugin)
        key_usage = context.get("key_usage")
        if not key_usage:
            return []

        # Check each bit if constrained
        checks = [
            (
                "digital_signature",
                self.digital_signature,
                key_usage.digital_signature,
            ),
            (
                "content_commitment",
                self.non_repudiation,
                getattr(key_usage, "content_commitment", False),
            ),
            (
                "key_encipherment",
                self.key_encipherment,
                key_usage.key_encipherment,
            ),
            (
                "data_encipherment",
                self.data_encipherment,
                key_usage.data_encipherment,
            ),
            ("key_agreement", self.key_agreement, key_usage.key_agreement),
            ("key_cert_sign", self.key_cert_sign, key_usage.key_cert_sign),
            ("crl_sign", self.crl_sign, key_usage.crl_sign),
        ]

        for name, required, actual in checks:
            if required is not None and required != actual:
                errors.append(
                    f"Key usage {name} must be {required}, not {actual}"
                )

        return errors


class ExtendedKeyUsageExtConstraint(Constraint):
    """extendedKeyUsageExtConstraintImpl - validates extended key usage"""

    def __init__(self, exKeyUsageOIDs: str = None, **kwargs):
        """Initialize extended key usage constraint

        Args:
            exKeyUsageOIDs: Comma-separated list of required EKU OIDs
        """
        self.required_oids = []
        if exKeyUsageOIDs:
            self.required_oids = [
                oid.strip() for oid in exKeyUsageOIDs.split(",")
            ]

    def validate(self, csr, context: dict) -> List[str]:
        """Validate extended key usage contains required OIDs"""
        errors = []

        # Get EKU from context (set by default plugin)
        eku = context.get("extended_key_usage")
        if not eku and self.required_oids:
            errors.append(
                "Extended key usage extension required but not present"
            )
            return errors

        # Check required OIDs are present
        # (Simplified - full implementation would check actual OIDs)

        return errors


class ExtensionConstraint(Constraint):
    """extensionConstraintImpl - validates certificate extensions"""

    def __init__(self, **kwargs):
        """Initialize extension constraint

        This constraint allows or denies specific certificate extensions.
        Parameters like extnIds (allowed extension OIDs) would be extracted
        from kwargs.
        """
        # Extract allowed extension OIDs if provided
        self.allowed_ext_oids = []
        if "extnIds" in kwargs:
            self.allowed_ext_oids = [
                oid.strip() for oid in kwargs["extnIds"].split(",")
            ]

    def validate(self, csr, context: dict) -> List[str]:
        """Validate certificate extensions

        For now, this is a permissive constraint (allows all extensions).
        Full implementation would check extension OIDs against allowed list.
        """
        errors = []

        # TODO: Implement extension validation if needed
        # For caOCSPCert, this is typically used to ensure specific
        # extensions are present or absent

        return errors


# Constraint factory
def create_constraint(class_id: str, params: Dict[str, Any]) -> Constraint:
    """Factory to instantiate constraints from .cfg data

    Args:
        class_id: Constraint class identifier
        params: Constraint parameters

    Returns:
        Instantiated Constraint object
    """
    constraint_map = {
        "noConstraintImpl": NoConstraint,
        "subjectNameConstraintImpl": SubjectNameConstraint,
        "validityConstraintImpl": ValidityConstraint,
        "keyConstraintImpl": KeyConstraint,
        "signingAlgConstraintImpl": SigningAlgConstraint,
        "keyUsageExtConstraintImpl": KeyUsageExtConstraint,
        "extendedKeyUsageExtConstraintImpl": ExtendedKeyUsageExtConstraint,
        "extensionConstraintImpl": ExtensionConstraint,
    }

    constraint_class = constraint_map.get(class_id)
    if not constraint_class:
        logger.warning(
            f"Unknown constraint class '{class_id}', using NoConstraint"
        )
        return NoConstraint()

    try:
        return constraint_class(**params)
    except Exception as e:
        logger.error(f"Failed to create constraint {class_id}: {e}")
        raise
