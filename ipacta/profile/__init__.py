"""
Certificate profile data model

This module defines the data structures for representing parsed certificate
profiles, including policy chains, constraints, and defaults.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from abc import ABC, abstractmethod

from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


@dataclass
class InputPlugin:
    """Profile input plugin configuration"""

    input_id: str
    class_id: str


@dataclass
class OutputPlugin:
    """Profile output plugin configuration"""

    output_id: str
    class_id: str


@dataclass
class Constraint(ABC):
    """Base class for profile constraints

    Constraints validate certificate signing requests according to
    profile-defined rules.
    """

    @abstractmethod
    def validate(self, csr, context: dict) -> List[str]:
        """Validate CSR against constraint

        Args:
            csr: cryptography CSR object
            context: Request context dictionary

        Returns:
            List of error messages (empty if validation passes)
        """


@dataclass
class Default(ABC):
    """Base class for profile defaults

    Defaults provide values for certificate fields during issuance.
    """

    @abstractmethod
    def apply(self, builder, csr, context: dict):
        """Apply default to certificate builder

        Args:
            builder: x509.CertificateBuilder
            csr: cryptography CSR object
            context: Request context dictionary

        Returns:
            Modified certificate builder
        """


@dataclass
class PolicyRule:
    """Single policy rule in a profile's policy chain

    Each policy consists of a constraint (validation) and a default
    (value provider) that are executed in sequence.
    """

    number: int
    constraint_name: str
    constraint: Constraint
    default_name: str
    default: Default


@dataclass
class Profile:
    """Parsed certificate profile

    Represents a complete profile parsed from a .cfg file, including
    all metadata, policy chains, constraints, and defaults.
    """

    profile_id: str
    class_id: str
    name: str
    description: str
    enabled: bool
    visible: bool
    auth_instance_id: Optional[str] = None
    authz_acl: Optional[str] = None
    enabled_by: Optional[str] = None

    # Input/output plugins
    inputs: List[InputPlugin] = field(default_factory=list)
    outputs: List[OutputPlugin] = field(default_factory=list)

    # Policy set
    policyset_name: str = ""
    policies: List[PolicyRule] = field(default_factory=list)

    # Raw configuration for debugging
    raw_config: Dict[str, str] = field(default_factory=dict)

    def get_policy_by_number(self, number: int) -> Optional[PolicyRule]:
        """Get policy by its sequence number"""
        for policy in self.policies:
            if policy.number == number:
                return policy
        return None

    def get_allowed_signing_algorithms(self) -> Optional[List[str]]:
        """Extract allowed signing algorithms from profile

        Returns:
            List of allowed algorithm strings, or None if not constrained
        """
        for policy in self.policies:
            if hasattr(policy.constraint, "allowed"):
                # This is a SigningAlgConstraint
                return policy.constraint.allowed
        return None

    def get_default_signing_algorithm(self) -> Optional[str]:
        """Get the default signing algorithm from profile

        Returns:
            Default algorithm string, or None if server decides
        """
        for policy in self.policies:
            if hasattr(policy.default, "signing_alg"):
                # This is a SigningAlgDefault
                alg = policy.default.signing_alg
                return None if alg == "-" else alg
        return None

    @property
    def validity_days(self) -> int:
        """Get validity period in days from profile

        Returns:
            Validity period in days (default: 365)
        """
        for policy in self.policies:
            if hasattr(policy.default, "range_days"):
                # This is a ValidityDefault
                return policy.default.range_days
        return 365  # Default if no ValidityDefault found

    def validate_csr(self, csr, context: dict) -> List[str]:
        """Validate CSR against all profile constraints

        This method simulates the policy chain execution to validate the CSR.
        It applies defaults (to build the final certificate subject/extensions)
        and then validates constraints against the constructed values.

        Args:
            csr: cryptography CSR object
            context: Request context dictionary

        Returns:
            List of validation error messages (empty if valid)
        """
        from cryptography import x509

        errors = []

        # Create a dummy certificate builder to simulate policy chain
        # This allows defaults to populate context with final values
        # (like final_subject_dn) that constraints can validate
        # NOTE: Don't pre-populate fields that defaults will set,
        # as builders only allow each field to be set once
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(1)  # Dummy serial (required)
        # Issuer will be set by defaults if needed
        # Subject, validity, public key will be set by defaults

        # Execute policy chain: apply defaults, then validate constraints
        for policy in self.policies:
            # Apply default (populates context and builder)
            if policy.default:
                try:
                    builder = policy.default.apply(builder, csr, context)
                except Exception:
                    # Some defaults may fail on dummy builder (that's OK)
                    # We only care about context population
                    pass

            # Validate constraint
            if policy.constraint:
                constraint_errors = policy.constraint.validate(csr, context)
                errors.extend(constraint_errors)

        return errors


def extract_request_variable(text: str, csr, context: dict) -> str:
    """Extract $$request.X$$ variables at runtime

    This is called by default plugins when they have access to the
    actual CSR and request context.

    Args:
        text: Text containing $$request.X$$ variables
        csr: CSR object
        context: Request context with 'request' dict

    Returns:
        Text with request variables extracted
    """

    pattern = r"\$\$request\.req_subject_name\.(\w+)\$\$"

    def replacer(match):
        attr = match.group(1).upper()

        oid_map = {
            "CN": NameOID.COMMON_NAME,
            "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "C": NameOID.COUNTRY_NAME,
            "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "L": NameOID.LOCALITY_NAME,
        }

        oid = oid_map.get(attr)
        if not oid:
            logger.warning("Unknown subject attribute: %s", attr)
            return match.group(0)

        try:
            attrs = csr.subject.get_attributes_for_oid(oid)
            if attrs:
                return attrs[0].value
        except Exception as e:
            logger.warning("Failed to extract %s: %s", attr, e)

        return match.group(0)

    return re.sub(pattern, replacer, text)
