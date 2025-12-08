# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Custom exception hierarchy for ipathinca

This module provides structured exceptions with detailed error information,
making debugging easier and enabling better API error responses.

Inspired by django-ca's exception design.
"""

from typing import Dict, Any, Optional, List, Set


class IPAThinCAError(Exception):
    """
    Base exception for all ipathinca errors

    All ipathinca exceptions inherit from this base class, providing
    consistent error handling and structured error information.

    Attributes:
        message: Human-readable error message
        context: Additional context information (optional)
    """

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        """
        Initialize the exception

        Args:
            message: Human-readable error message
            context: Additional context information
        """
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for API responses

        Returns:
            Dictionary with error information

        Example:
            >>> try:
            ...     raise IPAThinCAError("Something went wrong",
            ...                          context={'foo': 'bar'})
            ... except IPAThinCAError as e:
            ...     error_dict = e.to_dict()
            ...     print(error_dict)
            {'error': 'Something went wrong', 'error_type': 'IPAThinCAError',
             'context': {'foo': 'bar'}}
        """
        return {
            "error": self.message,
            "error_type": self.__class__.__name__,
            "context": self.context,
        }

    def __str__(self):
        return self.message


# ============================================================================
# Certificate Lifecycle Exceptions
# ============================================================================


class InvalidStateTransition(IPAThinCAError):
    """
    Invalid certificate lifecycle state transition

    Raised when attempting a state transition that is not allowed
    from the current state.

    Attributes:
        current_state: Current certificate state
        attempted_event: Event that was attempted
        allowed_events: Set of events allowed from current state
    """

    def __init__(self, current_state, attempted_event, allowed_events: Set):
        """
        Initialize invalid state transition exception

        Args:
            current_state: Current CertificateState
            attempted_event: CertificateEvent that was attempted
            allowed_events: Set of allowed CertificateEvents
        """
        self.current_state = current_state
        self.attempted_event = attempted_event
        self.allowed_events = allowed_events

        # Format allowed events for display
        if allowed_events:
            allowed_str = ", ".join(sorted(e.value for e in allowed_events))
        else:
            allowed_str = "none"

        message = (
            f"Invalid state transition: Cannot '{attempted_event.value}' "
            f"certificate in state '{current_state.value}'. Allowed "
            f"events: {allowed_str}"
        )
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with structured information"""
        return {
            "error": self.message,
            "error_type": "InvalidStateTransition",
            "current_state": self.current_state.value,
            "attempted_event": self.attempted_event.value,
            "allowed_events": sorted(e.value for e in self.allowed_events),
            "context": self.context,
        }


class CertificateLifecycleError(IPAThinCAError):
    """General certificate lifecycle error"""

    pass


# ============================================================================
# Storage Exceptions
# ============================================================================


class StorageError(IPAThinCAError):
    """Base exception for storage operations"""

    pass


class CertificateNotFound(StorageError):
    """
    Certificate not found in storage

    Attributes:
        serial_number: Serial number that was searched for
    """

    def __init__(
        self, serial_number: int, context: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize certificate not found exception

        Args:
            serial_number: Serial number that was not found
            context: Additional context (e.g., CA ID, search location)
        """
        self.serial_number = serial_number
        message = f"Certificate with serial number {serial_number} not found"
        super().__init__(message, context)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serial number"""
        result = super().to_dict()
        result["serial_number"] = self.serial_number
        return result


class ProfileNotFound(StorageError):
    """
    Certificate profile not found

    Attributes:
        profile_id: Profile ID that was searched for
        available_profiles: List of available profile IDs (optional)
    """

    def __init__(
        self, profile_id: str, available_profiles: Optional[List[str]] = None
    ):
        """
        Initialize profile not found exception

        Args:
            profile_id: Profile ID that was not found
            available_profiles: List of available profile IDs
        """
        self.profile_id = profile_id
        self.available_profiles = available_profiles or []

        message = f"Profile '{profile_id}' not found"
        if available_profiles:
            message += f". Available profiles: {', '.join(available_profiles)}"

        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with profile information"""
        result = super().to_dict()
        result["profile_id"] = self.profile_id
        if self.available_profiles:
            result["available_profiles"] = self.available_profiles
        return result


class StorageConnectionError(StorageError):
    """Failed to connect to storage backend (LDAP)"""

    pass


class StoragePermissionError(StorageError):
    """Permission denied accessing storage"""

    pass


# ============================================================================
# Certificate Request/Validation Exceptions
# ============================================================================


class CertificateRequestError(IPAThinCAError):
    """Base exception for certificate request errors"""

    pass


class InvalidCertificateRequest(CertificateRequestError):
    """
    CSR validation failed

    Raised when a Certificate Signing Request does not meet
    profile requirements.

    Attributes:
        validation_errors: List of validation error messages
        profile_id: Profile ID that was used for validation
    """

    def __init__(
        self, validation_errors: List[str], profile_id: Optional[str] = None
    ):
        """
        Initialize invalid certificate request exception

        Args:
            validation_errors: List of validation error messages
            profile_id: Profile ID used for validation
        """
        self.validation_errors = validation_errors
        self.profile_id = profile_id

        message = f"CSR validation failed: {len(validation_errors)} error(s)"
        if profile_id:
            message = (
                f"CSR validation against profile '{profile_id}' "
                f"failed: {len(validation_errors)} error(s)"
            )

        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with validation errors"""
        result = super().to_dict()
        result["validation_errors"] = self.validation_errors
        if self.profile_id:
            result["profile_id"] = self.profile_id
        return result


class InvalidCSRFormat(CertificateRequestError):
    """CSR format is invalid or cannot be parsed"""

    pass


class UnsupportedKeyType(CertificateRequestError):
    """
    Key type not supported

    Attributes:
        key_type: The unsupported key type
        supported_types: List of supported key types
    """

    def __init__(self, key_type: str, supported_types: List[str]):
        self.key_type = key_type
        self.supported_types = supported_types

        message = (
            f"Key type '{key_type}' is not supported. "
            f"Supported types: {', '.join(supported_types)}"
        )
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with key type information"""
        result = super().to_dict()
        result["key_type"] = self.key_type
        result["supported_types"] = self.supported_types
        return result


# ============================================================================
# Certificate Operation Exceptions
# ============================================================================


class CertificateOperationError(IPAThinCAError):
    """
    Certificate operation failed

    General exception for certificate operations (signing, revoking, etc.)
    """

    pass


class RevocationError(CertificateOperationError):
    """Certificate revocation operation failed"""

    pass


class SigningError(CertificateOperationError):
    """Certificate signing operation failed"""

    pass


class CRLGenerationError(CertificateOperationError):
    """CRL generation failed"""

    pass


# ============================================================================
# Profile Exceptions
# ============================================================================


class ProfileError(IPAThinCAError):
    """Base exception for profile operations"""

    pass


class ProfileValidationError(ProfileError):
    """
    Profile configuration is invalid

    Attributes:
        profile_id: Profile ID with invalid configuration
        validation_errors: List of validation errors
    """

    def __init__(self, profile_id: str, validation_errors: List[str]):
        self.profile_id = profile_id
        self.validation_errors = validation_errors

        message = (
            f"Profile '{profile_id}' configuration is invalid: "
            f"{len(validation_errors)} error(s)"
        )
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with validation errors"""
        result = super().to_dict()
        result["profile_id"] = self.profile_id
        result["validation_errors"] = self.validation_errors
        return result


class CircularProfileInheritance(ProfileError):
    """
    Circular inheritance detected in profile hierarchy

    Attributes:
        profile_chain: List of profile IDs showing the circular dependency
    """

    def __init__(self, profile_chain: List[str]):
        self.profile_chain = profile_chain

        message = (
            "Circular inheritance detected in profile hierarchy: "
            f"{' → '.join(profile_chain)}"
        )
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with profile chain"""
        result = super().to_dict()
        result["profile_chain"] = self.profile_chain
        return result


class ProfileAlreadyExists(ProfileError):
    """
    Attempted to create profile that already exists

    Attributes:
        profile_id: Profile ID that already exists
    """

    def __init__(self, profile_id: str):
        self.profile_id = profile_id
        message = f"Profile '{profile_id}' already exists"
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with profile ID"""
        result = super().to_dict()
        result["profile_id"] = self.profile_id
        return result


# Deprecated alias for backward compatibility
DuplicateProfileError = ProfileAlreadyExists


# ============================================================================
# CA Configuration Exceptions
# ============================================================================


class CAConfigurationError(IPAThinCAError):
    """CA configuration is invalid or missing"""

    pass


class CANotInitialized(CAConfigurationError):
    """CA has not been initialized yet"""

    pass


class InvalidCAConfiguration(CAConfigurationError):
    """CA configuration is invalid"""

    pass


# ============================================================================
# Utility Functions
# ============================================================================


def format_error_response(
    exception: IPAThinCAError, status_code: int = 400
) -> Dict[str, Any]:
    """
    Format exception as API error response

    Args:
        exception: IPAThinCAError to format
        status_code: HTTP status code (default: 400)

    Returns:
        Dictionary suitable for JSON API response

    Example:
        >>> try:
        ...     raise InvalidStateTransition(...)
        ... except IPAThinCAError as e:
        ...     response = format_error_response(e, status_code=409)
        ...     # Return as JSON in Flask/FastAPI
    """
    error_dict = exception.to_dict()
    error_dict["status_code"] = status_code
    return error_dict
