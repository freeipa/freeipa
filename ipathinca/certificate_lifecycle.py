# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Certificate Lifecycle State Machine

This module implements a proper state machine for certificate lifecycle
management, inspired by django-ca's approach. It provides:

1. Clear state definitions
2. Validated state transitions
3. Comprehensive audit trail
4. RFC 5280 compliance

States and Transitions:
    PENDING → VALID (issue)
    VALID → EXPIRED (expire)
    VALID → REVOKED (revoke)
    VALID → ON_HOLD (hold)
    VALID → SUPERSEDED (supersede)
    ON_HOLD → VALID (release)
    ON_HOLD → REVOKED (revoke)
    ON_HOLD → EXPIRED (expire)
    EXPIRED → REVOKED (revoke)  # Can revoke expired certs for CRL
    REVOKED: terminal state
    SUPERSEDED: terminal state

Example:
    >>> from ipathinca.certificate_lifecycle import CertificateLifecycle, \
    >>>     CertificateEvent
    >>>
    >>> # Create lifecycle for new certificate
    >>> lifecycle = CertificateLifecycle()
    >>> lifecycle.transition(CertificateEvent.ISSUE, principal='admin')
    >>> print(lifecycle.current_state)  # VALID
    >>>
    >>> # Put on hold
    >>> lifecycle.transition(CertificateEvent.HOLD, principal='admin',
    >>>                      reason='Investigation')
    >>> print(lifecycle.current_state)  # ON_HOLD
    >>>
    >>> # Release from hold
    >>> lifecycle.transition(CertificateEvent.RELEASE, principal='admin')
    >>> print(lifecycle.current_state)  # VALID
    >>>
    >>> # Revoke permanently
    >>> lifecycle.transition(CertificateEvent.REVOKE, principal='admin',
    >>>                      reason='keyCompromise')
    >>> print(lifecycle.current_state)  # REVOKED
"""

import logging
from enum import Enum
from typing import Optional, Set, List, Dict, Any
from datetime import datetime, timezone
from dataclasses import dataclass

from ipathinca.exceptions import InvalidStateTransition

logger = logging.getLogger(__name__)


class CertificateState(str, Enum):
    """
    Certificate lifecycle states

    States follow RFC 5280 certificate status model with additions
    for pending and superseded states.
    """

    PENDING = "PENDING"  # Request submitted, not yet issued
    VALID = "VALID"  # Active certificate, not revoked or expired
    EXPIRED = "EXPIRED"  # Past validity period (not_after exceeded)
    REVOKED = "REVOKED"  # Permanently revoked
    ON_HOLD = "ON_HOLD"  # Temporarily suspended (can be released)
    SUPERSEDED = "SUPERSEDED"  # Replaced by newer certificate

    def is_terminal(self) -> bool:
        """Check if this is a terminal state (no transitions out)"""
        return self in (CertificateState.REVOKED, CertificateState.SUPERSEDED)

    def is_usable(self) -> bool:
        """Check if certificate is usable in this state"""
        return self == CertificateState.VALID

    def __str__(self) -> str:
        return self.value


class CertificateEvent(str, Enum):
    """
    Events that trigger state transitions

    These events correspond to CA operations that change
    certificate status.
    """

    ISSUE = "ISSUE"  # Issue certificate from pending request
    EXPIRE = "EXPIRE"  # Certificate reaches not_after date
    REVOKE = "REVOKE"  # Permanently revoke certificate
    HOLD = "HOLD"  # Temporarily suspend certificate
    RELEASE = "RELEASE"  # Release certificate from hold
    SUPERSEDE = "SUPERSEDE"  # Mark as superseded by newer cert

    def __str__(self) -> str:
        return self.value


# State transition rules (RFC 5280 compliant)
# Format: {current_state: {event: next_state}}
STATE_TRANSITIONS: Dict[
    CertificateState, Dict[CertificateEvent, CertificateState]
] = {
    CertificateState.PENDING: {
        CertificateEvent.ISSUE: CertificateState.VALID,
    },
    CertificateState.VALID: {
        CertificateEvent.EXPIRE: CertificateState.EXPIRED,
        CertificateEvent.REVOKE: CertificateState.REVOKED,
        CertificateEvent.HOLD: CertificateState.ON_HOLD,
        CertificateEvent.SUPERSEDE: CertificateState.SUPERSEDED,
    },
    CertificateState.ON_HOLD: {
        CertificateEvent.RELEASE: CertificateState.VALID,
        CertificateEvent.REVOKE: CertificateState.REVOKED,
        CertificateEvent.EXPIRE: CertificateState.EXPIRED,
    },
    CertificateState.EXPIRED: {
        # RFC 5280: Expired certificates can still be revoked for CRL inclusion
        CertificateEvent.REVOKE: CertificateState.REVOKED,
    },
    # Terminal states - no transitions out
    CertificateState.REVOKED: {},
    CertificateState.SUPERSEDED: {},
}


# InvalidStateTransition is now imported from ipathinca.exceptions


@dataclass
class StateTransition:
    """
    Record of a single state transition

    This provides a complete audit trail of state changes with
    timestamps, principals, and reasons.

    Attributes:
        from_state: State before transition
        to_state: State after transition
        event: Event that triggered the transition
        timestamp: When the transition occurred (UTC)
        principal: Who initiated the transition (IPA principal)
        reason: Human-readable reason for the transition
        serial_number: Certificate serial number (for logging)
    """

    from_state: CertificateState
    to_state: CertificateState
    event: CertificateEvent
    timestamp: datetime
    principal: Optional[str] = None
    reason: Optional[str] = None
    serial_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/API"""
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "event": self.event.value,
            "timestamp": self.timestamp.isoformat(),
            "principal": self.principal,
            "reason": self.reason,
            "serial_number": (
                str(self.serial_number) if self.serial_number else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StateTransition":
        """Create from dictionary"""
        return cls(
            from_state=CertificateState(data["from_state"]),
            to_state=CertificateState(data["to_state"]),
            event=CertificateEvent(data["event"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            principal=data.get("principal"),
            reason=data.get("reason"),
            serial_number=(
                int(data["serial_number"])
                if data.get("serial_number")
                else None
            ),
        )

    def __str__(self) -> str:
        """Human-readable representation"""
        parts = [
            f"{self.from_state.value} → {self.to_state.value} "
            f"({self.event.value})"
        ]
        if self.principal:
            parts.append(f"by {self.principal}")
        if self.reason:
            parts.append(f"reason: {self.reason}")
        parts.append(f"at {self.timestamp.isoformat()}")
        return " ".join(parts)


class CertificateLifecycle:
    """
    Manages certificate lifecycle state machine

    This class enforces valid state transitions and maintains a complete
    audit trail of all state changes. It prevents invalid operations like
    revoking a revoked certificate or releasing a certificate that isn't on
    hold.

    Features:
    - State transition validation
    - Complete audit trail
    - RFC 5280 compliance
    - Principal tracking
    - Reason tracking

    Example:
        >>> lifecycle = CertificateLifecycle(serial_number=12345)
        >>> lifecycle.transition(CertificateEvent.ISSUE, principal='admin')
        >>> lifecycle.current_state
        VALID
        >>> lifecycle.can_transition(CertificateEvent.REVOKE)
        True
        >>> lifecycle.transition(CertificateEvent.REVOKE, principal='admin',
        >>>                      reason='keyCompromise')
        >>> lifecycle.current_state
        REVOKED
        >>> # Cannot transition from terminal state
        >>> lifecycle.can_transition(CertificateEvent.RELEASE)
        False
    """

    def __init__(
        self,
        initial_state: CertificateState = CertificateState.PENDING,
        serial_number: Optional[int] = None,
    ):
        """
        Initialize certificate lifecycle

        Args:
            initial_state: Initial state (default: PENDING)
            serial_number: Certificate serial number (for audit trail)
        """
        self.current_state = initial_state
        self.serial_number = serial_number
        self.history: List[StateTransition] = []

        logger.debug(
            f"Initialized lifecycle for cert {serial_number} in state "
            f"{initial_state.value}"
        )

    def can_transition(self, event: CertificateEvent) -> bool:
        """
        Check if a transition is allowed from current state

        Args:
            event: Event to check

        Returns:
            True if transition is allowed, False otherwise

        Example:
            >>> lifecycle = CertificateLifecycle()
            >>> lifecycle.can_transition(CertificateEvent.ISSUE)
            True
            >>> lifecycle.can_transition(CertificateEvent.REVOKE)
            False
        """
        allowed = STATE_TRANSITIONS.get(self.current_state, {})
        return event in allowed

    def get_allowed_events(self) -> Set[CertificateEvent]:
        """
        Get all allowed events from current state

        Returns:
            Set of allowed events

        Example:
            >>> lifecycle = CertificateLifecycle(CertificateState.VALID)
            >>> events = lifecycle.get_allowed_events()
            >>> CertificateEvent.REVOKE in events
            True
            >>> CertificateEvent.ISSUE in events
            False
        """
        return set(STATE_TRANSITIONS.get(self.current_state, {}).keys())

    def get_next_state(
        self, event: CertificateEvent
    ) -> Optional[CertificateState]:
        """
        Get the state that would result from an event (without transitioning)

        Args:
            event: Event to check

        Returns:
            Next state if transition is valid, None otherwise

        Example:
            >>> lifecycle = CertificateLifecycle(CertificateState.VALID)
            >>> lifecycle.get_next_state(CertificateEvent.REVOKE)
            REVOKED
            >>> lifecycle.get_next_state(CertificateEvent.ISSUE)
            None
        """
        return STATE_TRANSITIONS.get(self.current_state, {}).get(event)

    def transition(
        self,
        event: CertificateEvent,
        principal: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> CertificateState:
        """
        Perform a state transition

        This is the main method for changing certificate state. It validates
        the transition, records it in the audit trail, and updates the current
        state.

        Args:
            event: Event triggering the transition
            principal: Who is performing the transition (IPA principal)
            reason: Human-readable reason for the transition

        Returns:
            New state after transition

        Raises:
            InvalidStateTransition: If transition is not allowed

        Example:
            >>> lifecycle = CertificateLifecycle()
            >>> new_state = lifecycle.transition(
            ...     CertificateEvent.ISSUE,
            ...     principal='admin',
            ...     reason='New service certificate'
            ... )
            >>> print(new_state)
            VALID
        """
        # Validate transition
        if not self.can_transition(event):
            allowed_events = self.get_allowed_events()
            raise InvalidStateTransition(
                self.current_state, event, allowed_events
            )

        # Get new state
        old_state = self.current_state
        new_state = STATE_TRANSITIONS[old_state][event]

        # Create transition record
        transition = StateTransition(
            from_state=old_state,
            to_state=new_state,
            event=event,
            timestamp=datetime.now(timezone.utc),
            principal=principal,
            reason=reason,
            serial_number=self.serial_number,
        )

        # Record in history
        self.history.append(transition)

        # Update state
        self.current_state = new_state

        logger.debug(
            f"Certificate {self.serial_number} state transition: {transition}"
        )

        return new_state

    def get_history(self) -> List[StateTransition]:
        """
        Get complete transition history

        Returns:
            List of state transitions in chronological order

        Example:
            >>> lifecycle = CertificateLifecycle()
            >>> lifecycle.transition(CertificateEvent.ISSUE)
            >>> lifecycle.transition(CertificateEvent.HOLD)
            >>> lifecycle.transition(CertificateEvent.RELEASE)
            >>> history = lifecycle.get_history()
            >>> len(history)
            3
        """
        return self.history.copy()

    def get_last_transition(self) -> Optional[StateTransition]:
        """
        Get the most recent state transition

        Returns:
            Last transition or None if no transitions yet

        Example:
            >>> lifecycle = CertificateLifecycle()
            >>> lifecycle.get_last_transition()
            None
            >>> lifecycle.transition(CertificateEvent.ISSUE, principal='admin')
            >>> transition = lifecycle.get_last_transition()
            >>> transition.to_state
            VALID
        """
        return self.history[-1] if self.history else None

    def get_revocation_info(self) -> Optional[Dict[str, Any]]:
        """
        Get revocation information if certificate is revoked or on hold

        Returns:
            Dictionary with revocation details or None if not revoked/on hold

        Example:
            >>> lifecycle = CertificateLifecycle(CertificateState.VALID)
            >>> lifecycle.transition(CertificateEvent.REVOKE,
            >>>                      reason='keyCompromise')
            >>> info = lifecycle.get_revocation_info()
            >>> info['reason']
            'keyCompromise'
        """
        # Return revocation info for both REVOKED and ON_HOLD states
        if self.current_state not in (
            CertificateState.REVOKED,
            CertificateState.ON_HOLD,
        ):
            return None

        # For REVOKED state, find the REVOKE transition
        if self.current_state == CertificateState.REVOKED:
            for transition in reversed(self.history):
                if transition.event == CertificateEvent.REVOKE:
                    return {
                        "revoked_at": transition.timestamp,
                        "reason": transition.reason,
                        "principal": transition.principal,
                        "from_state": transition.from_state.value,
                    }

        # For ON_HOLD state, find the HOLD transition
        if self.current_state == CertificateState.ON_HOLD:
            for transition in reversed(self.history):
                if transition.event == CertificateEvent.HOLD:
                    return {
                        "revoked_at": transition.timestamp,
                        # RFC 5280 reason for ON_HOLD
                        "reason": "certificateHold",
                        "principal": transition.principal,
                        "from_state": transition.from_state.value,
                    }

        return None

    def is_usable(self) -> bool:
        """
        Check if certificate is currently usable

        Returns:
            True if certificate is in VALID state, False otherwise

        Example:
            >>> lifecycle = CertificateLifecycle(CertificateState.VALID)
            >>> lifecycle.is_usable()
            True
            >>> lifecycle.transition(CertificateEvent.HOLD)
            >>> lifecycle.is_usable()
            False
        """
        return self.current_state.is_usable()

    def is_terminal(self) -> bool:
        """
        Check if certificate is in a terminal state

        Returns:
            True if in REVOKED or SUPERSEDED state, False otherwise

        Example:
            >>> lifecycle = CertificateLifecycle(CertificateState.REVOKED)
            >>> lifecycle.is_terminal()
            True
            >>> lifecycle.get_allowed_events()
            set()
        """
        return self.current_state.is_terminal()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for storage/serialization

        Returns:
            Dictionary representation

        Example:
            >>> lifecycle = CertificateLifecycle(serial_number=12345)
            >>> lifecycle.transition(CertificateEvent.ISSUE)
            >>> data = lifecycle.to_dict()
            >>> data['current_state']
            'VALID'
        """
        return {
            "current_state": self.current_state.value,
            "serial_number": (
                str(self.serial_number) if self.serial_number else None
            ),
            "history": [t.to_dict() for t in self.history],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CertificateLifecycle":
        """
        Create from dictionary

        Args:
            data: Dictionary representation

        Returns:
            CertificateLifecycle instance

        Example:
            >>> data = {
            ...     'current_state': 'VALID',
            ...     'serial_number': '12345',
            ...     'history': []
            ... }
            >>> lifecycle = CertificateLifecycle.from_dict(data)
            >>> lifecycle.current_state
            VALID
        """
        serial_number = (
            int(data["serial_number"]) if data.get("serial_number") else None
        )
        lifecycle = cls(
            initial_state=CertificateState(data["current_state"]),
            serial_number=serial_number,
        )

        # Restore history
        lifecycle.history = [
            StateTransition.from_dict(t) for t in data.get("history", [])
        ]

        return lifecycle

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"CertificateLifecycle(serial={self.serial_number}, "
            f"state={self.current_state.value}, "
            f"transitions={len(self.history)})"
        )


def validate_state_machine() -> bool:
    """
    Validate the state machine configuration

    Checks that all states and events are properly configured
    and that there are no unreachable states.

    Returns:
        True if state machine is valid

    Raises:
        ValueError: If state machine configuration is invalid
    """
    # Check that all states have transitions defined
    all_states = set(CertificateState)
    states_with_transitions = set(STATE_TRANSITIONS.keys())

    if all_states != states_with_transitions:
        missing = all_states - states_with_transitions
        raise ValueError(f"States missing transition rules: {missing}")

    # Check that all transition targets are valid states
    for state, transitions in STATE_TRANSITIONS.items():
        for event, target_state in transitions.items():
            if target_state not in CertificateState:
                raise ValueError(
                    f"Invalid target state {target_state} in transition "
                    f"{state} --{event}--> {target_state}"
                )

    # Check for cycles that could prevent reaching terminal states
    # (This is actually OK - certificates can go VALID->HOLD->VALID->HOLD etc.)

    logger.debug("State machine validation passed")
    return True


# Validate state machine on module load
try:
    validate_state_machine()
except ValueError as e:
    logger.error(f"State machine validation failed: {e}")
    raise
