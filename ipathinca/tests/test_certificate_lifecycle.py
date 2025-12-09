# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Tests for certificate lifecycle state machine

Tests the CertificateLifecycle class, state transitions, audit trail,
and serialization.
"""

import pytest
from datetime import datetime, timezone

from ipathinca.certificate_lifecycle import (
    CertificateState,
    CertificateEvent,
    CertificateLifecycle,
    StateTransition,
    STATE_TRANSITIONS,
    validate_state_machine,
)
from ipathinca.exceptions import InvalidStateTransition


# ======================================================================
# Enum tests
# ======================================================================


class TestCertificateState:
    """Test CertificateState enum."""

    def test_all_states_defined(self):
        """All six states must be defined."""
        expected = {
            "PENDING",
            "VALID",
            "EXPIRED",
            "REVOKED",
            "ON_HOLD",
            "SUPERSEDED",
        }
        actual = {s.value for s in CertificateState}
        assert actual == expected

    def test_is_terminal(self):
        """Only REVOKED and SUPERSEDED are terminal."""
        assert CertificateState.REVOKED.is_terminal()
        assert CertificateState.SUPERSEDED.is_terminal()
        assert not CertificateState.PENDING.is_terminal()
        assert not CertificateState.VALID.is_terminal()
        assert not CertificateState.EXPIRED.is_terminal()
        assert not CertificateState.ON_HOLD.is_terminal()

    def test_is_usable(self):
        """Only VALID is usable."""
        assert CertificateState.VALID.is_usable()
        for state in CertificateState:
            if state != CertificateState.VALID:
                assert not state.is_usable()

    def test_str(self):
        """String representation is the value."""
        assert str(CertificateState.VALID) == "VALID"


class TestCertificateEvent:
    """Test CertificateEvent enum."""

    def test_all_events_defined(self):
        """All six events must be defined."""
        expected = {
            "ISSUE",
            "EXPIRE",
            "REVOKE",
            "HOLD",
            "RELEASE",
            "SUPERSEDE",
        }
        actual = {e.value for e in CertificateEvent}
        assert actual == expected

    def test_str(self):
        """String representation is the value."""
        assert str(CertificateEvent.ISSUE) == "ISSUE"


# ======================================================================
# State transition rules
# ======================================================================


class TestStateTransitions:
    """Test the STATE_TRANSITIONS table."""

    def test_all_states_have_entries(self):
        """Every state must appear in the transition table."""
        for state in CertificateState:
            assert state in STATE_TRANSITIONS

    def test_pending_transitions(self):
        """PENDING can only transition to VALID via ISSUE."""
        t = STATE_TRANSITIONS[CertificateState.PENDING]
        assert t == {CertificateEvent.ISSUE: CertificateState.VALID}

    def test_valid_transitions(self):
        """VALID can expire, be revoked, held, or superseded."""
        t = STATE_TRANSITIONS[CertificateState.VALID]
        assert CertificateEvent.EXPIRE in t
        assert CertificateEvent.REVOKE in t
        assert CertificateEvent.HOLD in t
        assert CertificateEvent.SUPERSEDE in t
        assert len(t) == 4

    def test_on_hold_transitions(self):
        """ON_HOLD can be released, revoked, or expired."""
        t = STATE_TRANSITIONS[CertificateState.ON_HOLD]
        assert CertificateEvent.RELEASE in t
        assert CertificateEvent.REVOKE in t
        assert CertificateEvent.EXPIRE in t
        assert len(t) == 3

    def test_expired_can_be_revoked(self):
        """EXPIRED certs can be revoked for CRL inclusion."""
        t = STATE_TRANSITIONS[CertificateState.EXPIRED]
        assert t == {CertificateEvent.REVOKE: CertificateState.REVOKED}

    def test_terminal_states_empty(self):
        """REVOKED and SUPERSEDED have no outgoing transitions."""
        assert STATE_TRANSITIONS[CertificateState.REVOKED] == {}
        assert STATE_TRANSITIONS[CertificateState.SUPERSEDED] == {}

    def test_validate_state_machine(self):
        """Module-level validation must pass."""
        assert validate_state_machine() is True


# ======================================================================
# CertificateLifecycle tests
# ======================================================================


class TestCertificateLifecycle:
    """Test the CertificateLifecycle class."""

    def test_default_initial_state(self):
        """Default initial state is PENDING."""
        lc = CertificateLifecycle()
        assert lc.current_state == CertificateState.PENDING

    def test_custom_initial_state(self):
        """Can set initial state explicitly."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        assert lc.current_state == CertificateState.VALID

    def test_serial_number(self):
        """Serial number is stored."""
        lc = CertificateLifecycle(serial_number=42)
        assert lc.serial_number == 42

    def test_issue_transition(self):
        """PENDING → VALID via ISSUE."""
        lc = CertificateLifecycle()
        new_state = lc.transition(CertificateEvent.ISSUE, principal="admin")
        assert new_state == CertificateState.VALID
        assert lc.current_state == CertificateState.VALID

    def test_full_lifecycle_revoke(self):
        """PENDING → VALID → REVOKED."""
        lc = CertificateLifecycle(serial_number=100)
        lc.transition(CertificateEvent.ISSUE, principal="admin")
        lc.transition(
            CertificateEvent.REVOKE, principal="admin", reason="keyCompromise"
        )
        assert lc.current_state == CertificateState.REVOKED

    def test_hold_and_release(self):
        """VALID → ON_HOLD → VALID."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        lc.transition(
            CertificateEvent.HOLD, principal="admin", reason="Investigation"
        )
        assert lc.current_state == CertificateState.ON_HOLD
        lc.transition(CertificateEvent.RELEASE, principal="admin")
        assert lc.current_state == CertificateState.VALID

    def test_supersede(self):
        """VALID → SUPERSEDED."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        lc.transition(CertificateEvent.SUPERSEDE, principal="admin")
        assert lc.current_state == CertificateState.SUPERSEDED
        assert lc.is_terminal()

    def test_expire(self):
        """VALID → EXPIRED."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        lc.transition(CertificateEvent.EXPIRE)
        assert lc.current_state == CertificateState.EXPIRED
        assert not lc.is_usable()

    def test_expired_then_revoked(self):
        """EXPIRED → REVOKED for CRL inclusion."""
        lc = CertificateLifecycle(initial_state=CertificateState.EXPIRED)
        lc.transition(CertificateEvent.REVOKE, principal="admin")
        assert lc.current_state == CertificateState.REVOKED

    def test_on_hold_then_revoked(self):
        """ON_HOLD → REVOKED."""
        lc = CertificateLifecycle(initial_state=CertificateState.ON_HOLD)
        lc.transition(CertificateEvent.REVOKE, principal="admin")
        assert lc.current_state == CertificateState.REVOKED

    def test_on_hold_then_expired(self):
        """ON_HOLD → EXPIRED."""
        lc = CertificateLifecycle(initial_state=CertificateState.ON_HOLD)
        lc.transition(CertificateEvent.EXPIRE)
        assert lc.current_state == CertificateState.EXPIRED

    def test_invalid_transition_from_pending(self):
        """Cannot REVOKE from PENDING."""
        lc = CertificateLifecycle()
        with pytest.raises(InvalidStateTransition):
            lc.transition(CertificateEvent.REVOKE)

    def test_invalid_transition_from_revoked(self):
        """Cannot do anything from REVOKED (terminal)."""
        lc = CertificateLifecycle(initial_state=CertificateState.REVOKED)
        with pytest.raises(InvalidStateTransition):
            lc.transition(CertificateEvent.RELEASE)

    def test_invalid_transition_from_superseded(self):
        """Cannot do anything from SUPERSEDED (terminal)."""
        lc = CertificateLifecycle(initial_state=CertificateState.SUPERSEDED)
        with pytest.raises(InvalidStateTransition):
            lc.transition(CertificateEvent.ISSUE)

    def test_can_transition(self):
        """can_transition returns correct booleans."""
        lc = CertificateLifecycle()
        assert lc.can_transition(CertificateEvent.ISSUE)
        assert not lc.can_transition(CertificateEvent.REVOKE)

    def test_get_allowed_events_pending(self):
        """PENDING allows only ISSUE."""
        lc = CertificateLifecycle()
        assert lc.get_allowed_events() == {CertificateEvent.ISSUE}

    def test_get_allowed_events_valid(self):
        """VALID allows EXPIRE, REVOKE, HOLD, SUPERSEDE."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        expected = {
            CertificateEvent.EXPIRE,
            CertificateEvent.REVOKE,
            CertificateEvent.HOLD,
            CertificateEvent.SUPERSEDE,
        }
        assert lc.get_allowed_events() == expected

    def test_get_allowed_events_terminal(self):
        """Terminal states have no allowed events."""
        for state in (CertificateState.REVOKED, CertificateState.SUPERSEDED):
            lc = CertificateLifecycle(initial_state=state)
            assert lc.get_allowed_events() == set()

    def test_get_next_state(self):
        """get_next_state returns the correct target state."""
        lc = CertificateLifecycle()
        assert (
            lc.get_next_state(CertificateEvent.ISSUE) == CertificateState.VALID
        )
        assert lc.get_next_state(CertificateEvent.REVOKE) is None

    def test_is_usable(self):
        """is_usable is True only for VALID."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        assert lc.is_usable()
        lc.transition(CertificateEvent.HOLD)
        assert not lc.is_usable()

    def test_is_terminal(self):
        """is_terminal is True only for REVOKED and SUPERSEDED."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        assert not lc.is_terminal()
        lc.transition(CertificateEvent.REVOKE)
        assert lc.is_terminal()


# ======================================================================
# History and audit trail
# ======================================================================


class TestLifecycleHistory:
    """Test transition history tracking."""

    def test_empty_history(self):
        """New lifecycle has empty history."""
        lc = CertificateLifecycle()
        assert lc.get_history() == []
        assert lc.get_last_transition() is None

    def test_history_records_transitions(self):
        """History records each transition."""
        lc = CertificateLifecycle(serial_number=1)
        lc.transition(CertificateEvent.ISSUE, principal="admin")
        lc.transition(
            CertificateEvent.HOLD, principal="admin", reason="Investigation"
        )
        lc.transition(CertificateEvent.RELEASE, principal="admin")

        history = lc.get_history()
        assert len(history) == 3

        assert history[0].from_state == CertificateState.PENDING
        assert history[0].to_state == CertificateState.VALID
        assert history[0].event == CertificateEvent.ISSUE

        assert history[1].event == CertificateEvent.HOLD
        assert history[1].reason == "Investigation"

        assert history[2].event == CertificateEvent.RELEASE

    def test_get_last_transition(self):
        """get_last_transition returns most recent."""
        lc = CertificateLifecycle()
        lc.transition(CertificateEvent.ISSUE, principal="admin")
        last = lc.get_last_transition()
        assert last.event == CertificateEvent.ISSUE
        assert last.principal == "admin"

    def test_history_is_copy(self):
        """get_history returns a copy, not the internal list."""
        lc = CertificateLifecycle()
        lc.transition(CertificateEvent.ISSUE)
        history = lc.get_history()
        history.clear()
        assert len(lc.get_history()) == 1

    def test_transition_has_timestamp(self):
        """Each transition has a UTC timestamp."""
        lc = CertificateLifecycle()
        lc.transition(CertificateEvent.ISSUE)
        t = lc.get_last_transition()
        assert isinstance(t.timestamp, datetime)
        assert t.timestamp.tzinfo == timezone.utc

    def test_revocation_info_revoked(self):
        """get_revocation_info returns details for REVOKED state."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        lc.transition(
            CertificateEvent.REVOKE, principal="admin", reason="keyCompromise"
        )
        info = lc.get_revocation_info()
        assert info is not None
        assert info["reason"] == "keyCompromise"
        assert info["principal"] == "admin"
        assert info["from_state"] == "VALID"

    def test_revocation_info_on_hold(self):
        """get_revocation_info returns details for ON_HOLD state."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        lc.transition(CertificateEvent.HOLD, principal="admin")
        info = lc.get_revocation_info()
        assert info is not None
        assert info["reason"] == "certificateHold"

    def test_revocation_info_none_for_valid(self):
        """get_revocation_info returns None for non-revoked states."""
        lc = CertificateLifecycle(initial_state=CertificateState.VALID)
        assert lc.get_revocation_info() is None


# ======================================================================
# Serialization
# ======================================================================


class TestLifecycleSerialization:
    """Test to_dict/from_dict serialization."""

    def test_to_dict(self):
        """to_dict returns correct structure."""
        lc = CertificateLifecycle(serial_number=42)
        lc.transition(CertificateEvent.ISSUE, principal="admin")
        d = lc.to_dict()
        assert d["current_state"] == "VALID"
        assert d["serial_number"] == "42"
        assert len(d["history"]) == 1

    def test_from_dict(self):
        """from_dict restores state correctly."""
        data = {
            "current_state": "VALID",
            "serial_number": "42",
            "history": [],
        }
        lc = CertificateLifecycle.from_dict(data)
        assert lc.current_state == CertificateState.VALID
        assert lc.serial_number == 42

    def test_round_trip(self):
        """to_dict followed by from_dict preserves state."""
        lc = CertificateLifecycle(serial_number=99)
        lc.transition(CertificateEvent.ISSUE, principal="admin")
        lc.transition(CertificateEvent.HOLD, reason="test")

        data = lc.to_dict()
        lc2 = CertificateLifecycle.from_dict(data)

        assert lc2.current_state == lc.current_state
        assert lc2.serial_number == lc.serial_number
        assert len(lc2.history) == len(lc.history)

    def test_state_transition_to_dict(self):
        """StateTransition.to_dict returns correct keys."""
        t = StateTransition(
            from_state=CertificateState.PENDING,
            to_state=CertificateState.VALID,
            event=CertificateEvent.ISSUE,
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            principal="admin",
        )
        d = t.to_dict()
        assert d["from_state"] == "PENDING"
        assert d["to_state"] == "VALID"
        assert d["event"] == "ISSUE"
        assert d["principal"] == "admin"

    def test_state_transition_from_dict(self):
        """StateTransition.from_dict restores correctly."""
        data = {
            "from_state": "VALID",
            "to_state": "REVOKED",
            "event": "REVOKE",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "principal": "admin",
            "reason": "keyCompromise",
            "serial_number": "42",
        }
        t = StateTransition.from_dict(data)
        assert t.from_state == CertificateState.VALID
        assert t.to_state == CertificateState.REVOKED
        assert t.serial_number == 42

    def test_repr(self):
        """__repr__ contains useful info."""
        lc = CertificateLifecycle(serial_number=42)
        r = repr(lc)
        assert "42" in r
        assert "PENDING" in r


# ======================================================================
# InvalidStateTransition exception
# ======================================================================


class TestInvalidStateTransition:
    """Test the InvalidStateTransition exception."""

    def test_exception_attributes(self):
        """Exception carries state transition details."""
        exc = InvalidStateTransition(
            CertificateState.PENDING,
            CertificateEvent.REVOKE,
            {CertificateEvent.ISSUE},
        )
        assert exc.current_state == CertificateState.PENDING
        assert exc.attempted_event == CertificateEvent.REVOKE
        assert exc.allowed_events == {CertificateEvent.ISSUE}

    def test_exception_message(self):
        """Exception message is descriptive."""
        exc = InvalidStateTransition(
            CertificateState.PENDING,
            CertificateEvent.REVOKE,
            {CertificateEvent.ISSUE},
        )
        msg = str(exc)
        assert "PENDING" in msg
        assert "REVOKE" in msg
        assert "ISSUE" in msg

    def test_exception_to_dict(self):
        """to_dict includes structured error info."""
        exc = InvalidStateTransition(
            CertificateState.PENDING,
            CertificateEvent.REVOKE,
            {CertificateEvent.ISSUE},
        )
        d = exc.to_dict()
        assert d["error_type"] == "InvalidStateTransition"
        assert d["current_state"] == "PENDING"
        assert "ISSUE" in d["allowed_events"]
