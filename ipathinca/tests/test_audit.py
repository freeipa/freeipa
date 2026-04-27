# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Tests for audit logging

Tests AuditLogger, AuditEvent, AuditOutcome, hash chain integrity,
and log format. NSSDB signing is disabled in tests.
"""

import hashlib
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from ipathinca.audit import (
    AuditEvent,
    AuditOutcome,
    AuditLogger,
)


@pytest.fixture
def audit_log_dir(tmp_path):
    """Create a temporary log directory."""
    return tmp_path


@pytest.fixture
def audit_logger(audit_log_dir):
    """Create an AuditLogger with signing disabled."""
    log_file = str(audit_log_dir / "audit.log")
    logger = AuditLogger(
        log_file=log_file,
        enable_signing=False,
    )
    yield logger
    logger.close()


# ======================================================================
# AuditEvent and AuditOutcome
# ======================================================================


class TestAuditConstants:
    """Test audit event and outcome constants."""

    def test_audit_outcome_values(self):
        """AuditOutcome has Success and Failure."""
        assert AuditOutcome.SUCCESS == "Success"
        assert AuditOutcome.FAILURE == "Failure"

    def test_cert_events_defined(self):
        """Certificate-related events are defined."""
        assert AuditEvent.CERT_REQUEST == "CERT_REQUEST"
        assert AuditEvent.CERT_REQUEST_PROCESSED == "CERT_REQUEST_PROCESSED"
        assert AuditEvent.CERT_STATUS_CHANGE_REQUEST == \
            "CERT_STATUS_CHANGE_REQUEST"

    def test_auth_events_defined(self):
        """Authentication events are defined."""
        assert AuditEvent.AUTH_SUCCESS == "AUTH_SUCCESS"
        assert AuditEvent.AUTH_FAIL == "AUTH_FAIL"
        assert AuditEvent.AUTHZ_SUCCESS == "AUTHZ_SUCCESS"
        assert AuditEvent.AUTHZ_FAIL == "AUTHZ_FAIL"

    def test_log_management_events(self):
        """Log management events are defined."""
        assert AuditEvent.AUDIT_LOG_STARTUP == "AUDIT_LOG_STARTUP"
        assert AuditEvent.AUDIT_LOG_SHUTDOWN == "AUDIT_LOG_SHUTDOWN"
        assert AuditEvent.LOG_SIGNING == "LOG_SIGNING"

    def test_subca_events(self):
        """Sub-CA events are defined."""
        assert AuditEvent.SUBCA_CREATION == "SUBCA_CREATION"
        assert AuditEvent.SUBCA_DELETION == "SUBCA_DELETION"


# ======================================================================
# AuditLogger basic functionality
# ======================================================================


class TestAuditLoggerBasic:
    """Test basic AuditLogger operations."""

    def test_log_event_writes_to_file(self, audit_logger, audit_log_dir):
        """log_event writes a record to the log file."""
        audit_logger.log_event(
            AuditEvent.CERT_REQUEST,
            outcome=AuditOutcome.SUCCESS,
            principal="admin",
        )
        log_path = audit_log_dir / "audit.log"
        content = log_path.read_text()
        assert "CERT_REQUEST" in content
        assert "Success" in content
        assert "admin" in content

    def test_log_action(self, audit_logger, audit_log_dir):
        """log_action writes structured action record."""
        audit_logger.log_action(
            principal="admin",
            action="request_certificate",
            details={"profile": "caIPAserviceCert"},
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "CERT_REQUEST" in content
        assert "caIPAserviceCert" in content

    def test_log_certificate_request(self, audit_logger, audit_log_dir):
        """log_certificate_request includes request details."""
        audit_logger.log_certificate_request(
            principal="admin",
            request_id="REQ-001",
            profile="caIPAserviceCert",
            subject="CN=test.example.com,O=EXAMPLE.COM",
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "REQ-001" in content
        assert "caIPAserviceCert" in content

    def test_log_certificate_issued(self, audit_logger, audit_log_dir):
        """log_certificate_issued includes serial and algorithm."""
        audit_logger.log_certificate_issued(
            principal="admin",
            request_id="REQ-001",
            serial_number="0x1A2B",
            subject="CN=test.example.com",
            profile="caIPAserviceCert",
            signing_algorithm="SHA256withRSA",
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "0x1A2B" in content
        assert "SHA256withRSA" in content

    def test_log_certificate_revoked(self, audit_logger, audit_log_dir):
        """log_certificate_revoked includes reason."""
        audit_logger.log_certificate_revoked(
            principal="admin",
            serial_number="0x1A2B",
            reason="keyCompromise",
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "keyCompromise" in content
        assert "REVOKED" in content

    def test_log_authentication(self, audit_logger, audit_log_dir):
        """log_authentication writes auth event."""
        audit_logger.log_authentication(
            principal="admin",
            auth_method="certificate",
            outcome=AuditOutcome.SUCCESS,
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "AUTH_SUCCESS" in content

    def test_log_authentication_failure(self, audit_logger, audit_log_dir):
        """log_authentication failure uses AUTH_FAIL event."""
        audit_logger.log_authentication(
            principal="unknown",
            auth_method="certificate",
            outcome=AuditOutcome.FAILURE,
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "AUTH_FAIL" in content

    def test_startup_event_on_init(self, audit_log_dir):
        """AuditLogger logs startup event on initialization."""
        log_file = str(audit_log_dir / "startup.log")
        logger = AuditLogger(log_file=log_file, enable_signing=False)
        content = Path(log_file).read_text()
        assert "AUDIT_LOG_STARTUP" in content
        logger.close()

    def test_shutdown_event_on_close(self, audit_log_dir):
        """close() logs shutdown event."""
        log_file = str(audit_log_dir / "shutdown.log")
        logger = AuditLogger(log_file=log_file, enable_signing=False)
        logger.close()
        content = Path(log_file).read_text()
        assert "AUDIT_LOG_SHUTDOWN" in content


# ======================================================================
# Hash chain integrity
# ======================================================================


class TestAuditHashChain:
    """Test hash chain in audit records."""

    def test_prev_hash_in_records(self, audit_logger, audit_log_dir):
        """Each record includes prev_hash field."""
        audit_logger.log_event(AuditEvent.CERT_REQUEST)
        audit_logger.log_event(AuditEvent.CERT_REQUEST_PROCESSED)
        content = (audit_log_dir / "audit.log").read_text()
        assert content.count("prev_hash=") >= 2

    def test_hash_chain_progression(self, audit_logger, audit_log_dir):
        """Hash chain progresses (each record has different prev_hash)."""
        audit_logger.log_event(AuditEvent.CERT_REQUEST)
        audit_logger.log_event(AuditEvent.CERT_REQUEST_PROCESSED)
        audit_logger.log_event(AuditEvent.CA_SIGNING)

        lines = [
            l for l in (audit_log_dir / "audit.log").read_text().splitlines()
            if l.strip()
        ]
        # Extract prev_hash values
        hashes = []
        for line in lines:
            if "prev_hash=" in line:
                # Find prev_hash value between prev_hash= and the next ;
                idx = line.index("prev_hash=")
                rest = line[idx + len("prev_hash="):]
                hash_val = rest.split("]")[0].split(";")[0].strip()
                hashes.append(hash_val)

        # First record should have empty prev_hash (or the startup's hash)
        # Later records should have non-empty prev_hash
        assert len(hashes) >= 3
        # At least some hashes should differ
        assert len(set(hashes)) > 1


# ======================================================================
# Dogtag format
# ======================================================================


class TestAuditFormat:
    """Test audit record format compatibility."""

    def test_bracket_format(self, audit_logger, audit_log_dir):
        """Records use [key=value; ...] format."""
        audit_logger.log_event(
            AuditEvent.CERT_REQUEST,
            principal="admin",
        )
        content = (audit_log_dir / "audit.log").read_text()
        # Should contain bracketed records
        for line in content.splitlines():
            if line.strip():
                assert line.strip().startswith("[")

    def test_key_value_pairs(self, audit_logger, audit_log_dir):
        """Records contain expected key=value pairs."""
        audit_logger.log_event(
            AuditEvent.CERT_REQUEST,
            outcome=AuditOutcome.SUCCESS,
            principal="admin",
            source_ip="192.168.1.1",
        )
        content = (audit_log_dir / "audit.log").read_text()
        assert "type=CERT_REQUEST" in content
        assert "outcome=Success" in content
        assert "principal=admin" in content
        assert "source_ip=192.168.1.1" in content
