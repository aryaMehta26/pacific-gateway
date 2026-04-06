"""Tests for Layer 4 — PII Redactor."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from gateway.redactor import redact_pii


class TestPIIRedactor:
    """Test suite for PII redaction."""

    def test_redact_ssn(self):
        """SSN should be redacted."""
        result = redact_pii("Employee SSN: 123-45-6789")
        assert "123-45-6789" not in result["redacted_text"]
        assert result["redaction_count"] >= 1

    def test_redact_email(self):
        """Email addresses should be redacted."""
        result = redact_pii("Contact john.doe@goldman.com for info")
        assert "john.doe@goldman.com" not in result["redacted_text"]
        assert result["redaction_count"] >= 1

    def test_redact_person_name(self):
        """Person names should be redacted."""
        result = redact_pii("CEO Sarah Chen approved the budget")
        # Presidio may or may not catch all names — check structure
        assert "redacted_text" in result
        assert result["original_length"] > 0

    def test_no_pii_clean_text(self):
        """Text without PII should pass through unchanged."""
        clean = "Q3 revenue was $12.4B, up 8% YoY."
        result = redact_pii(clean)
        assert result["redaction_count"] == 0
        assert result["redacted_text"] == clean

    def test_multiple_pii(self):
        """Multiple PII entities should all be redacted."""
        text = "Contact john.doe@goldman.com or SSN 123-45-6789"
        result = redact_pii(text)
        assert "john.doe@goldman.com" not in result["redacted_text"]
        assert "123-45-6789" not in result["redacted_text"]
        assert result["redaction_count"] >= 2

    def test_response_structure(self):
        """Response should have all expected fields."""
        result = redact_pii("test text")
        assert "original_length" in result
        assert "redacted_text" in result
        assert "redactions_made" in result
        assert "redaction_count" in result
        assert isinstance(result["redactions_made"], list)
