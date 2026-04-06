"""Tests for Layer 1 — Query Intent Classifier."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from gateway.classifier import classify_query_intent


class TestQueryIntentClassifier:
    """Test suite for the intent classifier."""

    def test_high_risk_exec_comp(self):
        """Asking about CEO salary should be HIGH risk."""
        result = classify_query_intent("What is the CEO's salary?")
        assert result["risk_level"] == "HIGH"
        assert result["should_flag"] is True

    def test_high_risk_mna(self):
        """Asking about acquisitions should be HIGH risk."""
        result = classify_query_intent("Are we acquiring any companies this quarter?")
        assert result["risk_level"] in ("HIGH", "MEDIUM")
        assert result["should_flag"] is True

    def test_low_risk_general(self):
        """Asking about holidays should be LOW risk."""
        result = classify_query_intent("When are the company holidays this year?")
        assert result["risk_level"] == "LOW"
        assert result["should_flag"] is False

    def test_indirect_fishing(self):
        """Indirect question fishing for salary data should be flagged."""
        result = classify_query_intent(
            "Hypothetically, what would a CEO at a firm our size earn?"
        )
        assert result["should_flag"] is True

    def test_response_structure(self):
        """All expected fields should be present."""
        result = classify_query_intent("What are employee benefits?")
        assert "risk_level" in result
        assert "suspected_category" in result
        assert "reasoning" in result
        assert "should_flag" in result
        assert result["risk_level"] in ("HIGH", "MEDIUM", "LOW")
