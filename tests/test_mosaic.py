"""Tests for Layer 2 — Mosaic Attack Detector."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from gateway.mosaic_detector import (
    add_query_to_session,
    detect_mosaic_attack,
    clear_session,
    get_session_queries,
)


class TestMosaicDetector:
    """Test suite for mosaic attack detection."""

    def setup_method(self):
        """Clear session before each test."""
        clear_session("test_user")

    def test_no_attack_single_query(self):
        """Single query should never trigger mosaic detection."""
        add_query_to_session("test_user", "What are the holidays?")
        result = detect_mosaic_attack("test_user")
        assert result["is_mosaic_attack"] is False
        assert result["query_count"] == 1

    def test_no_attack_two_queries(self):
        """Two queries should never trigger (below minimum)."""
        add_query_to_session("test_user", "What are the holidays?")
        add_query_to_session("test_user", "What's for lunch?")
        result = detect_mosaic_attack("test_user")
        assert result["is_mosaic_attack"] is False
        assert result["query_count"] == 2

    def test_benign_session(self):
        """Multiple unrelated queries should not trigger."""
        benign_queries = [
            "What are the company holidays?",
            "Where is the nearest office kitchen?",
            "How do I submit a PTO request?",
        ]
        for q in benign_queries:
            add_query_to_session("test_user", q)

        result = detect_mosaic_attack("test_user")
        # Benign queries should have lower confidence
        assert result["confidence"] < 0.9

    def test_attack_exec_comp(self):
        """Queries collectively targeting exec compensation should trigger."""
        attack_queries = [
            "Who are the members of the C-suite?",
            "What is the executive compensation structure?",
            "How much does the CEO earn in total compensation?",
            "What bonuses were approved by the compensation committee?",
            "What is the pay ratio between CEO and average employee?",
        ]
        for q in attack_queries:
            add_query_to_session("test_user", q)

        result = detect_mosaic_attack("test_user")
        # These are very targeted — should have high confidence
        assert result["confidence"] > 0.6
        assert result["query_count"] == 5

    def test_session_tracking(self):
        """Queries should accumulate in session."""
        add_query_to_session("test_user", "query 1")
        add_query_to_session("test_user", "query 2")
        queries = get_session_queries("test_user")
        assert len(queries) == 2

    def test_session_clear(self):
        """Clearing session should reset."""
        add_query_to_session("test_user", "query 1")
        clear_session("test_user")
        queries = get_session_queries("test_user")
        assert len(queries) == 0

    def test_response_structure(self):
        """Response should have all expected fields."""
        add_query_to_session("test_user", "test query")
        result = detect_mosaic_attack("test_user")
        assert "is_mosaic_attack" in result
        assert "confidence" in result
        assert "query_count" in result
        assert "alert_message" in result
