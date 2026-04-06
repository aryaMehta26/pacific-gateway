"""Tests for Layer 3 — Semantic Permission Check."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from gateway.semantic_permissions import (
    get_semantic_clearance_level,
    check_permission,
)


# Test documents
EXEC_DOC = {
    "id": "test_exec",
    "title": "Executive Compensation Review",
    "content": "CEO Sarah Chen: $8.2M total compensation. CFO James Park: $6.1M total.",
    "clearance_level": 5,
    "department": "executive",
    "category": "executive_hr",
}

GENERAL_DOC = {
    "id": "test_general",
    "title": "Holiday Schedule",
    "content": "All employees get December 25th and January 1st off.",
    "clearance_level": 1,
    "department": "hr",
    "category": "hr_general",
}

MISLABELED_DOC = {
    "id": "test_mislabel",
    "title": "Meeting Notes",
    "content": "Preliminary discussions to acquire Target Co at $4.2B. M&A deal structure: 60% cash. Board approval pending. Strictly confidential.",
    "clearance_level": 2,  # labeled as analyst-level but contains executive M&A data
    "department": "general",
    "category": "general",
}

INTERN = {"user_id": "intern_001", "name": "Test Intern", "role": "intern", "clearance_level": 1, "department": "general"}
ANALYST = {"user_id": "analyst_001", "name": "Test Analyst", "role": "analyst", "clearance_level": 2, "department": "finance"}
EXEC = {"user_id": "exec_001", "name": "Test Exec", "role": "executive", "clearance_level": 5, "department": "executive"}


class TestSemanticPermissions:
    """Test suite for semantic permission checking."""

    def test_exec_doc_high_semantic_level(self):
        """Executive compensation doc should be classified as high level."""
        result = get_semantic_clearance_level(EXEC_DOC)
        assert result["semantic_level"] >= 4
        assert result["metadata_level"] == 5

    def test_general_doc_low_semantic_level(self):
        """General holiday doc should be classified as low level."""
        result = get_semantic_clearance_level(GENERAL_DOC)
        assert result["semantic_level"] <= 2

    def test_mislabel_detection(self):
        """M&A content labeled as level 2 should be detected as mismatch."""
        result = get_semantic_clearance_level(MISLABELED_DOC)
        # Semantic level should be higher than metadata level
        assert result["semantic_level"] > result["metadata_level"]

    def test_intern_denied_exec_doc(self):
        """Intern should be denied access to executive document."""
        semantic = get_semantic_clearance_level(EXEC_DOC)
        perm = check_permission(INTERN, EXEC_DOC, semantic)
        assert perm["approved"] is False

    def test_exec_approved_exec_doc(self):
        """Executive should be approved for executive document."""
        semantic = get_semantic_clearance_level(EXEC_DOC)
        perm = check_permission(EXEC, EXEC_DOC, semantic)
        assert perm["approved"] is True

    def test_intern_approved_general_doc(self):
        """Intern should be approved for general document."""
        semantic = get_semantic_clearance_level(GENERAL_DOC)
        perm = check_permission(INTERN, GENERAL_DOC, semantic)
        assert perm["approved"] is True

    def test_permission_uses_higher_level(self):
        """Permission check should use the HIGHER of metadata vs semantic."""
        semantic = {"metadata_level": 2, "semantic_level": 5, "mismatch_detected": True}
        perm = check_permission(ANALYST, MISLABELED_DOC, semantic)
        assert perm["effective_doc_level"] == 5
        assert perm["approved"] is False

    def test_response_structure(self):
        """Response should have all expected fields."""
        result = get_semantic_clearance_level(GENERAL_DOC)
        assert "metadata_level" in result
        assert "semantic_level" in result
        assert "mismatch_detected" in result
        assert "confidence" in result
