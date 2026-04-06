"""
Layer 5 — Audit Logger

Logs EVERY request through the gateway to a JSONL file.
Provides queryable audit trail for compliance teams.
Flags suspicious patterns and tracks denial rates.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from config import AUDIT_LOG_PATH

_log_path = Path(AUDIT_LOG_PATH)


def log_request(
    user_id: str,
    query: str,
    documents_requested: list,
    permission_decision: dict,
    mosaic_result: dict,
    intent_classification: dict,
    redaction_result: dict,
    response_time_ms: float,
) -> dict:
    """Log a complete request to the audit trail."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "query": query,
        "documents_requested": documents_requested,
        "decision": "APPROVED" if permission_decision.get("approved") else "DENIED",
        "denial_reason": permission_decision.get("reason"),
        "intent_risk_level": intent_classification.get("risk_level", "UNKNOWN"),
        "mosaic_attack_detected": mosaic_result.get("is_mosaic_attack", False),
        "mosaic_confidence": mosaic_result.get("confidence", 0.0),
        "pii_redactions_applied": redaction_result.get("redaction_count", 0),
        "response_time_ms": round(response_time_ms, 1),
        "flags": [],
    }

    # Add security flags
    if intent_classification.get("should_flag"):
        entry["flags"].append("HIGH_RISK_INTENT")
    if mosaic_result.get("is_mosaic_attack"):
        entry["flags"].append("MOSAIC_ATTACK_DETECTED")
    if not permission_decision.get("approved"):
        entry["flags"].append("ACCESS_DENIED")

    # Append to JSONL file
    with open(_log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return entry


def get_audit_stats() -> dict:
    """Read audit log and return dashboard statistics."""
    if not _log_path.exists():
        return {"total_requests": 0, "message": "No audit log found yet"}

    entries = []
    with open(_log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    if not entries:
        return {"total_requests": 0}

    total = len(entries)
    approved = sum(1 for e in entries if e["decision"] == "APPROVED")
    denied = total - approved
    mosaic_attacks = sum(1 for e in entries if e["mosaic_attack_detected"])
    high_risk = sum(1 for e in entries if e["intent_risk_level"] == "HIGH")
    total_redactions = sum(e["pii_redactions_applied"] for e in entries)
    avg_response = sum(e["response_time_ms"] for e in entries) / total

    # Find most suspicious users (most denials)
    user_denial_counts: dict[str, int] = {}
    for entry in entries:
        if entry["decision"] == "DENIED":
            uid = entry["user_id"]
            user_denial_counts[uid] = user_denial_counts.get(uid, 0) + 1

    suspicious_users = sorted(
        user_denial_counts.items(), key=lambda x: x[1], reverse=True
    )[:5]

    # Collect recent flagged entries
    recent_flags = [e for e in entries[-20:] if e["flags"]]

    return {
        "total_requests": total,
        "approved": approved,
        "denied": denied,
        "approval_rate": f"{(approved / total) * 100:.1f}%",
        "mosaic_attacks_detected": mosaic_attacks,
        "high_risk_queries": high_risk,
        "total_pii_redactions": total_redactions,
        "avg_response_time_ms": f"{avg_response:.1f}",
        "suspicious_users": suspicious_users,
        "recent_flags": recent_flags,
    }


def clear_audit_log():
    """Clear the audit log (for testing)."""
    if _log_path.exists():
        _log_path.unlink()
