"""
Layer 3 — Semantic Permission Check

Uses local Ollama embeddings to understand what a document actually
contains, regardless of its metadata label.

Example: A doc titled "Meeting Notes" has clearance_level: 2 but
actually contains M&A information (level 5). We catch this.
"""

import numpy as np
import requests
from config import OLLAMA_BASE_URL, EMBEDDING_MODEL

CLEARANCE_LEVEL_DESCRIPTIONS = {
    1: "general company information, public announcements, holidays, general HR policies, employee benefits",
    2: "analyst level financial summaries, quarterly earnings, department updates, headcount changes",
    3: "manager level risk reports, credit exposure, budget details, technology infrastructure costs",
    4: "director level strategic planning, compensation bands, performance reviews, organizational changes",
    5: "executive level compensation details, mergers and acquisitions, confidential deals, board discussions, CEO salary",
}

_level_embeddings_cache = None


def _get_embedding(text: str) -> list[float]:
    """Get embedding from local Ollama."""
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/embeddings",
        json={"model": EMBEDDING_MODEL, "prompt": text},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def _get_level_embeddings():
    """Compute and cache clearance level description embeddings."""
    global _level_embeddings_cache
    if _level_embeddings_cache is None:
        _level_embeddings_cache = {
            level: _get_embedding(desc)
            for level, desc in CLEARANCE_LEVEL_DESCRIPTIONS.items()
        }
    return _level_embeddings_cache


def _cosine_similarity(a, b):
    a, b = np.array(a), np.array(b)
    dot = np.dot(a, b)
    norm = np.linalg.norm(a) * np.linalg.norm(b)
    if norm == 0:
        return 0.0
    return float(dot / norm)


def get_semantic_clearance_level(document: dict) -> dict:
    """
    Analyze document content semantically and return what clearance
    level it ACTUALLY deserves based on content.
    """
    try:
        doc_embedding = _get_embedding(document["content"])
        level_embeddings = _get_level_embeddings()

        similarities = {
            level: _cosine_similarity(doc_embedding, emb)
            for level, emb in level_embeddings.items()
        }

        semantic_level = max(similarities, key=similarities.get)
        confidence = similarities[semantic_level]
        metadata_level = document["clearance_level"]
        mismatch = semantic_level > metadata_level + 1

        return {
            "metadata_level": metadata_level,
            "semantic_level": int(semantic_level),
            "mismatch_detected": mismatch,
            "confidence": round(float(confidence), 4),
            "warning": (
                f"MISLABEL DETECTED: Document '{document['title']}' is labeled "
                f"level {metadata_level} but content suggests level {semantic_level}"
                if mismatch
                else None
            ),
        }
    except Exception as e:
        return {
            "metadata_level": document["clearance_level"],
            "semantic_level": document["clearance_level"],
            "mismatch_detected": False,
            "confidence": 0.0,
            "warning": f"Error: {str(e)[:100]}",
        }


def check_permission(user: dict, document: dict, semantic_result: dict) -> dict:
    """
    Final permission decision using BOTH metadata AND semantic analysis.
    Uses the HIGHER of metadata vs semantic level for maximum security.
    """
    effective_doc_level = max(
        semantic_result["metadata_level"],
        semantic_result["semantic_level"],
    )

    user_level = user["clearance_level"]
    approved = user_level >= effective_doc_level

    return {
        "approved": approved,
        "user_level": user_level,
        "effective_doc_level": effective_doc_level,
        "metadata_level": semantic_result["metadata_level"],
        "semantic_level": semantic_result["semantic_level"],
        "reason": (
            "Access granted"
            if approved
            else f"Access denied: document requires level {effective_doc_level}, user has level {user_level}"
        ),
    }
