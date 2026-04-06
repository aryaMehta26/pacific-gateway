"""
Layer 2 — Mosaic Attack Detector

Tracks ALL queries per user in a session. Uses local Ollama embeddings
to detect if multiple individually-innocent queries are collectively
trying to reconstruct restricted information.

Example mosaic attack:
  Query 1: "Who leads the derivatives desk?"       -> LOW risk alone
  Query 2: "What is Asia Pacific headcount?"        -> LOW risk alone
  Query 3: "Who got promoted recently?"             -> LOW risk alone
  Query 4: "What's the typical bonus cycle?"        -> LOW risk alone
  Combined: HIGH RISK — reconstructing org chart + compensation data
"""

import numpy as np
import requests
from collections import defaultdict
from config import OLLAMA_BASE_URL, EMBEDDING_MODEL, MOSAIC_SIMILARITY_THRESHOLD, MOSAIC_MIN_QUERIES, MOSAIC_LOOKBACK

# In-memory session store (Redis in production)
session_store: dict[str, list[str]] = defaultdict(list)

SENSITIVE_TOPIC_DESCRIPTIONS = [
    "executive compensation packages salaries bonuses and equity grants for C-suite officers",
    "mergers and acquisitions deal terms target companies valuations and board approvals",
    "employee layoffs workforce reductions terminations and restructuring plans",
    "proprietary trading positions exposure limits and counterparty risk data",
    "confidential financial projections revenue forecasts and unreleased earnings",
    "organizational structure reporting chains promotions and executive hierarchy",
]

_sensitive_embeddings_cache = None


def _get_embedding(text: str) -> list[float]:
    """Get embedding from local Ollama."""
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/embeddings",
        json={"model": EMBEDDING_MODEL, "prompt": text},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def _get_sensitive_embeddings():
    """Compute and cache sensitive topic embeddings."""
    global _sensitive_embeddings_cache
    if _sensitive_embeddings_cache is None:
        _sensitive_embeddings_cache = [
            _get_embedding(desc) for desc in SENSITIVE_TOPIC_DESCRIPTIONS
        ]
    return _sensitive_embeddings_cache


def _cosine_similarity(a, b):
    """Compute cosine similarity between two vectors."""
    a, b = np.array(a), np.array(b)
    dot = np.dot(a, b)
    norm = np.linalg.norm(a) * np.linalg.norm(b)
    if norm == 0:
        return 0.0
    return float(dot / norm)


def add_query_to_session(user_id: str, query: str):
    """Add a query to the user's session history."""
    session_store[user_id].append(query)


def get_session_queries(user_id: str) -> list[str]:
    """Get all queries from a user's current session."""
    return session_store[user_id].copy()


def clear_session(user_id: str):
    """Clear a user's session."""
    session_store[user_id] = []


def detect_mosaic_attack(user_id: str) -> dict:
    """
    Analyze all queries from this user's session.
    Check if combined they're building toward restricted information.
    """
    queries = session_store[user_id]

    if len(queries) < MOSAIC_MIN_QUERIES:
        return {
            "is_mosaic_attack": False,
            "confidence": 0.0,
            "suspected_target": None,
            "query_count": len(queries),
            "alert_message": None,
            "all_similarities": {},
        }

    recent_queries = queries[-MOSAIC_LOOKBACK:]
    combined_text = " | ".join(recent_queries)

    try:
        query_embedding = _get_embedding(combined_text)
        sensitive_embeddings = _get_sensitive_embeddings()

        similarities = {}
        for desc, emb in zip(SENSITIVE_TOPIC_DESCRIPTIONS, sensitive_embeddings):
            similarities[desc] = round(_cosine_similarity(query_embedding, emb), 4)

        max_topic = max(similarities, key=similarities.get)
        max_similarity = similarities[max_topic]

        is_attack = (
            max_similarity > MOSAIC_SIMILARITY_THRESHOLD
            and len(queries) >= MOSAIC_MIN_QUERIES
        )

        return {
            "is_mosaic_attack": is_attack,
            "confidence": round(max_similarity, 4),
            "suspected_target": max_topic if is_attack else None,
            "query_count": len(queries),
            "alert_message": (
                f"MOSAIC ALERT: User '{user_id}' has made {len(queries)} queries "
                f"collectively targeting: {max_topic} "
                f"(confidence: {max_similarity:.2%})"
                if is_attack
                else None
            ),
            "all_similarities": similarities,
        }
    except Exception as e:
        return {
            "is_mosaic_attack": False,
            "confidence": 0.0,
            "suspected_target": None,
            "query_count": len(queries),
            "alert_message": f"Error: {str(e)[:100]}",
            "all_similarities": {},
        }
