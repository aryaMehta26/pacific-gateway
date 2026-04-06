"""
Pacific Security Gateway — MCP Server

Main MCP server that LLMs connect to. Exposes tools for retrieving
enterprise context. All 5 security layers fire before data is returned.
Uses local Ollama for LLM + embeddings.
"""

import json
import time
import requests as http_requests
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from gateway.classifier import classify_query_intent
from gateway.mosaic_detector import add_query_to_session, detect_mosaic_attack
from gateway.semantic_permissions import get_semantic_clearance_level, check_permission
from gateway.redactor import redact_pii
from gateway.auditor import log_request, get_audit_stats
from config import OLLAMA_BASE_URL, EMBEDDING_MODEL

# ── Load mock data ──────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent / "data"

with open(DATA_DIR / "documents.json") as f:
    DOCUMENTS = json.load(f)
with open(DATA_DIR / "users.json") as f:
    USERS = {u["user_id"]: u for u in json.load(f)}


def _get_embedding(text: str) -> list[float]:
    """Get embedding from local Ollama."""
    response = http_requests.post(
        f"{OLLAMA_BASE_URL}/api/embeddings",
        json={"model": EMBEDDING_MODEL, "prompt": text},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["embedding"]


# ── MCP Server ──────────────────────────────────────────────────
server = Server("pacific-security-gateway")


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="retrieve_enterprise_context",
            description=(
                "Retrieves enterprise context for a query. "
                "Enforces permissions, detects mosaic attacks, "
                "redacts PII. Returns only safe context for the LLM."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The user's question"},
                    "user_id": {"type": "string", "description": "The authenticated user's ID"},
                },
                "required": ["query", "user_id"],
            },
        ),
        Tool(
            name="get_audit_dashboard",
            description="Returns audit statistics and security dashboard data",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "get_audit_dashboard":
        stats = get_audit_stats()
        return [TextContent(type="text", text=json.dumps(stats, indent=2))]

    if name == "retrieve_enterprise_context":
        return await _handle_retrieval(arguments)

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


async def _handle_retrieval(arguments: dict):
    """Core retrieval pipeline — all 5 security layers."""
    start_time = time.time()
    query = arguments["query"]
    user_id = arguments["user_id"]

    user = USERS.get(user_id)
    if not user:
        return [TextContent(type="text", text=json.dumps({"error": "Unknown user", "approved": False}))]

    # LAYER 1: Query Intent Classification
    intent = classify_query_intent(query)

    # LAYER 2: Session tracking + Mosaic Detection
    add_query_to_session(user_id, query)
    mosaic = detect_mosaic_attack(user_id)

    if mosaic["is_mosaic_attack"] and mosaic["confidence"] > 0.85:
        elapsed = (time.time() - start_time) * 1000
        log_request(user_id, query, [], {"approved": False, "reason": "Mosaic attack detected"},
                    mosaic, intent, {"redaction_count": 0}, elapsed)
        return [TextContent(type="text", text=json.dumps({
            "approved": False,
            "reason": "Security Alert: Suspicious query pattern detected",
            "alert": mosaic["alert_message"],
        }, indent=2))]

    # Simple similarity-based retrieval using Ollama embeddings
    import numpy as np
    query_emb = _get_embedding(query)
    doc_scores = []
    for doc in DOCUMENTS:
        doc_emb = _get_embedding(doc["content"])
        sim = float(np.dot(query_emb, doc_emb) / (np.linalg.norm(query_emb) * np.linalg.norm(doc_emb)))
        doc_scores.append((doc, sim))
    doc_scores.sort(key=lambda x: x[1], reverse=True)
    top_docs = [d for d, s in doc_scores[:3]]

    approved_docs = []
    denied_docs = []

    for doc in top_docs:
        # LAYER 3: Semantic Permission Check
        semantic_result = get_semantic_clearance_level(doc)
        permission = check_permission(user, doc, semantic_result)

        if permission["approved"]:
            # LAYER 4: PII Redaction
            redaction = redact_pii(doc["content"])
            approved_docs.append({
                "title": doc["title"],
                "content": redaction["redacted_text"],
                "redactions_applied": redaction["redaction_count"],
            })
        else:
            denied_docs.append({"title": doc["title"], "reason": permission["reason"]})

    elapsed = (time.time() - start_time) * 1000
    total_redactions = sum(d["redactions_applied"] for d in approved_docs)

    # LAYER 5: Audit Log
    log_request(user_id, query, [d["title"] for d in approved_docs],
                {"approved": len(approved_docs) > 0, "reason": "Query processed"},
                mosaic, intent, {"redaction_count": total_redactions}, elapsed)

    return [TextContent(type="text", text=json.dumps({
        "approved_context": approved_docs,
        "denied_documents": denied_docs,
        "intent_risk_level": intent["risk_level"],
        "pii_redactions_total": total_redactions,
        "response_time_ms": f"{elapsed:.1f}",
        "security_summary": {
            "intent_flagged": intent["should_flag"],
            "mosaic_detected": mosaic["is_mosaic_attack"],
            "docs_approved": len(approved_docs),
            "docs_denied": len(denied_docs),
        },
    }, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
