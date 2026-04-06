"""
Pacific Security Gateway — FastAPI Backend + Web Dashboard

Serves the interactive web dashboard and provides API endpoints
for running queries through all 5 security layers.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from gateway.classifier import classify_query_intent
from gateway.mosaic_detector import add_query_to_session, detect_mosaic_attack, clear_session
from gateway.semantic_permissions import get_semantic_clearance_level, check_permission
from gateway.redactor import redact_pii
from gateway.auditor import log_request, get_audit_stats, clear_audit_log

# Load data
DATA_DIR = Path(__file__).parent.parent / "data"
with open(DATA_DIR / "documents.json") as f:
    DOCUMENTS = json.load(f)
with open(DATA_DIR / "users.json") as f:
    USERS = {u["user_id"]: u for u in json.load(f)}

app = FastAPI(
    title="Pacific Security Gateway",
    description="Zero-Trust Semantic Security for Enterprise AI",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the main dashboard HTML."""
    html_path = STATIC_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(), status_code=200)
    return HTMLResponse(content="<h1>Dashboard not found. Check api/static/index.html</h1>", status_code=404)


@app.get("/api/users")
def get_users():
    """Return all available users."""
    return list(USERS.values())


@app.get("/api/documents")
def get_documents():
    """Return all documents (metadata only, no content for security)."""
    return [
        {"id": d["id"], "title": d["title"], "category": d["category"],
         "clearance_level": d["clearance_level"], "department": d["department"]}
        for d in DOCUMENTS
    ]


@app.post("/api/query")
async def run_query(request: Request):
    """
    Run a query through all 5 security layers.
    Returns detailed results from each layer.
    """
    body = await request.json()
    query = body.get("query", "")
    user_id = body.get("user_id", "")

    if not query or not user_id:
        return {"error": "query and user_id required"}

    user = USERS.get(user_id)
    if not user:
        return {"error": f"Unknown user: {user_id}"}

    start_time = time.time()
    layers = []

    # ── LAYER 1: Query Intent Classification ────────────────
    t1 = time.time()
    intent = classify_query_intent(query)
    layers.append({
        "name": "Query Intent Classifier",
        "layer": 1,
        "icon": "🔍",
        "time_ms": round((time.time() - t1) * 1000),
        "result": intent,
    })

    # ── LAYER 2: Mosaic Attack Detection ────────────────────
    t2 = time.time()
    add_query_to_session(user_id, query)
    mosaic = detect_mosaic_attack(user_id)
    layers.append({
        "name": "Mosaic Attack Detector",
        "layer": 2,
        "icon": "🕵️",
        "time_ms": round((time.time() - t2) * 1000),
        "result": mosaic,
    })

    # Check if blocked by mosaic
    if mosaic.get("is_mosaic_attack") and mosaic.get("confidence", 0) > 0.85:
        elapsed = (time.time() - start_time) * 1000
        log_request(
            user_id, query, [],
            {"approved": False, "reason": "Mosaic attack detected"},
            mosaic, intent, {"redaction_count": 0}, elapsed,
        )
        return {
            "blocked": True,
            "reason": "Mosaic attack detected",
            "user": user,
            "layers": layers,
            "total_time_ms": round(elapsed),
        }

    # ── LAYER 3: Semantic Permission Check ──────────────────
    approved_docs = []
    denied_docs = []
    semantic_results = []

    t3 = time.time()
    for doc in DOCUMENTS:
        try:
            semantic = get_semantic_clearance_level(doc)
            perm = check_permission(user, doc, semantic)
            entry = {
                "doc_id": doc["id"],
                "title": doc["title"],
                "metadata_level": semantic["metadata_level"],
                "semantic_level": semantic["semantic_level"],
                "mismatch": semantic["mismatch_detected"],
                "approved": perm["approved"],
                "reason": perm["reason"],
            }
            semantic_results.append(entry)
            if perm["approved"]:
                approved_docs.append(doc)
            else:
                denied_docs.append(doc)
        except Exception as e:
            semantic_results.append({
                "doc_id": doc["id"],
                "title": doc["title"],
                "error": str(e),
                "approved": False,
                "reason": f"Error: {str(e)}",
            })
            denied_docs.append(doc)

    layers.append({
        "name": "Semantic Permission Check",
        "layer": 3,
        "icon": "📄",
        "time_ms": round((time.time() - t3) * 1000),
        "result": {
            "documents": semantic_results,
            "approved_count": len(approved_docs),
            "denied_count": len(denied_docs),
        },
    })

    # ── LAYER 4: PII Redaction ──────────────────────────────
    t4 = time.time()
    redaction_results = []
    total_redactions = 0

    for doc in approved_docs:
        redaction = redact_pii(doc["content"])
        total_redactions += redaction["redaction_count"]
        redaction_results.append({
            "title": doc["title"],
            "original_preview": doc["content"][:100] + "..." if len(doc["content"]) > 100 else doc["content"],
            "redacted_preview": redaction["redacted_text"][:100] + "..." if len(redaction["redacted_text"]) > 100 else redaction["redacted_text"],
            "redaction_count": redaction["redaction_count"],
            "redactions": redaction["redactions_made"],
        })

    layers.append({
        "name": "PII Redactor",
        "layer": 4,
        "icon": "✂️",
        "time_ms": round((time.time() - t4) * 1000),
        "result": {
            "documents": redaction_results,
            "total_redactions": total_redactions,
        },
    })

    # ── LAYER 5: Audit Logger ───────────────────────────────
    elapsed = (time.time() - start_time) * 1000

    t5 = time.time()
    log_entry = log_request(
        user_id, query,
        [d["title"] for d in approved_docs],
        {"approved": len(approved_docs) > 0, "reason": "Query processed"},
        mosaic, intent,
        {"redaction_count": total_redactions},
        elapsed,
    )

    layers.append({
        "name": "Audit Logger",
        "layer": 5,
        "icon": "📋",
        "time_ms": round((time.time() - t5) * 1000),
        "result": {
            "decision": log_entry["decision"],
            "flags": log_entry["flags"],
            "logged": True,
        },
    })

    # ── LAYER 6: AI Assistant Generation ────────────────────
    t6 = time.time()
    import requests
    from config import OLLAMA_BASE_URL, CLASSIFIER_MODEL
    
    if len(approved_docs) > 0:
        safe_context = "\n\n".join([f"Doc: {d['title']}\n{redact_pii(d['content'])['redacted_text']}" for d in approved_docs])
        prompt = f"Use ONLY the following enterprise context to answer the user's question. If the answer is not in the context, say 'I cannot find the answer in the provided allowed context.'\n\nContext:\n{safe_context}\n\nQuestion: {query}"
        
        try:
            llm_res = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json={
                "model": CLASSIFIER_MODEL,
                "prompt": prompt,
                "stream": False
            }, timeout=30)
            final_answer = llm_res.json().get("response", "No answer generated.")
        except Exception as e:
            final_answer = f"Error generating answer: {str(e)}"
    else:
        final_answer = "I cannot answer this question as the security gateway has blocked access to all required context."

    layers.append({
        "name": "Secure LLM Answer",
        "layer": 6,
        "icon": "🤖",
        "time_ms": round((time.time() - t6) * 1000),
        "result": {
            "answer": final_answer
        }
    })

    return {
        "blocked": False,
        "user": user,
        "query": query,
        "layers": layers,
        "summary": {
            "intent_risk": intent.get("risk_level", "UNKNOWN"),
            "mosaic_detected": mosaic.get("is_mosaic_attack", False),
            "docs_approved": len(approved_docs),
            "docs_denied": len(denied_docs),
            "pii_redacted": total_redactions,
            "flags": log_entry["flags"],
        },
        "total_time_ms": round(elapsed),
    }


@app.get("/api/audit/stats")
def audit_stats():
    """Get aggregated audit statistics."""
    return get_audit_stats()


@app.post("/api/audit/clear")
def clear_audit():
    """Clear audit log."""
    clear_audit_log()
    return {"status": "cleared"}


@app.post("/api/session/clear")
async def clear_user_session(request: Request):
    """Clear a user's session history."""
    body = await request.json()
    user_id = body.get("user_id", "")
    if user_id:
        clear_session(user_id)
    return {"status": "session cleared", "user_id": user_id}


@app.get("/health")
def health():
    return {"status": "healthy"}
