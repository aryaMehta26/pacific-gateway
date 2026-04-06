# Pacific Security Gateway — Detailed Project Explanation

## What We Built & Why It Matters for Pacific

---

## 1. The Problem We're Solving

Pacific is building an **Enterprise Context Management System (ECMS)** — a "magical personal library" that sits between a company's internal data and any LLM. Their biggest clients are financial institutions like Goldman Sachs.

The #1 blocker for enterprise AI adoption is **security fear**:

> "What if our AI leaks our CEO's salary?"
> "What if someone uses the AI to piece together our secret M&A deal?"
> "What if documents get mislabeled and the AI shows restricted data?"

**Current solutions only check metadata labels** — they look at a document's tag and say "this is level 2, analyst can see it." But what if someone labeled an M&A document as "meeting notes"? The metadata says safe, but the content is toxic.

**We built the security layer that Pacific needs to sell to Goldman Sachs.**

---

## 2. What We Built

A **Zero-Trust Semantic Security Gateway** — a 5-layer security middleware that processes every single query before any data reaches the LLM.

Think of it as a security guard with 5 different checks:

```
User asks a question
        │
┌───────▼───────────────────────────────────────┐
│  Layer 1: "Is this question suspicious?"       │
│  Uses an LLM to classify intent               │
├───────────────────────────────────────────────┤
│  Layer 2: "Is this user slowly building        │
│  a picture of restricted data?"                │
│  Tracks ALL queries in a session               │
│  using embedding similarity (MOSAIC DETECTION) │
├───────────────────────────────────────────────┤
│  Layer 3: "Does this document actually         │
│  contain what its label says?"                 │
│  Embeds content and compares against           │
│  clearance level descriptions                  │
├───────────────────────────────────────────────┤
│  Layer 4: "Strip all personal info"            │
│  Redacts SSNs, emails, phone numbers,          │
│  names before LLM ever sees them               │
├───────────────────────────────────────────────┤
│  Layer 5: "Log everything for compliance"      │
│  Every request → JSONL audit trail             │
│  Flags, decisions, timing — all recorded       │
└───────────────────────────────────────────────┘
        │
        ▼
   Only safe, filtered context reaches the LLM
```

---

## 3. The 5 Security Layers — Deep Dive

### Layer 1: Query Intent Classifier (`gateway/classifier.py`)

**What it does:** Before we even look at documents, we analyze the question itself.

**How it works:**
- Takes the user's raw query
- Sends it to a local LLM (Llama 3.2 via Ollama)
- Asks: "Is this query trying to access sensitive categories?"
- Returns a risk level (HIGH / MEDIUM / LOW) and the suspected category

**Example:**
```
Input:  "What is the CEO's salary?"
Output: { risk_level: "HIGH", suspected_category: "executive_compensation", should_flag: true }

Input:  "When are the company holidays?"
Output: { risk_level: "LOW", suspected_category: null, should_flag: false }
```

**Why it matters:** This catches obvious attacks before any data is retrieved, saving compute and reducing exposure surface.

---

### Layer 2: Mosaic Attack Detector (`gateway/mosaic_detector.py`)

**This is the most novel part of the entire project.**

**What is a mosaic attack?** It's when someone asks 5 innocent questions that individually reveal nothing, but together reconstruct restricted information.

**How it works:**
1. Every query from a user is stored in a session history
2. When 3+ queries accumulate, we combine the last 5 into one text blob
3. We embed that combined text using `mxbai-embed-large` (local Ollama)
4. We compare it against pre-embedded descriptions of sensitive topics:
   - "executive compensation packages salaries bonuses..."
   - "mergers and acquisitions deal terms..."
   - etc.
5. If cosine similarity exceeds 0.70 → **MOSAIC ATTACK DETECTED**

**Example attack sequence:**
```
Query 1: "Who leads each major division?"              → 0.35 similarity → OK
Query 2: "How many executives in the C-suite?"          → 0.48 similarity → OK
Query 3: "What was total compensation budget?"          → 0.62 similarity → OK
Query 4: "How does exec pay compare to peers?"          → 0.71 similarity → 🚨 BLOCKED
```

Each query alone is LOW risk. But combined, they clearly target executive compensation data.

**Why it matters:** No existing security tool does this. Traditional permission systems only look at individual requests in isolation. This is the one feature that would genuinely differentiate Pacific's security story.

---

### Layer 3: Semantic Permission Check (`gateway/semantic_permissions.py`)

**What it does:** Checks if a document's actual content matches its clearance label.

**How it works:**
1. We embed the document's content
2. We embed descriptions of what each clearance level should contain:
   - Level 1: "general company info, holidays, HR policies..."
   - Level 2: "analyst financial summaries, quarterly earnings..."
   - Level 5: "executive compensation, M&A, board discussions..."
3. We find which level description is most similar to the document's content
4. If the semantic level is higher than the metadata level → **MISLABEL DETECTED**
5. We use the HIGHER of the two for the permission check

**Example:**
```
Document: "Project Falcon Meeting Notes"
Metadata label: Level 2 (analyst)
Content: "Preliminary discussions to acquire Target Co at $4.2B..."
Semantic analysis: Level 5 (executive — M&A content)
Result: MISMATCH DETECTED → requires Level 5 clearance
```

**Why it matters:** In real enterprises, documents get mislabeled ALL the time. A junior analyst tags an M&A doc as "meeting notes" and suddenly the whole firm can see it. This layer catches that.

---

### Layer 4: PII Redactor (`gateway/redactor.py`)

**What it does:** Even if you have permission to see a document, raw PII should never reach the LLM.

**How it works:**
- Uses Microsoft's **Presidio** library (open source, runs locally)
- Scans for: person names, email addresses, phone numbers, SSNs, credit card numbers, locations, bank account numbers
- Replaces each with a safe placeholder

**Example:**
```
Original:  "Contact john.doe@goldman.com. Employee SSN: 123-45-6789"
Redacted:  "Contact [EMAIL REDACTED]. Employee SSN: [SSN REDACTED]"
```

**Why it matters:** Even senior executives shouldn't see raw SSNs in an AI response. This is table-stakes compliance for financial services.

---

### Layer 5: Audit Logger (`gateway/auditor.py`)

**What it does:** Logs every single request for compliance.

**What gets logged:**
- Timestamp
- User ID
- Query text
- Which documents were requested/approved/denied
- Intent risk classification
- Mosaic attack detection result
- Number of PII items redacted
- Response time
- Security flags

**Output format:** JSONL file (one JSON object per line) — easy to ship to Splunk, Datadog, or any SIEM system.

**Dashboard stats available:**
- Total requests, approval rate
- Mosaic attacks detected
- PII redactions applied
- Most suspicious users (by denial count)
- Average response time

**Why it matters:** Financial services regulators (SEC, FINRA, OCC) require audit trails for data access. This gives CISOs full visibility into how AI accesses company data.

---

## 4. The Interactive Dashboard (`api/static/index.html`)

A full web-based UI where you can:

1. **Select a user identity** (intern, analyst, manager, executive)
2. **Type any query** and watch all 5 layers process it in real-time
3. **Run quick scenarios** — one-click demos of each security layer
4. **Run a Mosaic Attack simulation** — sends 5 progressively suspicious queries
5. **View the Audit Log** — see all flagged entries and aggregate stats

---

## 5. How This Helps Pacific

### For Pacific's Sales Team

> "Goldman's CISO asks: How do you prevent data leakage?"
>
> Pacific can demo this gateway: "Every query goes through 5 security layers. We detect not just obvious attacks, but sophisticated mosaic patterns where someone tries to reconstruct restricted data across multiple innocent queries. We also catch mislabeled documents semantically — even if someone tags an M&A doc as 'meeting notes,' our system detects the content is executive-level. All access is logged for your compliance team."

### For Pacific's Engineering Team

This is a working MCP server that plugs directly into Pacific's ECMS architecture. The security layers are modular — Pacific can:
- Swap the LLM (Ollama → Claude → GPT-4)
- Swap the embedding model (mxbai → Voyage Finance)
- Add new layers (prompt injection detection, etc.)
- Scale the session store (in-memory → Redis)
- Ship audit logs to any destination

### For Pacific's Product Roadmap

The mosaic attack detector opens a new product capability. Pacific could offer:
- **Real-time session threat monitoring** across all users
- **Anomaly detection dashboards** for CISOs
- **Compliance reporting** with automatic regulatory format export

---

## 6. Technical Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Web Dashboard                      │
│                  (HTML/CSS/JS)                        │
├─────────────────────────────────────────────────────┤
│                    FastAPI Server                      │
│              (api/dashboard.py)                       │
├───────┬───────┬───────────┬──────────┬──────────────┤
│ Layer1│ Layer2│  Layer 3  │ Layer 4  │   Layer 5    │
│Classif│Mosaic │ Semantic  │   PII    │   Audit      │
│  ier  │Detect │ Perms     │ Redact   │   Logger     │
├───────┴───────┴───────────┴──────────┴──────────────┤
│            Ollama (Local LLM + Embeddings)            │
│         llama3.2 (classifier) + mxbai-embed-large    │
│                                                       │
│            Microsoft Presidio (PII - Local)           │
└─────────────────────────────────────────────────────┘
```

**Everything runs locally. No cloud APIs. No API keys. No costs.**

---

## 7. How to Run

```bash
# 1. Start Ollama
ollama serve

# 2. Install dependencies
cd pacific-gateway
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# 3. Start the dashboard
uvicorn api.dashboard:app --reload --port 8000

# 4. Open browser
open http://localhost:8000
```

---

## 8. Files Overview

| File | Purpose |
|------|---------|
| `config.py` | All settings, thresholds, model names |
| `gateway/classifier.py` | Layer 1: LLM-based query classification |
| `gateway/mosaic_detector.py` | Layer 2: Session-based mosaic attack detection |
| `gateway/semantic_permissions.py` | Layer 3: Embedding-based document clearance |
| `gateway/redactor.py` | Layer 4: PII redaction with Presidio |
| `gateway/auditor.py` | Layer 5: JSONL audit logging + stats |
| `mcp_server/server.py` | MCP server for LLM integration |
| `api/dashboard.py` | FastAPI backend + web server |
| `api/static/index.html` | Interactive web dashboard |
| `data/documents.json` | 8 mock enterprise documents |
| `data/users.json` | 4 mock users with clearance levels |
| `demo.py` | Terminal-based demo (Rich formatting) |
| `tests/` | 27 pytest tests across all layers |
| `Dockerfile` | Container deployment |
