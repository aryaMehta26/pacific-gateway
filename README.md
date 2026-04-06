# Pacific Security Gateway

A zero-trust semantic security middleware for enterprise context management systems. The gateway intercepts every query between users and the LLM, enforcing 5 independent security layers before any enterprise data reaches the model. All inference and embedding computation runs locally via Ollama, so no sensitive data ever leaves the network.

## Dashboard
<img width="1470" height="831" alt="image" src="https://github.com/user-attachments/assets/7cd100af-796e-4639-9cc8-3713e43c8441" />


## Problem

Enterprise clients in regulated industries (finance, healthcare, defense) cannot adopt AI assistants unless they can guarantee:

- An intern cannot prompt the LLM into revealing executive compensation data
- Sequential "innocent" queries cannot be combined to reconstruct restricted information
- Documents mislabeled by administrators do not leak through metadata-only access control
- PII like SSNs, emails, and phone numbers never reach the language model
- Every access attempt is logged immutably for compliance audits

Traditional security relies on metadata tags and keyword blockers. Both fail against semantic attacks where the meaning of a query matters more than its keywords. This gateway solves that.

## Architecture

```
User Query
    |
    v
+---------------------------+
| Layer 1: Intent Classifier |  LLM analyzes the query itself for hostile intent
|   (Ollama / llama3.2)     |  Catches: "What is the CEO salary?" -> HIGH risk
+---------------------------+
    |
    v
+---------------------------+
| Layer 2: Mosaic Detector   |  Embedding similarity across session history
|   (Ollama / mxbai-embed)  |  Catches: 5 innocent queries that collectively
|                           |  target executive compensation -> BLOCKED
+---------------------------+
    |
    v
+---------------------------+
| Layer 3: Semantic RBAC     |  Compares document CONTENT against clearance
|   (Ollama / mxbai-embed)  |  level descriptions using cosine similarity.
|                           |  Catches: doc labeled L2 but containing L5
|                           |  M&A strategy -> DENIED despite metadata
+---------------------------+
    |
    v
+---------------------------+
| Layer 4: PII Redactor      |  Microsoft Presidio entity recognition
|   (presidio-analyzer)     |  Strips SSNs, emails, phone numbers, names
|                           |  before the LLM sees any approved content
+---------------------------+
    |
    v
+---------------------------+
| Layer 5: Audit Logger      |  Every transaction logged to JSONL with
|   (append-only JSONL)     |  timestamps, flags, denial reasons, and
|                           |  redaction counts for compliance review
+---------------------------+
    |
    v
+---------------------------+
| Layer 6: Secure LLM Answer |  Only now does the LLM receive the
|   (Ollama / llama3.2)     |  sanitized, permission-checked, PII-free
|                           |  context to generate a response
+---------------------------+
    |
    v
Safe Response to User
```

## How Each Layer Works

### Layer 1: Query Intent Classification

The user's raw query string is sent to a local llama3.2 instance with a security-focused system prompt. The LLM returns a structured JSON classification:

```json
{
  "risk_level": "HIGH",
  "suspected_category": "executive_compensation",
  "reasoning": "Query directly targets CEO salary data",
  "should_flag": true
}
```

The classifier watches for 6 sensitive categories: executive compensation, M&A activity, personnel records, credit risk data, layoff plans, and trading positions. It also detects indirect language patterns like hypothetical framing ("what would happen if...") and comparison questions that could reconstruct confidential data.

**Source:** `gateway/classifier.py`

### Layer 2: Mosaic Attack Detection

Every query from a user is appended to an in-memory session store (keyed by user ID). When the session accumulates 3 or more queries, the detector concatenates all recent queries into a single string and computes its embedding using `mxbai-embed-large`. This combined embedding is compared against pre-computed embeddings of 6 sensitive topic descriptions using cosine similarity.

If the maximum similarity exceeds the configurable threshold (default 0.70), the system concludes the user is building a mosaic and blocks the connection.

Example attack that gets caught:
1. "Who leads each major division?" (individually LOW risk)
2. "How many executives are in the C-suite?" (individually LOW risk)
3. "What was the total compensation budget last year?" (individually MEDIUM risk)
4. "How does our executive pay compare to peers?" (combined similarity crosses 0.70 -> BLOCKED)

**Source:** `gateway/mosaic_detector.py`

### Layer 3: Semantic Permission Enforcement

Traditional RBAC checks the document's metadata clearance level against the user's clearance. This fails when an administrator accidentally labels a Level 5 M&A document as Level 2.

The semantic layer computes the embedding of the document's actual content and compares it against embeddings of 5 clearance level descriptions (from "general company info" at L1 to "executive level M&A and compensation" at L5). The effective clearance is the maximum of the metadata level and the semantically inferred level.

This catches the "Project Falcon M&A Discussion Notes" which is categorized as L5 content by semantic analysis even if its metadata were somehow set to L2.

**Source:** `gateway/semantic_permissions.py`

### Layer 4: PII Redaction

Every approved document passes through Microsoft Presidio before reaching the LLM. The analyzer scans for 7 entity types (PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD, LOCATION, US_BANK_NUMBER) and replaces each detected entity with a labeled placeholder like `[SSN REDACTED]`.

This means the LLM can still answer questions about headcount changes, but it will never see the raw SSN `123-45-6789` or the email `john.doe@goldman.com` that appeared in the source document.

**Source:** `gateway/redactor.py`

### Layer 5: Immutable Audit Logging

Every transaction is appended to `audit_log.jsonl` with:
- Timestamp, user ID, and query text
- Final decision (APPROVED / DENIED)
- Denial reason
- Intent risk level and mosaic confidence score
- Number of PII entities redacted
- Response latency
- Security flags fired (HIGH_RISK_INTENT, MOSAIC_ATTACK_DETECTED, ACCESS_DENIED)

The audit endpoint aggregates these logs into dashboard statistics including approval rates, denial counts by user, and recent flagged events.

**Source:** `gateway/auditor.py`

### Layer 6: Secure LLM Answer Generation

After all 5 security layers have filtered and sanitized the data, the approved (and redacted) documents are sent to the local llama3.2 instance as context. The LLM generates a response using only the safe, permission-checked, PII-free content. If all documents were denied, the LLM returns a refusal message instead.

**Source:** `api/dashboard.py` (Layer 6 section)

## Project Structure

```
pacific-gateway/
|-- config.py                    # all thresholds, model names, sensitive categories
|-- main.py                      # MCP server entry point
|-- demo.py                      # CLI demo with rich terminal output
|-- requirements.txt
|-- Dockerfile
|-- .env.example
|
|-- gateway/
|   |-- classifier.py            # Layer 1: LLM intent classification
|   |-- mosaic_detector.py       # Layer 2: session embedding analysis
|   |-- semantic_permissions.py  # Layer 3: content-based RBAC
|   |-- redactor.py              # Layer 4: Presidio PII stripping
|   |-- auditor.py               # Layer 5: JSONL audit trail
|
|-- api/
|   |-- dashboard.py             # FastAPI backend, orchestrates all 6 layers
|   |-- static/
|       |-- index.html           # interactive web console
|
|-- mcp_server/
|   |-- server.py                # MCP protocol server for LLM tool integration
|
|-- data/
|   |-- documents.json           # 8 synthetic enterprise documents (L1-L5)
|   |-- users.json               # 4 user profiles (intern through executive)
|
|-- tests/
    |-- test_classifier.py
    |-- test_mosaic.py
    |-- test_permissions.py
    |-- test_redactor.py
```

## Data Model

### Users (data/users.json)

| User | Role | Clearance | Purpose |
|------|------|-----------|---------|
| Arya Intern | intern | 1 | tests denial of restricted content |
| Bob Analyst | analyst | 2 | tests PII redaction on permitted docs |
| Carol Manager | manager | 3 | tests mid-tier access with risk docs |
| Sarah Chen | executive | 5 | tests full access path |

### Documents (data/documents.json)

| Document | Category | Level | Notable Content |
|----------|----------|-------|-----------------|
| Company Holiday Schedule | hr_general | 1 | safe baseline |
| Q3 2024 Earnings Summary | finance_earnings | 2 | financial figures |
| Q3 Credit Risk Exposure | finance_risk | 3 | counterparty data |
| Project Falcon M&A Notes | executive_strategy | 5 | confidential deal terms |
| Executive Compensation Review | executive_hr | 5 | CEO/CFO/COO salaries |
| Q3 Headcount Changes | hr_changes | 2 | contains SSN and email for redaction testing |
| Tech Infrastructure Budget | technology | 3 | budget breakdowns |
| Employee Benefits Overview | hr_general | 1 | safe baseline |

## Setup

### Prerequisites

- Python 3.11+
- [Ollama](https://ollama.com) installed and running locally
- Required Ollama models pulled:

```bash
ollama pull llama3.2
ollama pull mxbai-embed-large
```

### Installation

```bash
git clone https://github.com/aryaMehta26/pacific-gateway.git
cd pacific-gateway

pip install -r requirements.txt
python -m spacy download en_core_web_lg

cp .env.example .env
```

### Running the Dashboard

```bash
python -m uvicorn api.dashboard:app --port 8000
```

Open `http://localhost:8000` in a browser. The dashboard provides:
- Identity selector (switch between intern, analyst, manager, executive)
- Free-text query input that runs through the live security pipeline
- 4 pre-configured threat scenarios
- Sequential animated layer-by-layer result visualization
- Audit and threat intelligence view with aggregate statistics

### Running the CLI Demo

```bash
python demo.py
```

Runs 4 scenarios in sequence with formatted terminal output via `rich`.

### Running via Docker

```bash
docker build -t pacific-gateway .
docker run -p 8000:8000 pacific-gateway
```

Note: the container needs network access to the host Ollama instance. The Dockerfile sets `OLLAMA_BASE_URL=http://host.docker.internal:11434` by default, which works on Docker Desktop for Mac and Windows.

## Demo Scenarios

### Scenario 1: Privileged Escalation

- **User:** Arya Intern (clearance L1)
- **Query:** "What is the CEO salary?"
- **Expected result:** Layer 1 flags HIGH risk (executive_compensation). Layer 3 denies access to the compensation document because the intern's L1 clearance is below the L5 requirement. Layer 6 refuses to generate an answer.

### Scenario 2: Permitted Access with PII Redaction

- **User:** Bob Analyst (clearance L2)
- **Query:** "What were the Q3 earnings?"
- **Expected result:** Layer 1 flags LOW risk. Layer 3 approves the Q3 Earnings Summary (L2 doc for L2 user). Layer 4 catches any PII in approved documents and replaces it with `[EMAIL REDACTED]`, `[SSN REDACTED]`, etc. Layer 6 generates a safe answer.

### Scenario 3: Mosaic Attack Simulation

- **User:** Arya Intern (clearance L1)
- **Queries:** 5 sequential queries that individually appear harmless but collectively target executive compensation patterns.
- **Expected result:** Queries 1-3 pass with rising confidence scores. Query 4 or 5 crosses the 0.70 similarity threshold and triggers a full session lock.

### Scenario 4: Mislabeled Document Detection

- **User:** Bob Analyst (clearance L2)
- **Query:** "Show me the Project Falcon M&A notes"
- **Expected result:** Layer 3 detects that the document content semantically matches L5 (executive M&A strategy) despite any metadata label. Access denied with a mismatch warning.

## Configuration

All security thresholds are centralized in `config.py`:

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `MOSAIC_SIMILARITY_THRESHOLD` | 0.70 | cosine similarity cutoff for mosaic detection |
| `MOSAIC_MIN_QUERIES` | 3 | minimum session queries before mosaic analysis activates |
| `MOSAIC_LOOKBACK` | 5 | number of recent queries to include in combined embedding |
| `SENSITIVE_CATEGORIES` | 6 categories | topic list for intent classification |
| `PII_ENTITIES` | 7 entity types | Presidio entity types to scan and redact |
| `CLASSIFIER_MODEL` | llama3.2 | Ollama model for intent classification and answer generation |
| `EMBEDDING_MODEL` | mxbai-embed-large | Ollama model for embedding computation |

## Testing

```bash
pytest tests/ -v
```

Tests cover:
- Intent classification output structure and risk level assignment
- Mosaic detection threshold behavior across query sequences
- Semantic permission enforcement including mismatch detection
- PII redaction accuracy for SSNs, emails, and phone numbers

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| LLM inference | Ollama (llama3.2) | intent classification, answer generation |
| Embeddings | Ollama (mxbai-embed-large) | mosaic detection, semantic RBAC |
| PII detection | Microsoft Presidio | entity recognition and redaction |
| API server | FastAPI | REST endpoints, dashboard serving |
| MCP integration | mcp Python SDK | Model Context Protocol for LLM tool use |
| NLP backend | spaCy (en_core_web_lg) | tokenization for Presidio |
| CLI output | rich | formatted terminal demo |

## License

MIT
