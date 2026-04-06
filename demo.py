"""
Pacific Security Gateway — Interactive Demo

Runs through 4 scenarios showing all 5 security layers in action.
Run with: python demo.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from gateway.classifier import classify_query_intent
from gateway.mosaic_detector import add_query_to_session, detect_mosaic_attack, clear_session
from gateway.semantic_permissions import get_semantic_clearance_level, check_permission
from gateway.redactor import redact_pii
from gateway.auditor import log_request, get_audit_stats, clear_audit_log

# Load data
DATA_DIR = Path(__file__).parent / "data"
with open(DATA_DIR / "documents.json") as f:
    DOCUMENTS = json.load(f)
with open(DATA_DIR / "users.json") as f:
    USERS = {u["user_id"]: u for u in json.load(f)}

console = Console()


def header():
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Pacific Security Gateway[/bold cyan]\n"
        "[dim]Zero-Trust Semantic Security for Enterprise AI[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))
    console.print()


def run_scenario(title: str, description: str, user_id: str, query: str, doc_ids: list[str] = None):
    """Run a single demo scenario through all security layers."""
    console.print(f"\n[bold yellow]{'━' * 60}[/bold yellow]")
    console.print(f"[bold yellow]  SCENARIO: {title}[/bold yellow]")
    console.print(f"[dim]  {description}[/dim]")
    console.print(f"[bold yellow]{'━' * 60}[/bold yellow]\n")

    user = USERS[user_id]
    console.print(f"  [cyan]User:[/cyan] {user['name']} (role: {user['role']}, clearance: {user['clearance_level']})")
    console.print(f"  [cyan]Query:[/cyan] \"{query}\"\n")

    start = time.time()

    # Layer 1
    console.print("[bold magenta]  ▸ Layer 1: Query Intent Classification[/bold magenta]")
    intent = classify_query_intent(query)
    risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(intent["risk_level"], "white")
    console.print(f"    Risk: [{risk_color}]{intent['risk_level']}[/{risk_color}]")
    console.print(f"    Category: {intent.get('suspected_category', 'none')}")
    console.print(f"    Reasoning: {intent['reasoning']}")
    console.print(f"    Flagged: {'🚨 YES' if intent['should_flag'] else '✅ NO'}\n")

    # Layer 2
    console.print("[bold magenta]  ▸ Layer 2: Mosaic Attack Detection[/bold magenta]")
    add_query_to_session(user_id, query)
    mosaic = detect_mosaic_attack(user_id)
    console.print(f"    Queries in session: {mosaic['query_count']}")
    console.print(f"    Mosaic detected: {'🚨 YES' if mosaic['is_mosaic_attack'] else '✅ NO'}")
    console.print(f"    Confidence: {mosaic['confidence']:.2%}")
    if mosaic['alert_message']:
        console.print(f"    [red]Alert: {mosaic['alert_message']}[/red]")
    console.print()

    # Layer 3 + 4 on relevant docs
    if doc_ids:
        docs_to_check = [d for d in DOCUMENTS if d["id"] in doc_ids]
    else:
        docs_to_check = DOCUMENTS[:3]

    approved_docs = []
    denied_docs = []

    console.print("[bold magenta]  ▸ Layer 3: Semantic Permission Check[/bold magenta]")
    for doc in docs_to_check:
        semantic = get_semantic_clearance_level(doc)
        perm = check_permission(user, doc, semantic)

        status = "[green]✅ APPROVED[/green]" if perm["approved"] else "[red]🚫 DENIED[/red]"
        console.print(f"    {status} — {doc['title']}")
        console.print(f"      Metadata level: {semantic['metadata_level']} | Semantic level: {semantic['semantic_level']} | Mismatch: {semantic['mismatch_detected']}")
        console.print(f"      {perm['reason']}")

        if perm["approved"]:
            approved_docs.append(doc)
        else:
            denied_docs.append(doc)
    console.print()

    # Layer 4 on approved docs
    console.print("[bold magenta]  ▸ Layer 4: PII Redaction[/bold magenta]")
    total_redactions = 0
    for doc in approved_docs:
        redaction = redact_pii(doc["content"])
        total_redactions += redaction["redaction_count"]
        if redaction["redaction_count"] > 0:
            console.print(f"    📄 {doc['title']}: {redaction['redaction_count']} PII items redacted")
            for r in redaction["redactions_made"]:
                console.print(f"      [{r['type']}] \"{r['original']}\" → [REDACTED]")
            console.print(f"    [dim]Redacted text: {redaction['redacted_text'][:100]}...[/dim]")
        else:
            console.print(f"    📄 {doc['title']}: No PII found ✅")
    console.print()

    elapsed = (time.time() - start) * 1000

    # Layer 5
    console.print("[bold magenta]  ▸ Layer 5: Audit Log[/bold magenta]")
    log_entry = log_request(
        user_id, query,
        [d["title"] for d in approved_docs],
        {"approved": len(approved_docs) > 0, "reason": "Demo scenario"},
        mosaic, intent,
        {"redaction_count": total_redactions},
        elapsed,
    )
    console.print(f"    Decision: {log_entry['decision']}")
    console.print(f"    Flags: {log_entry['flags'] if log_entry['flags'] else 'None'}")
    console.print(f"    Response time: {elapsed:.0f}ms")
    console.print()


def run_mosaic_scenario():
    """Special scenario: simulate a mosaic attack over 5 queries."""
    console.print(f"\n[bold red]{'━' * 60}[/bold red]")
    console.print(f"[bold red]  SCENARIO: Mosaic Attack Simulation[/bold red]")
    console.print(f"[dim]  Intern makes 5 innocent queries that collectively target exec comp[/dim]")
    console.print(f"[bold red]{'━' * 60}[/bold red]\n")

    user_id = "intern_001"
    user = USERS[user_id]
    clear_session(user_id)

    queries = [
        "Who leads each major division?",
        "How many executives are in the C-suite?",
        "What was the total compensation budget last year?",
        "How does our executive pay compare to industry peers?",
        "What bonuses were approved by the compensation committee?",
    ]

    console.print(f"  [cyan]User:[/cyan] {user['name']} (role: {user['role']}, clearance: {user['clearance_level']})\n")

    for i, q in enumerate(queries, 1):
        console.print(f"  [bold]Query {i}/5:[/bold] \"{q}\"")
        add_query_to_session(user_id, q)
        mosaic = detect_mosaic_attack(user_id)

        if mosaic["is_mosaic_attack"]:
            console.print(f"    [red]🚨 MOSAIC ATTACK DETECTED at query {i}![/red]")
            console.print(f"    Confidence: {mosaic['confidence']:.2%}")
            console.print(f"    Suspected target: {mosaic['suspected_target']}")
            console.print(f"    [red]{mosaic['alert_message']}[/red]")

            log_request(
                user_id, q, [],
                {"approved": False, "reason": "Mosaic attack detected"},
                mosaic,
                {"risk_level": "HIGH", "should_flag": True, "suspected_category": "mosaic", "reasoning": "Mosaic pattern"},
                {"redaction_count": 0},
                0.0,
            )
            break
        else:
            console.print(f"    Confidence: {mosaic['confidence']:.2%} — [green]Below threshold[/green]")
        console.print()


def show_audit_summary():
    """Display final audit stats."""
    stats = get_audit_stats()
    console.print(f"\n[bold cyan]{'━' * 60}[/bold cyan]")
    console.print(f"[bold cyan]  AUDIT DASHBOARD SUMMARY[/bold cyan]")
    console.print(f"[bold cyan]{'━' * 60}[/bold cyan]\n")

    table = Table(box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    for key, val in stats.items():
        if key not in ("suspicious_users", "recent_flags"):
            table.add_row(key.replace("_", " ").title(), str(val))

    console.print(table)


if __name__ == "__main__":
    header()
    clear_audit_log()

    # Scenario 1: Intern tries to access exec compensation
    run_scenario(
        "Intern Tries Executive Access",
        "Low-clearance intern asks about CEO salary",
        "intern_001",
        "What is the CEO's total compensation?",
        ["doc_005", "doc_008"],
    )

    # Scenario 2: Analyst accesses permitted financial data
    run_scenario(
        "Analyst Accesses Earnings (Permitted)",
        "Analyst with level 2 clearance queries Q3 earnings",
        "analyst_001",
        "What were the Q3 2024 earnings?",
        ["doc_002", "doc_001"],
    )

    # Scenario 3: Analyst accesses doc with PII
    run_scenario(
        "Document With PII — Redaction Demo",
        "Analyst accesses headcount doc containing SSN and email",
        "analyst_001",
        "What were the Q3 headcount changes?",
        ["doc_006"],
    )

    # Scenario 4: Mosaic attack
    run_mosaic_scenario()

    # Final audit summary
    show_audit_summary()

    console.print("\n[bold green]  Demo complete! ✨[/bold green]\n")
