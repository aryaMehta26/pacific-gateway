"""
Pacific Security Gateway -- Entry Point

Runs the MCP server for LLM integration.
For the web dashboard, run: python -m uvicorn api.dashboard:app --port 8000
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from mcp_server.server import main


if __name__ == "__main__":
    print("=" * 60)
    print("  Pacific Security Gateway -- MCP Server")
    print("  Zero-Trust Semantic Security for Enterprise AI")
    print("=" * 60)
    print()
    print("  Server is starting...")
    print("  Layers active:")
    print("    1. Query Intent Classifier (Ollama / llama3.2)")
    print("    2. Mosaic Attack Detector  (Ollama / mxbai-embed-large)")
    print("    3. Semantic Permission Check (Ollama / mxbai-embed-large)")
    print("    4. PII Redactor (Microsoft Presidio)")
    print("    5. Audit Logger (JSONL)")
    print()
    print("  Waiting for MCP client connection...")
    print("=" * 60)

    asyncio.run(main())
