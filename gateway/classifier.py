"""
Layer 1 — Query Intent Classifier

Uses a local Ollama LLM to analyze incoming queries and classify whether
they're trying to access sensitive enterprise information.
"""

import json
import requests
from config import OLLAMA_BASE_URL, CLASSIFIER_MODEL, SENSITIVE_CATEGORIES


def classify_query_intent(query: str) -> dict:
    """
    Classify a user query for security risk using local Ollama.

    Returns:
        {
            "risk_level": "HIGH" | "MEDIUM" | "LOW",
            "suspected_category": str | None,
            "reasoning": str,
            "should_flag": bool
        }
    """
    prompt = f"""You are a security classifier for an enterprise AI system at a major financial institution.

Analyze this query and determine if it is attempting to access sensitive enterprise information.

Query: "{query}"

Sensitive categories to watch for:
{', '.join(SENSITIVE_CATEGORIES)}

Also flag queries that use indirect language to fish for sensitive data, such as:
- Hypothetical framing ("What would happen if...")
- Comparison questions ("How does X compare to...")
- Seemingly innocent questions that could reconstruct confidential information

Respond in valid JSON only. No explanation outside the JSON:
{{
    "risk_level": "HIGH" or "MEDIUM" or "LOW",
    "suspected_category": "category_name" or null,
    "reasoning": "one sentence explanation",
    "should_flag": true or false
}}"""

    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={
                "model": CLASSIFIER_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=30,
        )
        response.raise_for_status()
        raw = response.json().get("response", "").strip()

        # Handle markdown wrapping
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        return json.loads(raw)
    except Exception as e:
        return {
            "risk_level": "MEDIUM",
            "suspected_category": None,
            "reasoning": f"Classification error: {str(e)[:100]}",
            "should_flag": True,
        }
