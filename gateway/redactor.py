"""
Layer 4 — PII Redactor

Before ANY document content reaches the LLM, scan and redact all PII
using Microsoft Presidio. Even if a user has permission to see a document,
raw PII (SSNs, emails, phone numbers) should be scrubbed.
"""

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from config import PII_ENTITIES

# Initialize engines (heavy init, do once)
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Replacement labels for each PII type
REDACTION_OPERATORS = {
    "PERSON": OperatorConfig("replace", {"new_value": "[PERSON REDACTED]"}),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL REDACTED]"}),
    "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE REDACTED]"}),
    "US_SSN": OperatorConfig("replace", {"new_value": "[SSN REDACTED]"}),
    "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CARD REDACTED]"}),
    "LOCATION": OperatorConfig("replace", {"new_value": "[LOCATION REDACTED]"}),
    "US_BANK_NUMBER": OperatorConfig("replace", {"new_value": "[BANK# REDACTED]"}),
}


def redact_pii(text: str) -> dict:
    """
    Scan text for PII and redact all instances.

    Returns:
        {
            "original_length": int,
            "redacted_text": str,
            "redactions_made": list[dict],
            "redaction_count": int
        }
    """
    # Analyze for PII entities
    results = analyzer.analyze(
        text=text,
        entities=PII_ENTITIES,
        language="en",
    )

    # Track what was found
    redactions = []
    for result in results:
        redactions.append({
            "type": result.entity_type,
            "score": round(result.score, 3),
            "start": result.start,
            "end": result.end,
            "original": text[result.start : result.end],
        })

    # Apply redaction
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators=REDACTION_OPERATORS,
    )

    return {
        "original_length": len(text),
        "redacted_text": anonymized.text,
        "redactions_made": redactions,
        "redaction_count": len(redactions),
    }
