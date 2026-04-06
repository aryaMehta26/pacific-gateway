"""Configuration for Pacific Security Gateway."""
import os
from dotenv import load_dotenv

load_dotenv()

# Ollama settings (local, no API key needed)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
CLASSIFIER_MODEL = os.getenv("CLASSIFIER_MODEL", "llama3.2")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "mxbai-embed-large")

# Voyage AI (optional, for production use)
VOYAGE_API_KEY = os.getenv("VOYAGE_API_KEY", "")

# Security thresholds
MOSAIC_SIMILARITY_THRESHOLD = 0.70
MOSAIC_MIN_QUERIES = 3
MOSAIC_LOOKBACK = 5

SENSITIVE_CATEGORIES = [
    "executive_compensation",
    "mergers_and_acquisitions",
    "personnel_records",
    "credit_risk_confidential",
    "layoff_plans",
    "trading_positions",
]

PII_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "US_SSN", "CREDIT_CARD", "LOCATION", "US_BANK_NUMBER",
]

AUDIT_LOG_PATH = "audit_log.jsonl"
