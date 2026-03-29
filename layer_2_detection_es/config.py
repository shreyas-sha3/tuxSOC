"""
config.py
---------
Central configuration for the Elasticsearch-native Layer-2 detection engine.
All tunables live here — no magic numbers scattered across modules.
"""

import os

# ── Elasticsearch ──────────────────────────────────────────────────────────
ES_HOST          = os.getenv("ES_HOST",    "http://localhost:9200")
ES_TIMEOUT       = int(os.getenv("ES_TIMEOUT", "10"))
ES_MAX_RETRIES   = int(os.getenv("ES_MAX_RETRIES", "3"))
ES_RETRY_DELAY   = float(os.getenv("ES_RETRY_DELAY", "1.0"))

# ── Log indices written by Layer-1 ────────────────────────────────────────
INDICES = {
    "web":      "logs-web",
    "auth":     "logs-auth",
    "network":  "logs-network",
    "endpoint": "logs-endpoint",
    "all":      "logs-*",
}

# ── Polling ────────────────────────────────────────────────────────────────
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL", "30"))
POLL_LOOKBACK_MINUTES = int(os.getenv("POLL_LOOKBACK", "2"))

# ── Incident merger ────────────────────────────────────────────────────────
MERGE_WINDOW_SECONDS  = 300   # 5 minutes
MERGE_KEYS            = ("source_ip", "affected_user")

# ── Risk engine ────────────────────────────────────────────────────────────
RISK_WEIGHT_RULE        = 0.40
RISK_WEIGHT_ANOMALY     = 0.30
RISK_WEIGHT_IOC         = 0.20
RISK_WEIGHT_CORRELATION = 0.10

# ── Severity thresholds ────────────────────────────────────────────────────
SEVERITY_CRITICAL = 0.85
SEVERITY_HIGH     = 0.65
SEVERITY_MEDIUM   = 0.40

# ── Baseline ──────────────────────────────────────────────────────────────
BASELINE_LOOKBACK_DAYS = 30
BASELINE_MIN_SAMPLES   = 10

# ── Layer-3 dispatch ──────────────────────────────────────────────────────
LAYER3_ENDPOINT = os.getenv("LAYER3_ENDPOINT", "http://localhost:8001/analyze")
LAYER3_TIMEOUT  = int(os.getenv("LAYER3_TIMEOUT", "10"))

# ── Logging ───────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
