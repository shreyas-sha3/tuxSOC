"""
detection_orchestrator.py
--------------------------
Main Layer 2 orchestrator. Receives the output of layer_1 feature engineering
and routes it through the three detection engines in conditional-sequential order:

  Always:      Engine 1 (Anomaly Detection + UEBA)
  Conditional: Engine 2 (Threat Intel + IOC matching) — only if anomaly_score >= threshold
  Always:      Engine 3 (Correlation + Timeline) — uses both E1 + E2 results

Final output: a DetectionResult dict matching the agreed schema for layer_3_ai_analysis.

Usage (from main.py or layer pipeline):
    from layer_2_detection.detection_orchestrator import run
    result = run(layer1_output)
"""

import logging
import uuid
from datetime import datetime, timezone
import sys
import os

# Engine paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine_1_anomaly"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine_2_threat_intel"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine_3_correlation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ioc_database"))

import anomaly_orchestrator
import intel_orchestrator
import correlation_orchestrator
from ioc_db import DEFAULT_DB_PATH, init_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config — these can be overridden via config.py
# ---------------------------------------------------------------------------

# Minimum anomaly_score to trigger Engine 2 (threat intel lookup)
ANOMALY_THRESHOLD_FOR_E2 = float(os.environ.get("ANOMALY_THRESHOLD_E2", "0.55"))

# IOC DB path
IOC_DB_PATH = os.environ.get("IOC_DB_PATH", DEFAULT_DB_PATH)

# Initialise DB on first import (safe — uses CREATE IF NOT EXISTS)
try:
    init_db(IOC_DB_PATH)
except Exception as e:
    logger.warning("IOC DB init warning: %s", e)


# ---------------------------------------------------------------------------
# Incident ID generator
# ---------------------------------------------------------------------------

def _make_incident_id() -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m%d")
    short = str(uuid.uuid4()).split("-")[0].upper()
    return f"INC-{today}-{short}"


# ---------------------------------------------------------------------------
# Main run function
# ---------------------------------------------------------------------------

def run(layer1_output: dict,
        db_path: str = IOC_DB_PATH) -> dict:
    """
    Execute the full Layer 2 detection pipeline.

    Args:
        layer1_output: Output from layer_1 feature engineering, expected shape:
            {
              "raw_event":        dict,   # original normalized log fields
              "log_type":         str,    # 'endpoint' | 'network' | 'iot' | 'auth' | 'firewall'
              "feature_vector":   list[float],  # numerical features for PyOD
              "fidelity_score":   float,  # from layer_1 (used for logging/context)
              "timestamp":        str,    # ISO8601
              "incident_id":      str,    # optional, generated here if absent
            }
        db_path: Path to the IOC SQLite database.

    Returns:
        DetectionResult dict (full schema matching layer_3 input contract).
    """
    raw_event      = layer1_output.get("raw_event", {})
    log_type       = layer1_output.get("log_type", "endpoint")
    feature_vector = layer1_output.get("feature_vector", [])
    timestamp      = layer1_output.get("timestamp") or datetime.now(timezone.utc).isoformat()
    incident_id    = layer1_output.get("incident_id") or _make_incident_id()

    logger.info("Detection pipeline START — incident=%s log_type=%s", incident_id, log_type)

    # ------------------------------------------------------------------
    # STAGE 1: Engine 1 — Anomaly Detection (always runs)
    # ------------------------------------------------------------------
    engine_1 = anomaly_orchestrator.run(
        feature_vector=feature_vector,
        raw_event=raw_event,
        log_type=log_type,
    )
    anomaly_score = engine_1.get("anomaly_score", 0.0)
    ueba_flags    = engine_1.get("ueba_flags", [])

    logger.info(
        "Engine 1 done — anomaly_score=%.3f flagged=%s",
        anomaly_score, engine_1.get("anomaly_flagged")
    )

    # ------------------------------------------------------------------
    # STAGE 2: Engine 2 — Threat Intel (conditional on anomaly_score)
    # ------------------------------------------------------------------
    engine_2 = {}
    e2_skipped = False

    if anomaly_score >= ANOMALY_THRESHOLD_FOR_E2:
        logger.info(
            "Anomaly score %.3f >= threshold %.3f — running Engine 2",
            anomaly_score, ANOMALY_THRESHOLD_FOR_E2
        )
        engine_2 = intel_orchestrator.run(
            raw_event=raw_event,
            log_type=log_type,
            anomaly_score=anomaly_score,
            ueba_flags=ueba_flags,
            db_path=db_path,
        )
        logger.info(
            "Engine 2 done — threat_intel_match=%s tactic=%s",
            engine_2.get("threat_intel_match"), engine_2.get("mitre_tactic")
        )
    else:
        e2_skipped = True
        logger.info(
            "Anomaly score %.3f < threshold %.3f — Engine 2 skipped",
            anomaly_score, ANOMALY_THRESHOLD_FOR_E2
        )
        # Fill in empty Engine 2 structure so downstream schema is consistent
        engine_2 = {
            "ioc_matches":         [],
            "matched_ioc_details": [],
            "cis_violations":      [],
            "iot_threshold_hits":  [],
            "threat_intel_match":  False,
            "mitre_tactic":        "N/A",
            "mitre_technique":     "N/A",
            "mitre_technique_name":"N/A",
            "all_techniques":      [],
            "skipped":             True,
            "skip_reason":         f"anomaly_score {anomaly_score:.3f} < threshold {ANOMALY_THRESHOLD_FOR_E2}",
        }

    # ------------------------------------------------------------------
    # STAGE 3: Engine 3 — Correlation + Timeline (always runs)
    # ------------------------------------------------------------------
    engine_3 = correlation_orchestrator.run(
        engine_1=engine_1,
        engine_2=engine_2,
        raw_event=raw_event,
    )
    logger.info(
        "Engine 3 done — %d linked events, %d timeline entries",
        engine_3.get("event_count"), len(engine_3.get("attack_timeline", []))
    )

    # ------------------------------------------------------------------
    # Assemble final DetectionResult
    # ------------------------------------------------------------------
    result = {
        "incident_id":          incident_id,
        "timestamp":            timestamp,
        "log_type":             log_type,
        "raw_event":            raw_event,
        "layer1_fidelity":      layer1_output.get("fidelity_score"),
        "engine_1_anomaly":     engine_1,
        "engine_2_threat_intel":engine_2,
        "engine_3_correlation": engine_3,
        "detection_summary": {
            "anomaly_score":      anomaly_score,
            "threat_intel_match": engine_2.get("threat_intel_match", False),
            "mitre_tactic":       engine_2.get("mitre_tactic", "N/A"),
            "linked_event_count": engine_3.get("event_count", 0),
            "engine_2_ran":       not e2_skipped,
        },
        # ai_analysis block is intentionally empty — filled by layer_3
        "ai_analysis": None,
    }

    logger.info(
        "Detection pipeline COMPLETE — incident=%s score=%.3f tactic=%s",
        incident_id, anomaly_score, engine_2.get("mitre_tactic", "N/A")
    )
    return result