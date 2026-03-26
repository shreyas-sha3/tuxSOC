# feature_orchestrator.py
# Location: layer_1_feature_engineering/feature_orchestrator.py
#
# PURPOSE:
# The main coordinator of Layer 1.
# Receives the normalized log dict from the ingestion layer,
# runs it through all engines in the correct sequence,
# and returns the fully feature-enriched dict to the detection layer.
#
# FLOW:
# 1. classify_log()         → stamps log_family
# 2. temporal_orchestrator  → adds temporal_features
# 3. behavioral_orchestrator → adds behavioral_features
# 4. statistical_orchestrator → adds statistical_features
# 5. family-specific engine  → adds network/web/iot features
#
# ERROR HANDLING:
# Pass-through pattern — if any engine fails, the log passes through
# unchanged with an error note. Pipeline never breaks.
#
# CALLED BY:
# main.py or the ingestion layer output handler


from log_classifier import classify_log

from engine_1_temporal.temporal_orchestrator import run_temporal
from engine_2_behavioral.behavioral_orchestrator import run_behavioral
from engine_3_statistical.statistical_orchestrator import run_statistical
from engine_4_network.network_orchestrator import run_network
from engine_5_web.web_orchestrator import run_web
from engine_6_iot.iot_orchestrator import run_iot


# ─────────────────────────────────────────
# HELPER — safe engine runner
# Wraps each engine call in try/except
# If engine fails, log passes through with error note
# ─────────────────────────────────────────

def _safe_run(engine_fn, log: dict, engine_name: str) -> dict:
    """
    Calls the engine function safely.
    On failure, returns the log unchanged with an error entry added.
    """
    try:
        return engine_fn(log)
    except Exception as e:
        # Do not break the pipeline
        # Stamp what went wrong and pass through
        errors = log.get("feature_errors", [])
        errors.append({
            "engine": engine_name,
            "error": str(e)
        })
        return {**log, "feature_errors": errors}


# ─────────────────────────────────────────
# MAIN ORCHESTRATOR FUNCTION
# Called once per log dict
# ─────────────────────────────────────────

def run_feature_engineering(log: dict) -> dict:
    """
    Receives a normalized log dict from ingestion.
    Returns the same dict enriched with all feature blocks.

    Always added:
        log_family
        classification_scores
        classification_confidence
        temporal_features
        behavioral_features
        statistical_features

    Conditionally added (based on log_family):
        network_features   ← if log_family == "network"
        web_features       ← if log_family == "web"
        iot_features       ← if log_family == "iot"
    """

    # ── Step 1: Classify ──────────────────
    log = _safe_run(classify_log, log, "log_classifier")

    # ── Step 2: Temporal (runs for ALL logs) ──
    log = _safe_run(run_temporal, log, "engine_1_temporal")

    # ── Step 3: Behavioral (runs for ALL logs) ──
    log = _safe_run(run_behavioral, log, "engine_2_behavioral")

    # ── Step 4: Statistical (runs for ALL logs) ──
    log = _safe_run(run_statistical, log, "engine_3_statistical")

    # ── Step 5: Family-specific engine ────
    family = log.get("log_family", "unknown")

    if family == "network":
        log = _safe_run(run_network, log, "engine_4_network")

    elif family == "web":
        log = _safe_run(run_web, log, "engine_5_web")

    elif family == "iot":
        log = _safe_run(run_iot, log, "engine_6_iot")

    else:
        # Unknown family — no family-specific engine runs
        # Log it so the analyst knows
        warnings = log.get("feature_warnings", [])
        warnings.append("log_family is unknown — family-specific features skipped")
        log = {**log, "feature_warnings": warnings}

    return log