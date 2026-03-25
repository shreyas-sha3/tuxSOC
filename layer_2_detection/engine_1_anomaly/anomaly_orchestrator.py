"""
anomaly_orchestrator.py
-----------------------
Engine 1 orchestrator. Coordinates pyod_detector and ueba_scorer,
combines their outputs into the engine_1_anomaly block.
"""

import logging
import pyod_detector
import ueba_scorer

logger = logging.getLogger(__name__)


def run(feature_vector: list[float],
        raw_event: dict,
        log_type: str = "endpoint") -> dict:
    """
    Run Engine 1: PyOD anomaly detection + UEBA behavioural scoring.

    Args:
        feature_vector : numerical feature vector
        raw_event      : normalized log event
        log_type       : endpoint | network | iot | auth | firewall

    Returns engine_1_anomaly block:
        {
          "pyod_score": float,
          "is_outlier": bool,
          "fidelity_score": float,
          "model_votes": dict,

          "ueba_flags": list[str],
          "ueba_risk_boost": float,
          "flag_details": dict,

          "anomaly_score": float,
          "anomaly_flagged": bool
        }
    """

    logger.debug("Engine 1 starting for log_type=%s", log_type)

    # STEP 1 — PyOD anomaly scoring
    pyod_result = pyod_detector.score_event(feature_vector)

    # STEP 2 — UEBA behavioural analysis
    ueba_result = ueba_scorer.evaluate(raw_event)

    pyod_score = pyod_result.get("pyod_score", 0.0)
    ueba_boost = ueba_result.get("ueba_risk_boost", 0.0)

    # STEP 3 — Final anomaly score
    anomaly_score = round(min(pyod_score + ueba_boost, 1.0), 4)

    ANOMALY_THRESHOLD = 0.65

    anomaly_flagged = (
        anomaly_score >= ANOMALY_THRESHOLD
        or pyod_result.get("is_outlier", False)
    )

    result = {
        **pyod_result,
        **ueba_result,
        "anomaly_score": anomaly_score,
        "anomaly_flagged": anomaly_flagged
    }

    logger.debug(
        "Engine 1 complete — anomaly_score=%.3f flagged=%s flags=%s",
        anomaly_score,
        anomaly_flagged,
        result.get("ueba_flags", [])
    )

    return result