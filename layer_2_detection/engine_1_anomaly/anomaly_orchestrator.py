# anomaly_orchestrator.py
# Location: layer_2_detection/engine_1_anomaly/anomaly_orchestrator.py
# ─────────────────────────────────────────────────────────────────
# Orchestrates UEBA scoring + PyOD anomaly scoring into a single
# engine_1_anomaly result block.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from typing import Optional
from elasticsearch import Elasticsearch

from layer_2_detection.engine_1_anomaly.pyod_detector import compute_anomaly_score
from layer_2_detection.engine_1_anomaly.ueba_scorer import run_ueba


def build_anomaly_block(
    rule_id: str,
    es: Optional[Elasticsearch] = None,
    user: Optional[str] = None,
    current_country: Optional[str] = None,
    current_hour: Optional[int] = None,
    extra_ueba_flags: Optional[list[str]] = None,
    auth_index: str = "logs-auth",
) -> dict:
    """
    Full Engine 1 pipeline:
      1. Run UEBA against ES (impossible-travel + temporal)
      2. Merge with any rule-level flags (e.g. "dns_tunneling_pattern")
      3. Compute PyOD-compatible anomaly score

    Returns the complete `engine_1_anomaly` dict.
    """
    ueba_flags: list[str] = []

    # Run live UEBA if we have an ES connection & a user identity
    if es is not None and user:
        ueba_flags = run_ueba(
            es, user,
            current_country=current_country,
            current_hour=current_hour,
            auth_index=auth_index,
        )

    # Merge rule-level flags
    if extra_ueba_flags:
        for f in extra_ueba_flags:
            if f not in ueba_flags:
                ueba_flags.append(f)

    return compute_anomaly_score(rule_id, ueba_flags)
