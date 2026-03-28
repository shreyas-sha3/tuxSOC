# correlation_orchestrator.py
# Location: layer_2_detection/engine_3_correlation/correlation_orchestrator.py
# ─────────────────────────────────────────────────────────────────
# Orchestrates the full correlation + timeline pipeline for a
# single detection alert, producing the engine_3_correlation block.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from elasticsearch import Elasticsearch

from layer_2_detection.engine_3_correlation.event_linker import correlate_events
from layer_2_detection.engine_3_correlation.timeline_builder import build_attack_timeline


def build_correlation_block(
    es: Elasticsearch,
    pivot_ip: str | None = None,
    pivot_user: str | None = None,
    pivot_host: str | None = None,
    pivot_dest_ip: str | None = None,
) -> dict:
    """
    Full Engine 3 pipeline:
      1. Run Time-Machine correlation query across all pivot axes
      2. Build attack timeline
      3. Return raw correlated evidence for the LLM

    Returns the `engine_3_correlation` dict:
      {
        "event_count": int,
        "attack_timeline": [...],
        "correlated_evidence": [...]   ← raw ES docs for the LLM
      }
    """
    correlated = correlate_events(
        es,
        pivot_ip=pivot_ip,
        pivot_user=pivot_user,
        pivot_host=pivot_host,
        pivot_dest_ip=pivot_dest_ip,
    )
    timeline = build_attack_timeline(correlated)

    return {
        "event_count":         len(correlated),
        "attack_timeline":     timeline,
        "correlated_evidence": correlated,
    }
