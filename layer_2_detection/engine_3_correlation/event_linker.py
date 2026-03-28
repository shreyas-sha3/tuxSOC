"""
event_linker.py
---------------
Links Engine 1 (anomaly) and Engine 2 (threat intel) findings
into a unified list of linked_events for the correlation block.

Each linked_event has a type and the relevant evidence payload.
"""

import logging

logger = logging.getLogger(__name__)


def link(engine_1: dict, engine_2: dict, raw_event: dict) -> list[dict]:
    """
    Combine Engine 1 and Engine 2 outputs into a linked_events list.

    Returns:
        list of linked event dicts, each with a 'type' and evidence fields.
    """
    linked = []

    # ---- Anomaly detection hit ----
    if engine_1.get("anomaly_flagged"):
        linked.append({
            "type":          "anomaly_detected",
            "score":         engine_1.get("anomaly_score"),
            "fidelity":      engine_1.get("fidelity_score"),
            "model_votes":   engine_1.get("model_votes", {}),
        })

    # ---- Behavioural flags hit ----
    ueba_flags = engine_1.get("ueba_flags", [])
    if ueba_flags:
        linked.append({
            "type":         "behavioral_anomaly",
            "flags":        ueba_flags,
            "risk_boost":   engine_1.get("ueba_risk_boost", 0.0),
            "flag_details": engine_1.get("flag_details", {}),
        })

    # ---- Threat intel match ----
    if engine_2 and engine_2.get("threat_intel_match"):
        linked.append({
            "type":    "threat_intel_hit",
            "matches": engine_2.get("ioc_matches", []),
            "tactic":  engine_2.get("mitre_tactic"),
            "technique": engine_2.get("mitre_technique"),
        })

    # ---- CIS benchmark violation ----
    cis_violations = engine_2.get("cis_violations", []) if engine_2 else []
    if cis_violations:
        linked.append({
            "type":       "cis_benchmark_violation",
            "violations": [
                {
                    "benchmark_id": v.get("benchmark_id"),
                    "title":        v.get("title"),
                    "section":      v.get("section"),
                    "profile_level":v.get("profile_level"),
                    "match_reason": v.get("match_reason"),
                }
                for v in cis_violations[:5]   # top 5 to avoid bloat
            ],
        })

    # ---- IoT threshold violation ----
    iot_hits = engine_2.get("iot_threshold_hits", []) if engine_2 else []
    if iot_hits:
        linked.append({
            "type": "iot_threshold_violation",
            "hits": [
                {
                    "device_type":    h.get("device_type"),
                    "metric":         h.get("metric"),
                    "observed_value": h.get("observed_value"),
                    "threshold_max":  h.get("threshold_max"),
                    "severity":       h.get("severity"),
                }
                for h in iot_hits
            ],
        })

    return linked