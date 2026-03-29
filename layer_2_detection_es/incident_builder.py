"""
incident_builder.py
-------------------
Builds structured SOC incident objects from merged clusters,
risk scores, MITRE mappings, and UEBA results.

Output schema matches the Layer-3 AI analysis contract:
{
  "incident_id":     str,
  "timestamp":       ISO8601,
  "severity":        low|medium|high|critical,
  "risk_score":      float,
  "confidence":      float,
  "incident_summary": str,
  "entities":        dict,
  "detections":      list[dict],
  "mitre_attack":    list[dict],
  "ueba_flags":      list[dict],
  "attack_timeline": list[dict],
  "event_count":     int,
  "rule_ids":        list[str],
  "categories":      list[str],
  "risk_components": dict,
}
"""

import uuid
import logging
from datetime import datetime, timezone

from layer_2_detection_es.mitre_mapper import map_detections_to_mitre

logger = logging.getLogger(__name__)

MAX_LINKED_EVENTS = 100


def _build_summary(cluster: dict, risk: dict) -> str:
    """Generate a concise machine-readable incident summary."""
    entities  = cluster.get("entities", {})
    src_ips   = entities.get("source_ips", [])
    users     = entities.get("users", [])
    hosts     = entities.get("hosts", [])
    cats      = cluster.get("categories", [])
    severity  = risk.get("severity", "low")
    det_count = len(cluster.get("detections", []))

    actor = src_ips[0] if src_ips else (users[0] if users else "unknown actor")
    target = hosts[0] if hosts else ""

    cat_str = " and ".join(cats) if cats else "multi-category"
    parts = [
        f"{severity.upper()} severity {cat_str} incident",
        f"from {actor}",
    ]
    if target:
        parts.append(f"targeting {target}")
    parts.append(f"({det_count} detection(s))")

    # Mention notable detection types
    rule_ids = cluster.get("rule_ids", [])
    notable = []
    if any("BRUTEFORCE" in r or "SPRAY" in r for r in rule_ids):
        notable.append("credential attack")
    if any("LATERAL" in r for r in rule_ids):
        notable.append("lateral movement")
    if any("EXFIL" in r for r in rule_ids):
        notable.append("data exfiltration")
    if any("RANSOMWARE" in r for r in rule_ids):
        notable.append("ransomware activity")
    if any("C2" in r or "BEACON" in r for r in rule_ids):
        notable.append("C2 beaconing")
    if notable:
        parts.append("— " + ", ".join(notable) + " detected")

    return " ".join(parts) + "."


def build_incident(
    cluster: dict,
    risk: dict,
    ueba_result: dict,
) -> dict:
    """
    Build a single incident object from a merged cluster.

    Args:
        cluster:     output from incident_merger.merge_detections()
        risk:        output from risk_engine.compute_risk()
        ueba_result: output from ueba_engine.run_ueba()
    """
    incident_id = "INC-" + uuid.uuid4().hex[:8].upper()
    now         = datetime.now(timezone.utc).isoformat()

    detections  = cluster.get("detections", [])
    mitre_attack = map_detections_to_mitre(detections)

    # Collect attack timeline from correlated events (capped)
    timeline: list[dict] = []
    seen_sigs: set = set()
    for det in detections:
        for ev in det.get("attack_timeline", []):
            sig = f"{ev.get('timestamp')}|{ev.get('action')}|{ev.get('source_ip')}"
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                timeline.append(ev)
    timeline.sort(key=lambda e: e.get("timestamp") or "9999")
    timeline = timeline[:MAX_LINKED_EVENTS]

    summary = _build_summary(cluster, risk)

    incident = {
        "incident_id":      incident_id,
        "timestamp":        now,
        "first_seen":       cluster.get("first_seen", now),
        "last_seen":        cluster.get("last_seen", now),
        "severity":         risk["severity"],
        "risk_score":       risk["risk_score"],
        "confidence":       risk["confidence"],
        "incident_summary": summary,
        "entities":         cluster.get("entities", {}),
        "detections":       detections,
        "mitre_attack":     mitre_attack,
        "mitre_techniques": [t["technique_id"] for t in mitre_attack],
        "mitre_tactics":    list({t["tactic"] for t in mitre_attack if t.get("tactic")}),
        "ueba_flags":       ueba_result.get("ueba_flags", []),
        "anomaly_score":    ueba_result.get("anomaly_score", 0.0),
        "attack_timeline":  timeline,
        "event_count":      len(timeline),
        "rule_ids":         cluster.get("rule_ids", []),
        "categories":       cluster.get("categories", []),
        "risk_components":  risk.get("components", {}),
    }

    logger.info(
        "INCIDENT BUILT: id=%s severity=%s risk=%.3f confidence=%.3f rules=%s",
        incident_id,
        risk["severity"],
        risk["risk_score"],
        risk["confidence"],
        cluster.get("rule_ids", []),
    )

    return incident


def build_all_incidents(
    clusters: list[dict],
    ueba_result: dict,
    ioc_count: int = 0,
) -> list[dict]:
    """Build incidents for all merged clusters."""
    from layer_2_detection_es.risk_engine import compute_risk

    incidents = []
    for cluster in clusters:
        try:
            risk     = compute_risk(cluster, ueba_result, ioc_count)
            incident = build_incident(cluster, risk, ueba_result)
            incidents.append(incident)
        except Exception as exc:
            logger.error("Failed to build incident for cluster: %s", exc)

    # Sort by risk_score descending
    incidents.sort(key=lambda i: i.get("risk_score", 0.0), reverse=True)
    return incidents
