"""
risk_engine.py
--------------
Calculates composite SOC risk score and severity for an incident cluster.

Formula:
  risk = (0.35 * rule_weight)
       + (0.25 * anomaly_score)
       + (0.20 * ioc_presence)
       + (0.10 * correlation_depth_norm)
       + (0.10 * chain_strength)

Severity thresholds:
  critical  >= 0.85
  high      >= 0.65
  medium    >= 0.40
  low       <  0.40
"""

import logging
from layer_2_detection_es.config import (
    RISK_WEIGHT_RULE, RISK_WEIGHT_ANOMALY,
    RISK_WEIGHT_IOC, RISK_WEIGHT_CORRELATION,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
)

logger = logging.getLogger(__name__)

_MAX_CORRELATION_DEPTH = 4  # normalisation ceiling (4 log types)

# Attack chain stage bonuses (mirrors layer_2_detection risk_scorer)
_CHAIN_STAGE_BONUSES: dict = {
    "brute_force":        0.10,
    "login_success":      0.15,
    "suspicious_command": 0.15,
    "process_execution":  0.10,
    "lateral_movement":   0.20,
    "data_transfer":      0.25,
    "network_connection": 0.05,
}

# Rule category severity multipliers
_CATEGORY_MULTIPLIERS: dict = {
    "endpoint": 1.10,
    "auth":     1.05,
    "network":  1.00,
    "web":      0.95,
}


def _chain_strength(cluster: dict) -> float:
    """
    Compute attack chain strength from detection categories and rule IDs.

    Multi-category incidents (auth + endpoint + network) indicate
    a more complete attack chain and receive a higher bonus.
    """
    categories = set(cluster.get("categories", []))
    rule_ids   = cluster.get("rule_ids", [])

    bonus = 0.0

    # Multi-category chain bonus
    if len(categories) >= 3:
        bonus += 0.15
    elif len(categories) == 2:
        bonus += 0.08

    # Specific high-value chain patterns
    has_auth     = "auth" in categories
    has_endpoint = "endpoint" in categories
    has_network  = "network" in categories

    # Brute force → endpoint = credential compromise chain
    if has_auth and has_endpoint:
        bonus += 0.10

    # Endpoint + network = malware staging + C2
    if has_endpoint and has_network:
        bonus += 0.08

    # Full kill chain (auth + endpoint + network)
    if has_auth and has_endpoint and has_network:
        bonus += 0.12

    # Exfiltration detected
    if any("EXFIL" in r or "LATERAL" in r for r in rule_ids):
        bonus += 0.10

    return round(min(bonus, 0.40), 3)


def _entity_graph_depth(cluster: dict) -> float:
    """
    Normalised entity diversity score.
    More entity types = deeper graph correlation = higher confidence.
    """
    entities = cluster.get("entities", {})
    entity_types = 0
    if entities.get("source_ips"):
        entity_types += 1
    if entities.get("users"):
        entity_types += 1
    if entities.get("hosts"):
        entity_types += 1
    if entities.get("destination_ips"):
        entity_types += 1
    # Normalise to 0-1 (max 4 entity types)
    return round(entity_types / 4.0, 2)


def compute_risk(
    cluster: dict,
    ueba_result: dict,
    ioc_count: int = 0,
) -> dict:
    """
    Compute risk score for an incident cluster.

    Args:
        cluster:     merged incident cluster from incident_merger
        ueba_result: output from ueba_engine.run_ueba()
        ioc_count:   number of IOC matches from threat intel

    Returns:
        {
          "risk_score":   float,
          "severity":     str,
          "confidence":   float,
          "components":   dict,
        }
    """
    # ── Rule weight component ──────────────────────────────────────────
    rule_weight = cluster.get("max_risk_weight", 0.0)

    # Boost for multiple detections in the cluster
    det_count  = len(cluster.get("detections", []))
    rule_weight = min(rule_weight + (det_count - 1) * 0.05, 1.0)

    # Apply category multiplier (highest-severity category wins)
    categories = cluster.get("categories", [])
    cat_mult   = max((_CATEGORY_MULTIPLIERS.get(c, 1.0) for c in categories), default=1.0)
    rule_weight = min(rule_weight * cat_mult, 1.0)

    # ── Anomaly component ──────────────────────────────────────────────
    anomaly_score = float(ueba_result.get("anomaly_score", 0.0))

    # ── IOC presence component ─────────────────────────────────────────
    ioc_presence = min(ioc_count * 0.25, 1.0)

    # ── Correlation depth component ────────────────────────────────────
    depths    = [d.get("correlation_depth", 0) for d in cluster.get("detections", [])]
    avg_depth = sum(depths) / max(len(depths), 1)
    depth_norm = min(avg_depth / _MAX_CORRELATION_DEPTH, 1.0)

    # ── Attack chain strength ──────────────────────────────────────────
    chain_score = _chain_strength(cluster)

    # ── Entity graph depth ─────────────────────────────────────────────
    graph_depth = _entity_graph_depth(cluster)

    # ── Composite score ────────────────────────────────────────────────
    # Weights: rule=0.35, anomaly=0.25, ioc=0.20, correlation=0.10, chain=0.10
    risk = (
        0.35 * rule_weight    +
        0.25 * anomaly_score  +
        0.20 * ioc_presence   +
        0.10 * depth_norm     +
        0.10 * chain_score
    )
    # Entity graph depth adds a small bonus (up to +0.05)
    risk += graph_depth * 0.05
    risk  = round(min(risk, 1.0), 3)

    # ── Severity ───────────────────────────────────────────────────────
    if risk >= SEVERITY_CRITICAL:
        severity = "critical"
    elif risk >= SEVERITY_HIGH:
        severity = "high"
    elif risk >= SEVERITY_MEDIUM:
        severity = "medium"
    else:
        severity = "low"

    # ── Confidence ─────────────────────────────────────────────────────
    dets = cluster.get("detections", [])
    if dets:
        conf_sum   = sum(d.get("confidence", 0.5) * d.get("risk_weight", 0.5) for d in dets)
        weight_sum = sum(d.get("risk_weight", 0.5) for d in dets)
        confidence = round(conf_sum / max(weight_sum, 0.001), 3)
    else:
        confidence = 0.0

    components = {
        "rule_weight_component":   round(0.35 * rule_weight, 3),
        "anomaly_component":       round(0.25 * anomaly_score, 3),
        "ioc_component":           round(0.20 * ioc_presence, 3),
        "correlation_component":   round(0.10 * depth_norm, 3),
        "chain_component":         round(0.10 * chain_score, 3),
        "graph_component":         round(graph_depth * 0.05, 3),
    }

    logger.debug(
        "Risk computed: score=%.3f severity=%s confidence=%.3f chain=%.3f",
        risk, severity, confidence, chain_score
    )

    return {
        "risk_score":  risk,
        "severity":    severity,
        "confidence":  confidence,
        "components":  components,
    }
