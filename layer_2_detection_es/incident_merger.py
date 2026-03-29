"""
incident_merger.py
------------------
Merges related detections into unified incidents.

Merge criteria:
  - Same source_ip OR same affected_user
  - Within MERGE_WINDOW_SECONDS of each other

Uses a greedy single-pass clustering algorithm:
  1. Sort detections by timestamp
  2. For each detection, check if it belongs to an existing open cluster
  3. If yes, merge; if no, open a new cluster
  4. Emit one incident per cluster
"""

import logging
from datetime import datetime, timezone

from layer_2_detection_es.config import MERGE_WINDOW_SECONDS

logger = logging.getLogger(__name__)


def _parse_ts(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def _entity_key(det: dict) -> set:
    """Return the set of entity identifiers for a detection."""
    keys = set()
    if det.get("source_ip"):
        keys.add(f"ip:{det['source_ip']}")
    if det.get("affected_user"):
        keys.add(f"user:{det['affected_user']}")
    return keys


def merge_detections(detections: list[dict]) -> list[dict]:
    """
    Merge a flat list of detections into incident clusters.

    Returns a list of cluster dicts:
        {
          "detections":    list[dict],
          "entities":      dict,
          "first_seen":    str,
          "last_seen":     str,
          "rule_ids":      list[str],
          "categories":    list[str],
          "max_severity":  str,
          "max_risk_weight": float,
        }
    """
    if not detections:
        return []

    # Sort by timestamp ascending
    sorted_dets = sorted(detections, key=lambda d: d.get("timestamp", ""))

    clusters: list[dict] = []

    for det in sorted_dets:
        det_ts    = _parse_ts(det.get("timestamp", ""))
        det_keys  = _entity_key(det)
        merged    = False

        for cluster in clusters:
            # Check time proximity
            cluster_last = _parse_ts(cluster["last_seen"])
            delta = abs((det_ts - cluster_last).total_seconds())
            if delta > MERGE_WINDOW_SECONDS:
                continue
            # Check entity overlap
            if det_keys & cluster["_entity_keys"]:
                # Merge into this cluster
                cluster["detections"].append(det)
                cluster["_entity_keys"] |= det_keys
                cluster["last_seen"] = max(cluster["last_seen"], det.get("timestamp", ""))
                cluster["rule_ids"].append(det["rule_id"])
                if det["category"] not in cluster["categories"]:
                    cluster["categories"].append(det["category"])
                cluster["max_risk_weight"] = max(
                    cluster["max_risk_weight"], det.get("risk_weight", 0.0)
                )
                cluster["max_severity"] = _higher_severity(
                    cluster["max_severity"], det.get("severity", "low")
                )
                merged = True
                break

        if not merged:
            clusters.append({
                "detections":      [det],
                "_entity_keys":    det_keys,
                "first_seen":      det.get("timestamp", ""),
                "last_seen":       det.get("timestamp", ""),
                "rule_ids":        [det["rule_id"]],
                "categories":      [det["category"]],
                "max_severity":    det.get("severity", "low"),
                "max_risk_weight": det.get("risk_weight", 0.0),
            })

    # Clean up internal key and build entity dicts
    result = []
    for cluster in clusters:
        cluster.pop("_entity_keys", None)
        cluster["entities"] = _extract_entities(cluster["detections"])
        result.append(cluster)

    logger.info(
        "Merged %d detections into %d incident cluster(s)",
        len(detections), len(result)
    )
    return result


def _extract_entities(detections: list[dict]) -> dict:
    """Collect unique entity values across all detections in a cluster."""
    src_ips, users, hosts, dst_ips = set(), set(), set(), set()
    for det in detections:
        if det.get("source_ip"):      src_ips.add(det["source_ip"])
        if det.get("affected_user"):  users.add(det["affected_user"])
        if det.get("affected_host"):  hosts.add(det["affected_host"])
        if det.get("destination_ip"): dst_ips.add(det["destination_ip"])
    return {
        "source_ips":    sorted(src_ips),
        "users":         sorted(users),
        "hosts":         sorted(hosts),
        "destination_ips": sorted(dst_ips),
    }


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _higher_severity(a: str, b: str) -> str:
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b
