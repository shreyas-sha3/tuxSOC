"""
es_correlator.py
----------------
Time-machine correlation engine.

For each detection, queries Elasticsearch for all related events
across log indices within a configurable time window, then builds
a sorted attack timeline.
"""

import logging
from datetime import datetime, timezone, timedelta

from layer_2_detection_es.elastic_client import search_all_logs
from layer_2_detection_es.config import INDICES

logger = logging.getLogger(__name__)


def _ts_key(event: dict) -> str:
    return event.get("timestamp") or "9999"


def correlate_detection(detection: dict, window_minutes: int = 5) -> dict:
    """
    Given a detection, fetch all related events from Elasticsearch
    within the correlation window and build an attack timeline.

    Correlation keys (any match triggers inclusion):
      - source_ip
      - affected_user
      - affected_host
      - destination_ip

    Returns:
        {
          "related_events":  list[dict],
          "attack_timeline": list[dict],
          "event_count":     int,
          "correlation_depth": int,   # number of distinct log types seen
        }
    """
    ts_str = detection.get("timestamp") or datetime.now(timezone.utc).isoformat()
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    window_start = (ts - timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    window_end   = (ts + timedelta(minutes=window_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build OR conditions for entity matching
    should_clauses = []
    for field in ("source_ip", "affected_user", "affected_host", "destination_ip"):
        val = detection.get(field)
        if val:
            kw_field = f"{field}.keyword" if field in ("affected_user", "affected_host") else field
            should_clauses.append({"term": {kw_field: val}})

    if not should_clauses:
        return {"related_events": [], "attack_timeline": [], "event_count": 0, "correlation_depth": 0}

    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": window_start, "lte": window_end}}}],
            "should": should_clauses,
            "minimum_should_match": 1,
        }},
        "sort": [{"timestamp": {"order": "asc"}}],
    }

    events = search_all_logs(query, size=200)

    # Deduplicate by timestamp + action + source_ip
    seen: set = set()
    unique_events: list[dict] = []
    for ev in events:
        sig = f"{ev.get('timestamp')}|{ev.get('action')}|{ev.get('source_ip')}"
        if sig not in seen:
            seen.add(sig)
            unique_events.append(ev)

    # Sort chronologically
    unique_events.sort(key=_ts_key)

    # Build human-readable timeline
    timeline = _build_timeline(unique_events)

    # Correlation depth = number of distinct log_type values seen
    log_types = {ev.get("log_type", "unknown") for ev in unique_events}
    correlation_depth = len(log_types)

    logger.info(
        "Correlated %d events for detection %s (depth=%d)",
        len(unique_events), detection.get("rule_id"), correlation_depth
    )

    return {
        "related_events":    unique_events,
        "attack_timeline":   timeline,
        "event_count":       len(unique_events),
        "correlation_depth": correlation_depth,
    }


def correlate_all(detections: list[dict], window_minutes: int = 5) -> list[dict]:
    """
    Correlate all detections and attach timeline/related_events to each.
    Returns enriched detection list.
    """
    enriched = []
    for det in detections:
        try:
            corr = correlate_detection(det, window_minutes)
            enriched.append({**det, **corr})
        except Exception as exc:
            logger.error("Correlation failed for %s: %s", det.get("rule_id"), exc)
            enriched.append(det)
    return enriched


def _build_timeline(events: list[dict]) -> list[dict]:
    """Convert raw events into structured timeline entries representing attack progression."""
    timeline = []
    for ev in events:
        action = ev.get("action", "")
        entry = {
            "timestamp":      ev.get("timestamp", ""),
            "log_type":       ev.get("log_type", "unknown"),
            "action":         action,
            "source_ip":      ev.get("source_ip", ""),
            "destination_ip": ev.get("destination_ip", ""),
            "affected_user":  ev.get("affected_user", ""),
            "affected_host":  ev.get("affected_host", ""),
        }
        # Add notable fields
        for field in ("url", "command_line", "process_name", "bytes_out", "port", "protocol",
                      "dns_query", "file_path", "registry_key"):
            val = ev.get(field)
            if val is not None:
                entry[field] = val

        # Classify attack stage for progression tracking
        action_lower = action.lower()
        if "fail" in action_lower or "denied" in action_lower:
            entry["attack_stage"] = "credential_attack"
        elif "success" in action_lower and ("login" in action_lower or "auth" in action_lower):
            entry["attack_stage"] = "initial_access"
        elif ev.get("command_line") or ev.get("process_name"):
            entry["attack_stage"] = "execution"
        elif int(ev.get("bytes_out") or 0) > 1_000_000:
            entry["attack_stage"] = "exfiltration"
        elif int(ev.get("port") or 0) in (445, 139, 3389):
            entry["attack_stage"] = "lateral_movement"
        else:
            entry["attack_stage"] = "reconnaissance"

        timeline.append(entry)
    return timeline
