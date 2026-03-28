"""
timeline_builder.py
-------------------
Reconstructs a human-readable attack timeline from the raw_event fields
and the linked_events produced by event_linker.

Each timeline entry has:
  - timestamp : ISO8601 string
  - event      : short event type label
  - detail     : one-line human-readable description
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# Maps event field names to a readable label
_FIELD_LABEL_MAP = {
    "failed_attempts":    "failed_logins",
    "failed_logins":      "failed_logins",
    "bytes_out":          "data_transfer",
    "outbound_bytes":     "data_transfer",
    "process":            "process_execution",
    "command_line":       "command_execution",
    "action":             "firewall_action",
    "port":               "port_activity",
    "device_id":          "device_activity",
}


def _safe_ts(ts_str: str) -> str:
    """Normalise a timestamp string to ISO8601 or return as-is."""
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:
        return str(ts_str)


def build(raw_event: dict, linked_events: list[dict]) -> list[dict]:
    """
    Build a chronological attack timeline.

    Strategy:
      1. Pull explicitly timestamped sub-events if raw_event contains them.
      2. Synthesise timeline entries from raw_event fields.
      3. Append a summary entry for each linked_event type.

    Returns:
        list of dicts: [{"timestamp": str, "event": str, "detail": str}, ...]
    """
    timeline = []
    base_ts  = _safe_ts(raw_event.get("timestamp") or raw_event.get("event_time", ""))

    # ---- 1. Pull pre-existing sub-events if present ----
    sub_events = raw_event.get("events") or raw_event.get("timeline") or []
    for sub in sub_events:
        timeline.append({
            "timestamp": _safe_ts(sub.get("timestamp", base_ts)),
            "event":     sub.get("event_type") or sub.get("type", "event"),
            "detail":    sub.get("detail") or sub.get("description", ""),
        })

    # ---- 2. Synthesise entries from notable raw_event fields ----
    # Firewall action
    action = raw_event.get("action", "")
    src_ip = raw_event.get("source_ip") or raw_event.get("src_ip", "")
    dst_ip = raw_event.get("destination_ip") or raw_event.get("dst_ip", "")
    port   = raw_event.get("port") or raw_event.get("destination_port", "")

    if action and src_ip:
        detail = f"{action.upper()} from {src_ip}"
        if dst_ip: detail += f" → {dst_ip}"
        if port:   detail += f" on port {port}"
        timeline.append({"timestamp": base_ts, "event": "firewall_action", "detail": detail})

    # Failed logins
    failures = raw_event.get("failed_attempts") or raw_event.get("failed_logins", 0)
    if int(failures or 0) > 0:
        user = raw_event.get("affected_user") or raw_event.get("username", "unknown_user")
        timeline.append({
            "timestamp": base_ts,
            "event":     "failed_login",
            "detail":    f"{failures} failed login attempts for user '{user}'",
        })

    # Process execution
    process = raw_event.get("process", "")
    parent  = raw_event.get("parent_process", "")
    if process:
        detail = f"Process '{process}' executed"
        if parent: detail += f" (spawned by '{parent}')"
        timeline.append({"timestamp": base_ts, "event": "process_execution", "detail": detail})

    # Data transfer
    bytes_out = raw_event.get("bytes_out") or raw_event.get("outbound_bytes", 0)
    if int(bytes_out or 0) > 0:
        mb = int(bytes_out) / (1024 * 1024)
        timeline.append({
            "timestamp": base_ts,
            "event":     "data_transfer",
            "detail":    f"{mb:.1f} MB transferred outbound from {src_ip or 'unknown'}",
        })

    # IoT device activity
    device_id = raw_event.get("device_id", "")
    device_type = raw_event.get("device_type", "")
    if device_id and device_type:
        timeline.append({
            "timestamp": base_ts,
            "event":     "iot_device_activity",
            "detail":    f"IoT device '{device_id}' ({device_type}) generated alert",
        })

    # ---- 3. Append linked event summaries ----
    for linked in linked_events:
        ev_type = linked.get("type", "event")
        detail  = ""

        if ev_type == "anomaly_detected":
            score = linked.get("score", 0)
            detail = f"Anomaly detected — score {score:.2f}, fidelity {linked.get('fidelity', 0):.2f}"

        elif ev_type == "behavioral_anomaly":
            flags = linked.get("flags", [])
            detail = f"Behavioural flags raised: {', '.join(flags)}"

        elif ev_type == "threat_intel_hit":
            matches = linked.get("matches", [])
            tactic  = linked.get("tactic", "")
            detail  = f"IOC match: {', '.join(matches)} — MITRE: {tactic}"

        elif ev_type == "cis_benchmark_violation":
            viols = linked.get("violations", [])
            rules = [v.get("benchmark_id","?") for v in viols]
            detail = f"CIS benchmark violations: {', '.join(rules)}"

        elif ev_type == "iot_threshold_violation":
            hits = linked.get("hits", [])
            detail = f"IoT threshold exceeded: {', '.join(h.get('metric','?') for h in hits)}"

        if detail:
            timeline.append({"timestamp": base_ts, "event": ev_type, "detail": detail})

    # De-duplicate and sort by timestamp
    seen = set()
    unique_timeline = []
    for entry in timeline:
        key = f"{entry['timestamp']}|{entry['event']}|{entry['detail'][:40]}"
        if key not in seen:
            seen.add(key)
            unique_timeline.append(entry)

    unique_timeline.sort(key=lambda e: e["timestamp"])
    return unique_timeline