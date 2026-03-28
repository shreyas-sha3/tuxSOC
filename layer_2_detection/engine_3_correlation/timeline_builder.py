# timeline_builder.py
# Location: layer_2_detection/engine_3_correlation/timeline_builder.py
# ─────────────────────────────────────────────────────────────────
# Takes the raw correlated events from event_linker and produces
# the attack_timeline array required by Layer 3's JSON schema.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations


def build_attack_timeline(correlated_events: list[dict]) -> list[dict]:
    """
    Converts raw ES docs into the attack_timeline format:
      [
        {"timestamp": "...", "event": "...", "detail": "..."},
        ...
      ]
    """
    timeline: list[dict] = []

    for evt in correlated_events:
        raw = evt.get("raw_event", evt)
        ts = (
            raw.get("timestamp")
            or evt.get("@timestamp")
            or evt.get("timestamp")
            or ""
        )
        action = raw.get("action") or evt.get("event", {}).get("action", "unknown_event")
        detail = _build_detail(evt)

        timeline.append({
            "timestamp": ts,
            "event":     _classify_event(evt),
            "detail":    detail,
        })

    return timeline


def _classify_event(evt: dict) -> str:
    """Derive a short event classification from the ES doc."""
    outcome = evt.get("event", {}).get("outcome", "")
    category = evt.get("event", {}).get("category", "")
    log_type = evt.get("log_type", "")

    if outcome == "failure" and category == "authentication":
        return "auth_failure"
    if outcome == "success" and category == "authentication":
        return "auth_success"
    if log_type == "network" or "network" in category:
        return "network_connection"
    if log_type == "endpoint" or "process" in category:
        return "endpoint_activity"
    if log_type == "web":
        return "web_attack"
    return "generic_event"


def _build_detail(evt: dict) -> str:
    """Build a human-readable detail string."""
    raw = evt.get("raw_event", evt)
    action = raw.get("action", "")
    src = raw.get("source_ip") or evt.get("source", {}).get("ip", "")
    dst = raw.get("destination_ip") or evt.get("destination", {}).get("ip", "")
    user = raw.get("affected_user") or evt.get("user", {}).get("name", "")

    parts: list[str] = []
    if action:
        parts.append(action)
    if src and dst:
        parts.append(f"({src} → {dst})")
    elif src:
        parts.append(f"(from {src})")
    if user:
        parts.append(f"[user: {user}]")

    return " ".join(parts) if parts else "Correlated event"
