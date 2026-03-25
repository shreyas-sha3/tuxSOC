"""
auto_enricher.py
----------------
Watches detection engine outputs and automatically stages new IOC candidates
into the auto_enriched_candidates table for analyst review.

Four configurable triggers (each can be toggled independently via config.py):

  1. UNKNOWN_IP_FREQUENCY   — an IP seen ≥ N times in a rolling window not in ioc_entries
  2. FLAGGED_DOMAIN         — a domain flagged by anomaly engine but absent from ioc_entries
  3. UNKNOWN_FILE_HASH      — a file hash in endpoint logs not in ioc_entries
  4. IOT_CIS_VIOLATION      — an IoT device violated a CIS benchmark rule

When a candidate is staged, it gets:
  - source = "auto"
  - confidence = "low"     (analyst can promote to "medium" or "high")
  - status = "pending"     (pending review in the SOC dashboard)

Analyst then uses ioc_api.py to:
  - GET  /ioc/candidates            → see all pending
  - POST /ioc/candidates/{id}/promote → move to ioc_entries (with optional edits)
  - POST /ioc/candidates/{id}/reject  → mark as false positive
"""

import json
import logging
import time
from collections import defaultdict
from typing import Optional
from ioc_db import get_connection, lookup_ioc, insert_ioc, DEFAULT_DB_PATH

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enrichment config — each trigger can be toggled in config.py
# If you import this module, these defaults are used unless you call
# configure_triggers() with overrides.
# ---------------------------------------------------------------------------

_TRIGGER_CONFIG = {
    "UNKNOWN_IP_FREQUENCY": {
        "enabled": True,
        "threshold": 5,           # times seen in the rolling window
        "window_seconds": 300,    # 5-minute rolling window
    },
    "FLAGGED_DOMAIN": {
        "enabled": True,
        "min_anomaly_score": 0.7, # only stage if anomaly score ≥ this
    },
    "UNKNOWN_FILE_HASH": {
        "enabled": True,
    },
    "IOT_CIS_VIOLATION": {
        "enabled": True,
    },
}

# In-memory rolling window counter for unknown IPs
# Format: {ip: [(timestamp, event_snapshot), ...]}
_ip_window: dict[str, list] = defaultdict(list)


def configure_triggers(overrides: dict) -> None:
    """
    Override trigger configuration at runtime.
    Example:
        configure_triggers({
            "UNKNOWN_IP_FREQUENCY": {"enabled": False},
            "FLAGGED_DOMAIN": {"min_anomaly_score": 0.85},
        })
    """
    for trigger, settings in overrides.items():
        if trigger in _TRIGGER_CONFIG:
            _TRIGGER_CONFIG[trigger].update(settings)
            logger.info("Trigger %s reconfigured: %s", trigger, settings)
        else:
            logger.warning("Unknown trigger name: %s", trigger)


# ---------------------------------------------------------------------------
# Internal staging helper
# ---------------------------------------------------------------------------

def _stage_candidate(ioc_type: str, value: str, trigger: str,
                     trigger_detail: str, anomaly_score: Optional[float],
                     log_type: str, raw_event: dict,
                     db_path: str) -> bool:
    """
    Insert a candidate into auto_enriched_candidates.
    Returns True if newly staged, False if already present.
    """
    raw_str = json.dumps(raw_event, default=str)
    with get_connection(db_path) as conn:
        try:
            conn.execute("""
                INSERT INTO auto_enriched_candidates
                    (ioc_type, value, trigger, trigger_detail,
                     anomaly_score, log_type, raw_event)
                VALUES (?,?,?,?,?,?,?)
            """, (ioc_type, value, trigger, trigger_detail,
                  anomaly_score, log_type, raw_str))
            logger.info("Staged auto-enrichment candidate: [%s] %s (%s)",
                        ioc_type, value, trigger)
            return True
        except Exception:
            # UNIQUE constraint hit — already staged, that's fine
            return False


# ---------------------------------------------------------------------------
# Trigger 1: Unknown IP seen repeatedly
# ---------------------------------------------------------------------------

def check_unknown_ip_frequency(source_ip: str, raw_event: dict,
                                anomaly_score: float, log_type: str,
                                db_path: str = DEFAULT_DB_PATH) -> bool:
    """
    Track how often an unknown IP appears. Stage it if it hits the threshold
    within the rolling window.

    Call this from the intel_orchestrator after every event.
    Returns True if a new candidate was staged.
    """
    cfg = _TRIGGER_CONFIG["UNKNOWN_IP_FREQUENCY"]
    if not cfg["enabled"] or not source_ip:
        return False

    # If it's already a known IOC, don't track
    if lookup_ioc(source_ip, ioc_type="ip", db_path=db_path):
        return False

    now = time.time()
    window = cfg["window_seconds"]

    # Append current hit
    _ip_window[source_ip].append((now, raw_event))

    # Prune entries outside the rolling window
    _ip_window[source_ip] = [
        (ts, ev) for ts, ev in _ip_window[source_ip]
        if now - ts <= window
    ]

    count = len(_ip_window[source_ip])
    threshold = cfg["threshold"]

    if count >= threshold:
        detail = f"seen {count} times in {window}s window"
        staged = _stage_candidate(
            ioc_type="ip", value=source_ip,
            trigger="UNKNOWN_IP_FREQUENCY",
            trigger_detail=detail,
            anomaly_score=anomaly_score,
            log_type=log_type, raw_event=raw_event,
            db_path=db_path
        )
        if staged:
            # Reset window after staging to avoid re-staging on every subsequent hit
            _ip_window[source_ip] = []
        return staged

    return False


# ---------------------------------------------------------------------------
# Trigger 2: Domain flagged by anomaly engine but absent from IOC DB
# ---------------------------------------------------------------------------

def check_flagged_domain(domain: str, raw_event: dict,
                         anomaly_score: float, log_type: str,
                         db_path: str = DEFAULT_DB_PATH) -> bool:
    """
    If the anomaly engine flagged this event and the domain isn't in the DB,
    stage it as a candidate.
    """
    cfg = _TRIGGER_CONFIG["FLAGGED_DOMAIN"]
    if not cfg["enabled"] or not domain:
        return False

    if anomaly_score < cfg["min_anomaly_score"]:
        return False

    if lookup_ioc(domain, ioc_type="domain", db_path=db_path):
        return False

    return _stage_candidate(
        ioc_type="domain", value=domain,
        trigger="FLAGGED_DOMAIN",
        trigger_detail=f"anomaly_score={anomaly_score:.2f}, not in IOC DB",
        anomaly_score=anomaly_score,
        log_type=log_type, raw_event=raw_event,
        db_path=db_path
    )


# ---------------------------------------------------------------------------
# Trigger 3: Unknown file hash from endpoint logs
# ---------------------------------------------------------------------------

def check_unknown_file_hash(file_hash: str, raw_event: dict,
                             anomaly_score: float, log_type: str,
                             db_path: str = DEFAULT_DB_PATH) -> bool:
    """
    If an endpoint log contains a file hash not in the IOC DB, stage it.
    Even benign-looking hashes are worth reviewing if the anomaly engine
    also flagged the event.
    """
    cfg = _TRIGGER_CONFIG["UNKNOWN_FILE_HASH"]
    if not cfg["enabled"] or not file_hash:
        return False

    if lookup_ioc(file_hash, ioc_type="file_hash", db_path=db_path):
        return False

    return _stage_candidate(
        ioc_type="file_hash", value=file_hash,
        trigger="UNKNOWN_FILE_HASH",
        trigger_detail=f"hash not in IOC DB, anomaly_score={anomaly_score:.2f}",
        anomaly_score=anomaly_score,
        log_type=log_type, raw_event=raw_event,
        db_path=db_path
    )


# ---------------------------------------------------------------------------
# Trigger 4: IoT device violating a CIS benchmark rule
# ---------------------------------------------------------------------------

def check_iot_cis_violation(device_id: str, device_type: str,
                             violated_rule: dict, raw_event: dict,
                             anomaly_score: float,
                             db_path: str = DEFAULT_DB_PATH) -> bool:
    """
    When an IoT device is found to violate a CIS benchmark rule, stage
    the device identifier as a candidate for analyst review.

    violated_rule should be the matched cis_rules row dict.
    """
    cfg = _TRIGGER_CONFIG["IOT_CIS_VIOLATION"]
    if not cfg["enabled"] or not device_id:
        return False

    # Use the device_id as the "value" under a new ioc_type concept
    # We store it as type 'ip' if device_id looks like an IP,
    # otherwise we store it as a generic 'domain' (hostname/device label)
    import re
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", device_id))
    ioc_type = "ip" if is_ip else "domain"

    detail = (
        f"IoT device '{device_id}' ({device_type}) violated "
        f"CIS rule {violated_rule.get('benchmark_id','?')}: "
        f"{violated_rule.get('title','?')}"
    )

    return _stage_candidate(
        ioc_type=ioc_type, value=device_id,
        trigger="IOT_CIS_VIOLATION",
        trigger_detail=detail,
        anomaly_score=anomaly_score,
        log_type="iot", raw_event=raw_event,
        db_path=db_path
    )


# ---------------------------------------------------------------------------
# Analyst promotion / rejection (called by ioc_api.py)
# ---------------------------------------------------------------------------

def promote_candidate(candidate_id: int, analyst_id: str,
                      severity: str = "medium",
                      confidence: str = "medium",
                      description: str = None,
                      db_path: str = DEFAULT_DB_PATH) -> Optional[int]:
    """
    Promote a staged candidate to the ioc_entries table.
    Returns the new ioc_entries row id, or None on failure.
    """
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM auto_enriched_candidates WHERE id=? AND status='pending'",
            (candidate_id,)
        ).fetchone()

        if not row:
            logger.warning("Candidate %d not found or not pending.", candidate_id)
            return None

        row = dict(row)

    # Insert into ioc_entries
    ioc_id = insert_ioc(
        ioc_type=row["ioc_type"],
        value=row["value"],
        threat_type=f"auto_promoted_{row['trigger'].lower()}",
        severity=severity,
        confidence=confidence,
        source="auto",
        description=description or row.get("trigger_detail", ""),
        added_by=analyst_id,
        db_path=db_path
    )

    # Mark candidate as promoted
    with get_connection(db_path) as conn:
        conn.execute("""
            UPDATE auto_enriched_candidates
            SET status='promoted', reviewed_by=?, reviewed_at=datetime('now')
            WHERE id=?
        """, (analyst_id, candidate_id))

    logger.info("Candidate %d promoted to ioc_entries id=%d by %s",
                candidate_id, ioc_id, analyst_id)
    return ioc_id


def reject_candidate(candidate_id: int, analyst_id: str,
                     db_path: str = DEFAULT_DB_PATH) -> bool:
    """Mark a staged candidate as rejected (false positive)."""
    with get_connection(db_path) as conn:
        conn.execute("""
            UPDATE auto_enriched_candidates
            SET status='rejected', reviewed_by=?, reviewed_at=datetime('now')
            WHERE id=? AND status='pending'
        """, (analyst_id, candidate_id))
    logger.info("Candidate %d rejected by %s.", candidate_id, analyst_id)
    return True