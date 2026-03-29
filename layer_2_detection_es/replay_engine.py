"""
replay_engine.py
----------------
Detection replay engine for historical log analysis.

Allows running detection rules against a specific historical time window.
Use cases:
  - Rule tuning against past data
  - Historical attack discovery
  - Forensic analysis of past incidents

The replay engine temporarily overrides the time window used by rules
by patching the lookback calculation, then restores normal operation.
"""

import logging
from datetime import datetime, timezone, timedelta

from layer_2_detection_es.elastic_client import search_index, run_aggregation
from layer_2_detection_es.rules_registry import get_enabled_rules, get_rule
from layer_2_detection_es.suppression_engine import clear_all as clear_suppressions
from layer_2_detection_es.es_correlator import correlate_all
from layer_2_detection_es.incident_merger import merge_detections
from layer_2_detection_es.incident_builder import build_all_incidents
from layer_2_detection_es.ueba_engine import run_ueba

logger = logging.getLogger(__name__)


def _ts_range(start: datetime, end: datetime) -> dict:
    return {
        "range": {
            "timestamp": {
                "gte": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lte": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        }
    }


def _run_rule_in_window(rule: dict, start: datetime, end: datetime) -> list[dict]:
    """
    Run a single rule against a historical time window.
    Reuses the same query patterns as rules_engine but with explicit timestamps.
    """
    from layer_2_detection_es.rules_engine import _make_detection

    since = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    rule_id = rule["rule_id"]

    # ── Pattern-based rules (web + endpoint) ──────────────────────────
    _PATTERN_RULES = {
        "WEB_SQLI":           ("logs-web",      ["url", "request_body"], ["UNION SELECT", "1=1", "WAITFOR DELAY", "' OR '"]),
        "WEB_CMDI":           ("logs-web",      ["url", "request_body"], ["| bash", "; wget", "/etc/passwd", "| sh"]),
        "WEB_LFI":            ("logs-web",      ["url"],                 ["../", "..%2f", "/etc/passwd"]),
        "WEB_XSS":            ("logs-web",      ["url", "request_body"], ["<script>", "javascript:", "onerror="]),
        "WEB_SCANNER":        ("logs-web",      ["user_agent"],          ["sqlmap", "nikto", "nmap", "curl", "python-requests"]),
        "WEB_SSRF":           ("logs-web",      ["url"],                 ["169.254.169.254", "metadata.google.internal"]),
        "EP_RANSOMWARE":      ("logs-endpoint", ["command_line", "file_path"], [".encrypted", ".locked", "vssadmin delete shadows"]),
        "EP_LOLBIN":          ("logs-endpoint", ["command_line"],        ["-EncodedCommand", "ExecutionPolicy Bypass", "Invoke-WebRequest"]),
        "EP_CREDENTIAL_DUMP": ("logs-endpoint", ["command_line", "process_name"], ["mimikatz", "procdump", "lsass"]),
        "EP_DEF_EVASION":     ("logs-endpoint", ["command_line"],        ["wevtutil cl", "Clear-EventLog"]),
        "EP_PERSISTENCE":     ("logs-endpoint", ["command_line", "registry_key"], ["schtasks /create", "CurrentVersion\\Run"]),
    }

    if rule_id in _PATTERN_RULES:
        index, fields, patterns = _PATTERN_RULES[rule_id]
        should = [{"match_phrase": {f: p}} for f in fields for p in patterns]
        query = {
            "query": {"bool": {
                "must": [_ts_range(start, end)],
                "should": should,
                "minimum_should_match": 1,
            }}
        }
        hits = search_index(index, query)
        return [_make_detection(rule, h, {"replay": True, "pattern": rule_id.lower()}) for h in hits]

    # ── Aggregation-based rules ────────────────────────────────────────
    if rule_id == "AUTH_BRUTEFORCE":
        query = {
            "query": {"bool": {"must": [_ts_range(start, end), {"term": {"action": "login_failed"}}]}},
            "aggs": {"by_src": {"terms": {"field": "source_ip.keyword", "min_doc_count": 20}}}
        }
        aggs = run_aggregation("logs-auth", query)
        return [
            _make_detection(rule, {"source_ip": b["key"]}, {"failure_count": b["doc_count"], "replay": True})
            for b in aggs.get("by_src", {}).get("buckets", [])
        ]

    if rule_id == "NET_PORTSCAN":
        query = {
            "query": {"bool": {"must": [_ts_range(start, end)]}},
            "aggs": {"by_src": {
                "terms": {"field": "source_ip.keyword", "min_doc_count": 10},
                "aggs": {
                    "unique_ports": {"cardinality": {"field": "destination_port"}},
                    "unique_hosts": {"cardinality": {"field": "destination_ip.keyword"}},
                }
            }}
        }
        aggs = run_aggregation("logs-network", query)
        detections = []
        for b in aggs.get("by_src", {}).get("buckets", []):
            ports = b.get("unique_ports", {}).get("value", 0)
            hosts = b.get("unique_hosts", {}).get("value", 0)
            if ports >= 50 or hosts >= 50:
                detections.append(_make_detection(rule, {"source_ip": b["key"]}, {
                    "unique_ports": ports, "unique_hosts": hosts, "replay": True
                }))
        return detections

    if rule_id == "NET_EXFIL":
        query = {
            "query": {"bool": {"must": [_ts_range(start, end), {"term": {"direction": "outbound"}}]}},
            "aggs": {"by_src": {
                "terms": {"field": "source_ip.keyword"},
                "aggs": {"total_bytes": {"sum": {"field": "bytes_out"}}}
            }}
        }
        aggs = run_aggregation("logs-network", query)
        return [
            _make_detection(rule, {"source_ip": b["key"]}, {
                "total_bytes": b.get("total_bytes", {}).get("value", 0), "replay": True
            })
            for b in aggs.get("by_src", {}).get("buckets", [])
            if (b.get("total_bytes", {}).get("value", 0) or 0) >= 1_073_741_824
        ]

    # Default: no handler for this rule in replay mode
    logger.debug("No replay handler for rule %s — skipping", rule_id)
    return []


def run_detection_replay(
    start_time: datetime,
    end_time: datetime,
    rule_ids: list[str] | None = None,
    suppress: bool = False,
) -> list[dict]:
    """
    Run detection rules against a historical time window.

    Args:
        start_time: replay window start (UTC datetime)
        end_time:   replay window end   (UTC datetime)
        rule_ids:   specific rules to run (None = all enabled)
        suppress:   whether to apply suppression during replay

    Returns:
        list of incident dicts
    """
    logger.info(
        "REPLAY started: %s → %s rules=%s",
        start_time.isoformat(), end_time.isoformat(),
        rule_ids or "all"
    )

    if not suppress:
        clear_suppressions()

    target_rules = [
        r for r in get_enabled_rules()
        if rule_ids is None or r["rule_id"] in rule_ids
    ]

    all_detections: list[dict] = []
    for rule in target_rules:
        try:
            dets = _run_rule_in_window(rule, start_time, end_time)
            for det in dets:
                logger.info(
                    "REPLAY DETECTION: rule=%s entity=%s timestamp=%s",
                    det["rule_id"],
                    det.get("source_ip") or det.get("affected_user"),
                    det.get("timestamp"),
                )
            all_detections.extend(dets)
        except Exception as exc:
            logger.error("Replay rule %s failed: %s", rule["rule_id"], exc)

    logger.info("Replay found %d raw detections", len(all_detections))

    if not all_detections:
        return []

    # Correlate, merge, and build incidents
    enriched   = correlate_all(all_detections)
    clusters   = merge_detections(enriched)
    ueba       = run_ueba(lookback_minutes=int((end_time - start_time).total_seconds() / 60))
    incidents  = build_all_incidents(clusters, ueba)

    logger.info("Replay produced %d incidents", len(incidents))
    return incidents
