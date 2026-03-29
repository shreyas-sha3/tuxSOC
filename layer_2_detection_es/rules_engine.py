"""
rules_engine.py
---------------
Executes all 20 detection rules against Elasticsearch.
Each rule runs a targeted ES query and returns structured detections.
"""

import logging
from datetime import datetime, timezone, timedelta

from layer_2_detection_es.elastic_client import search_index, run_aggregation
from layer_2_detection_es.rules_registry import get_enabled_rules, get_rule
from layer_2_detection_es.suppression_engine import is_suppressed, record_alert

logger = logging.getLogger(__name__)


def _now_minus(minutes: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _time_range(minutes: int) -> dict:
    return {"range": {"timestamp": {"gte": _now_minus(minutes), "lte": "now"}}}


# ── Rule implementations ───────────────────────────────────────────────────

def _run_web_sqli(rule: dict, since: str) -> list[dict]:
    patterns = ["UNION SELECT", "1=1", "WAITFOR DELAY", "' OR '", "-- ", "/**/"]
    should = [{"match_phrase": {"url": p}} for p in patterns] + \
             [{"match_phrase": {"request_body": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "sql_injection"}) for h in hits]


def _run_web_cmdi(rule: dict, since: str) -> list[dict]:
    patterns = ["| bash", "; wget", "/etc/passwd", "| sh", "; curl", "$(", "`"]
    should = [{"match_phrase": {"url": p}} for p in patterns] + \
             [{"match_phrase": {"request_body": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "command_injection"}) for h in hits]


def _run_web_lfi(rule: dict, since: str) -> list[dict]:
    patterns = ["../", "..%2f", "/etc/passwd", "/etc/shadow", "..\\"]
    should = [{"match_phrase": {"url": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "lfi"}) for h in hits]


def _run_web_xss(rule: dict, since: str) -> list[dict]:
    patterns = ["<script>", "javascript:", "onerror=", "onload=", "alert("]
    should = [{"match_phrase": {"url": p}} for p in patterns] + \
             [{"match_phrase": {"request_body": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "xss"}) for h in hits]


def _run_web_scanner(rule: dict, since: str) -> list[dict]:
    agents = ["sqlmap", "nikto", "nmap", "curl", "python-requests", "masscan", "dirbuster"]
    should = [{"match_phrase": {"user_agent": a}} for a in agents]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "scanner_ua"}) for h in hits]


def _run_web_ssrf(rule: dict, since: str) -> list[dict]:
    targets = ["169.254.169.254", "metadata.google.internal", "169.254.170.2",
               "fd00:ec2::254", "metadata.internal"]
    should = [{"match_phrase": {"url": t}} for t in targets] + \
             [{"match_phrase": {"request_body": t}} for t in targets]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "ssrf_metadata"}) for h in hits]


def _run_auth_bruteforce(rule: dict, since: str) -> list[dict]:
    """≥20 login failures from same source_ip within 1 minute."""
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(1)}}},
            {"term": {"action": "login_failed"}},
        ]}},
        "aggs": {"by_src": {"terms": {"field": "source_ip.keyword", "min_doc_count": 20}}}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        src = bucket["key"]
        count = bucket["doc_count"]
        detections.append(_make_detection(rule, {"source_ip": src}, {
            "failure_count": count, "window": "1m"
        }))
    return detections


def _run_auth_spray(rule: dict, since: str) -> list[dict]:
    """Same source_ip targeting >10 unique users within 5 minutes."""
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(5)}}},
            {"term": {"action": "login_failed"}},
        ]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "min_doc_count": 5},
            "aggs": {"unique_users": {"cardinality": {"field": "affected_user.keyword"}}}
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        unique = bucket.get("unique_users", {}).get("value", 0)
        if unique >= 10:
            detections.append(_make_detection(rule, {"source_ip": bucket["key"]}, {
                "unique_users_targeted": unique, "window": "5m"
            }))
    return detections


def _run_auth_mfa_fatigue(rule: dict, since: str) -> list[dict]:
    """Multiple MFA prompts followed by successful login from same user."""
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(30)}}},
            {"terms": {"action": ["mfa_prompt", "mfa_denied"]}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "min_doc_count": 3},
            "aggs": {"mfa_count": {"value_count": {"field": "action.keyword"}}}
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        # Check if a successful login followed the MFA prompts
        success_q = {
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": _now_minus(30)}}},
                {"term": {"affected_user.keyword": user}},
                {"term": {"action": "login_success"}},
            ]}}
        }
        hits = search_index(rule["index"], success_q, size=1)
        if hits:
            detections.append(_make_detection(rule, {"affected_user": user}, {
                "mfa_prompts": bucket["doc_count"], "followed_by_success": True
            }))
    return detections


def _run_auth_priv_abuse(rule: dict, since: str) -> list[dict]:
    """Admin/root login from outside jump-box subnet (10.0.0.0/24)."""
    query = {
        "query": {"bool": {
            "must": [
                {"range": {"timestamp": {"gte": since}}},
                {"term": {"action": "login_success"}},
                {"terms": {"affected_user.keyword": ["admin", "root", "administrator"]}},
            ],
            "must_not": [
                {"prefix": {"source_ip": "10.0.0."}},
            ]
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"reason": "privileged_login_outside_jumpbox"}) for h in hits]


def _run_ep_ransomware(rule: dict, since: str) -> list[dict]:
    patterns = [".encrypted", ".locked", ".vault", "vssadmin delete shadows",
                ".ransom", "YOUR_FILES_ARE_ENCRYPTED"]
    should = [{"match_phrase": {"command_line": p}} for p in patterns] + \
             [{"match_phrase": {"file_path": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "ransomware_indicator"}) for h in hits]


def _run_ep_lolbin(rule: dict, since: str) -> list[dict]:
    patterns = ["-EncodedCommand", "ExecutionPolicy Bypass", "Invoke-WebRequest",
                "IEX(", "DownloadString", "certutil -decode", "regsvr32 /s /n /u /i"]
    should = [{"match_phrase": {"command_line": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "lolbin"}) for h in hits]


def _run_ep_credential_dump(rule: dict, since: str) -> list[dict]:
    patterns = ["mimikatz", "procdump", "lsass", "sekurlsa", "wce.exe",
                "gsecdump", "fgdump", "pwdump"]
    should = [{"match_phrase": {"command_line": p}} for p in patterns] + \
             [{"match_phrase": {"process_name": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "credential_dump"}) for h in hits]


def _run_ep_def_evasion(rule: dict, since: str) -> list[dict]:
    patterns = ["wevtutil cl", "Clear-EventLog", "wevtutil clear-log",
                "Remove-EventLog", "auditpol /clear"]
    should = [{"match_phrase": {"command_line": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "log_clearing"}) for h in hits]


def _run_ep_persistence(rule: dict, since: str) -> list[dict]:
    patterns = ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "schtasks /create", "at.exe", "sc create",
                "New-ScheduledTask"]
    should = [{"match_phrase": {"command_line": p}} for p in patterns] + \
             [{"match_phrase": {"registry_key": p}} for p in patterns]
    query = {
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": since}}}],
            "should": should,
            "minimum_should_match": 1,
        }}
    }
    hits = search_index(rule["index"], query)
    return [_make_detection(rule, h, {"pattern": "persistence_mechanism"}) for h in hits]


def _run_net_portscan(rule: dict, since: str) -> list[dict]:
    """Same source_ip hitting >50 unique ports OR >50 unique hosts within 2 min."""
    query = {
        "query": {"bool": {"must": [{"range": {"timestamp": {"gte": _now_minus(2)}}}]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "min_doc_count": 10},
            "aggs": {
                "unique_ports": {"cardinality": {"field": "destination_port"}},
                "unique_hosts": {"cardinality": {"field": "destination_ip.keyword"}},
            }
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        ports = bucket.get("unique_ports", {}).get("value", 0)
        hosts = bucket.get("unique_hosts", {}).get("value", 0)
        if ports >= 50 or hosts >= 50:
            detections.append(_make_detection(rule, {"source_ip": bucket["key"]}, {
                "unique_ports": ports, "unique_hosts": hosts, "window": "2m"
            }))
    return detections


def _run_net_c2_beacon(rule: dict, since: str) -> list[dict]:
    """
    Periodic outbound connections with low timing variance.
    Proxy: same src→dst pair with ≥10 connections and low byte variance.
    """
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(60)}}},
            {"term": {"direction": "outbound"}},
        ]}},
        "aggs": {"by_pair": {
            "terms": {
                "script": {"source": "doc['source_ip.keyword'].value + '|' + doc['destination_ip.keyword'].value"},
                "min_doc_count": 10,
                "size": 50,
            },
            "aggs": {"byte_stddev": {"extended_stats": {"field": "bytes_out"}}}
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_pair", {}).get("buckets", []):
        stats = bucket.get("byte_stddev", {})
        stddev = stats.get("std_deviation", 9999)
        avg    = stats.get("avg", 0)
        # Low variance relative to mean = beaconing pattern
        if avg > 0 and stddev / max(avg, 1) < 0.3:
            src, dst = bucket["key"].split("|", 1)
            detections.append(_make_detection(rule, {"source_ip": src, "destination_ip": dst}, {
                "connection_count": bucket["doc_count"],
                "byte_stddev": round(stddev, 2),
                "byte_avg": round(avg, 2),
            }))
    return detections


def _run_net_dns_tunnel(rule: dict, since: str) -> list[dict]:
    """Long DNS TXT records or high-entropy subdomains."""
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": since}}},
            {"term": {"protocol": "dns"}},
        ]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "min_doc_count": 5},
            "aggs": {"avg_query_len": {"avg": {"field": "dns_query_length"}}}
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        avg_len = bucket.get("avg_query_len", {}).get("value", 0) or 0
        if avg_len >= 50:
            detections.append(_make_detection(rule, {"source_ip": bucket["key"]}, {
                "avg_dns_query_length": round(avg_len, 1),
                "query_count": bucket["doc_count"],
            }))
    return detections


def _run_net_exfil(rule: dict, since: str) -> list[dict]:
    """>1 GB outbound to external IP within 10 minutes."""
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(10)}}},
            {"term": {"direction": "outbound"}},
        ]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "min_doc_count": 1},
            "aggs": {"total_bytes": {"sum": {"field": "bytes_out"}}}
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        total = bucket.get("total_bytes", {}).get("value", 0) or 0
        if total >= 1_073_741_824:  # 1 GB
            detections.append(_make_detection(rule, {"source_ip": bucket["key"]}, {
                "total_bytes_out": total,
                "total_gb": round(total / 1_073_741_824, 2),
                "window": "10m",
            }))
    return detections


def _run_net_lateral(rule: dict, since: str) -> list[dict]:
    """SMB or RDP to >5 internal hosts within 3 minutes."""
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(3)}}},
            {"terms": {"destination_port": [445, 139, 3389]}},
            {"prefix": {"destination_ip": "192.168."}},
        ]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "min_doc_count": 3},
            "aggs": {"unique_hosts": {"cardinality": {"field": "destination_ip.keyword"}}}
        }}
    }
    aggs = run_aggregation(rule["index"], query)
    detections = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        hosts = bucket.get("unique_hosts", {}).get("value", 0)
        if hosts >= 5:
            detections.append(_make_detection(rule, {"source_ip": bucket["key"]}, {
                "unique_internal_hosts": hosts, "window": "3m"
            }))
    return detections


# ── Dispatch table ─────────────────────────────────────────────────────────

_RULE_HANDLERS = {
    "WEB_SQLI":           _run_web_sqli,
    "WEB_CMDI":           _run_web_cmdi,
    "WEB_LFI":            _run_web_lfi,
    "WEB_XSS":            _run_web_xss,
    "WEB_SCANNER":        _run_web_scanner,
    "WEB_SSRF":           _run_web_ssrf,
    "AUTH_BRUTEFORCE":    _run_auth_bruteforce,
    "AUTH_SPRAY":         _run_auth_spray,
    "AUTH_MFA_FATIGUE":   _run_auth_mfa_fatigue,
    "AUTH_PRIV_ABUSE":    _run_auth_priv_abuse,
    "EP_RANSOMWARE":      _run_ep_ransomware,
    "EP_LOLBIN":          _run_ep_lolbin,
    "EP_CREDENTIAL_DUMP": _run_ep_credential_dump,
    "EP_DEF_EVASION":     _run_ep_def_evasion,
    "EP_PERSISTENCE":     _run_ep_persistence,
    "NET_PORTSCAN":       _run_net_portscan,
    "NET_C2_BEACON":      _run_net_c2_beacon,
    "NET_DNS_TUNNEL":     _run_net_dns_tunnel,
    "NET_EXFIL":          _run_net_exfil,
    "NET_LATERAL":        _run_net_lateral,
}


def _make_detection(rule: dict, event: dict, context: dict) -> dict:
    """Build a structured detection object."""
    return {
        "rule_id":      rule["rule_id"],
        "rule_name":    rule["name"],
        "category":     rule["category"],
        "mitre":        rule["mitre"],
        "severity":     rule["severity"],
        "risk_weight":  rule["risk_weight"],
        "confidence":   rule["confidence"],
        "source_ip":    event.get("source_ip", ""),
        "affected_user": event.get("affected_user", ""),
        "affected_host": event.get("affected_host", ""),
        "destination_ip": event.get("destination_ip", ""),
        "timestamp":    event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "context":      context,
        "raw_event":    event,
    }


# ── Public API ─────────────────────────────────────────────────────────────

def run_all_rules(lookback_minutes: int = 2) -> list[dict]:
    """
    Execute all enabled rules and return a flat list of detections.
    Suppressed alerts are skipped and logged.
    """
    since = _now_minus(lookback_minutes)
    all_detections: list[dict] = []

    for rule in get_enabled_rules():
        handler = _RULE_HANDLERS.get(rule["rule_id"])
        if not handler:
            logger.warning("No handler for rule %s", rule["rule_id"])
            continue
        try:
            detections = handler(rule, since)
            for det in detections:
                entity = det.get("source_ip") or det.get("affected_user") or "unknown"
                if is_suppressed(rule["rule_id"], entity):
                    logger.info(
                        "SUPPRESSED rule=%s entity=%s",
                        rule["rule_id"], entity
                    )
                    continue
                record_alert(rule["rule_id"], entity, rule["cooldown"])
                logger.info(
                    "TRIGGERED rule=%s entity=%s confidence=%.2f",
                    rule["rule_id"], entity, rule["confidence"]
                )
                all_detections.append(det)
        except Exception as exc:
            logger.error("Rule %s failed: %s", rule["rule_id"], exc)

    return all_detections


def run_rules_for_replay(lookback_minutes: int, rules: list[str] | None = None) -> list[dict]:
    """Run specific rules (or all) for a historical time window."""
    since = _now_minus(lookback_minutes)
    all_detections: list[dict] = []
    target_rules = [r for r in get_enabled_rules()
                    if rules is None or r["rule_id"] in rules]
    for rule in target_rules:
        handler = _RULE_HANDLERS.get(rule["rule_id"])
        if not handler:
            continue
        try:
            detections = handler(rule, since)
            all_detections.extend(detections)
        except Exception as exc:
            logger.error("Replay rule %s failed: %s", rule["rule_id"], exc)
    return all_detections
