# rules_engine.py
# Location: layer_2_detection/rules_engine.py
# ─────────────────────────────────────────────────────────────────
# Comprehensive ES-backed Rule Engine for Layer 2.
#
# Each rule is a function that returns a list of "detections", where
# each detection is a dict:
#   {
#       "rule_id":    "WEB_SQLI",
#       "log_type":   "web",
#       "raw_hits":   [ ... raw ES docs ... ],
#       "pivot_ip":   "1.2.3.4",         # key for correlation
#       "pivot_user": "jdoe",            # optional
#       "ueba_flags": ["sqli_pattern"],  # extra flags for anomaly engine
#       "detail":     "Detected SQL injection payload in URI parameter",
#   }
#
# All queries use Request Body DSL via elasticsearch-py.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from elasticsearch import Elasticsearch, NotFoundError
from typing import Optional


# ═════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════

def _safe_search(es: Elasticsearch, index: str, body: dict, label: str) -> list[dict]:
    """Execute a search and return hits, swallowing missing-index errors."""
    try:
        resp = es.search(index=index, body=body, request_timeout=10)
        return [h["_source"] for h in resp["hits"]["hits"]]
    except NotFoundError:
        print(f"[L2-RULES] WARN RulesEngine] Index '{index}' does not exist — skipping {label}")
        return []
    except Exception as e:
        print(f"[L2-RULES] WARN RulesEngine] Query failed for {label}: {e}")
        return []


def _safe_agg_search(es: Elasticsearch, index: str, body: dict, label: str) -> dict:
    """Execute an aggregation search and return the full response body."""
    try:
        return es.search(index=index, body=body, request_timeout=10)
    except NotFoundError:
        print(f"[L2-RULES] WARN RulesEngine] Index '{index}' does not exist — skipping {label}")
        return {}
    except Exception as e:
        print(f"[L2-RULES] WARN RulesEngine] Agg query failed for {label}: {e}")
        return {}


# ═════════════════════════════════════════════════════════════════
# 1. WEB ATTACK RULES  (index: logs-web)
# ═════════════════════════════════════════════════════════════════

def rule_web_sqli(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """SQL Injection — OWASP A05: Injection"""
    body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"request.uri": "UNION SELECT"}},
                    {"match_phrase": {"request.uri": "1=1"}},
                    {"wildcard":     {"request.uri.keyword": "*--*"}},
                    {"match_phrase": {"request.uri": "WAITFOR DELAY"}},
                    {"match_phrase": {"request.body": "UNION SELECT"}},
                    {"match_phrase": {"request.body": "1=1"}},
                    {"match_phrase": {"request.body": "WAITFOR DELAY"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-web", body, "WEB_SQLI")
    detections = []
    for h in hits:
        detections.append({
            "rule_id":    "WEB_SQLI",
            "log_type":   "web",
            "raw_hits":   [h],
            "pivot_ip":   h.get("source", {}).get("ip") or h.get("source_ip", ""),
            "pivot_user": h.get("user", {}).get("name"),
            "ueba_flags": ["sqli_pattern"],
            "detail":     "SQL Injection payload detected in HTTP request",
        })
    return detections


def rule_web_cmdi(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """OS Command Injection"""
    body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"request.uri": "/etc/passwd"}},
                    {"match_phrase": {"request.uri": "| bash"}},
                    {"match_phrase": {"request.uri": "; wget"}},
                    {"match_phrase": {"request.body": "/etc/passwd"}},
                    {"match_phrase": {"request.body": "| bash"}},
                    {"match_phrase": {"request.body": "; wget"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-web", body, "WEB_CMDI")
    return [{
        "rule_id": "WEB_CMDI", "log_type": "web", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name"),
        "ueba_flags": ["cmdi_pattern"],
        "detail": "OS Command Injection payload detected",
    } for h in hits]


def rule_web_lfi(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Path Traversal / Local File Inclusion"""
    body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"wildcard": {"request.uri.keyword": "*../*"}},
                    {"wildcard": {"request.uri.keyword": "*..%2f*"}},
                    {"wildcard": {"request.uri.keyword": "*..%252f*"}},
                    {"match_phrase": {"request.uri": "/etc/shadow"}},
                    {"match_phrase": {"request.uri": "boot.ini"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-web", body, "WEB_LFI")
    return [{
        "rule_id": "WEB_LFI", "log_type": "web", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name"),
        "ueba_flags": ["lfi_pattern"],
        "detail": "Path traversal / LFI attempt detected",
    } for h in hits]


def rule_web_xss(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Cross-Site Scripting (XSS)"""
    body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"request.uri": "<script>"}},
                    {"match_phrase": {"request.uri": "javascript:"}},
                    {"match_phrase": {"request.uri": "onerror="}},
                    {"match_phrase": {"request.body": "<script>"}},
                    {"match_phrase": {"request.body": "onerror="}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-web", body, "WEB_XSS")
    return [{
        "rule_id": "WEB_XSS", "log_type": "web", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name"),
        "ueba_flags": ["xss_pattern"],
        "detail": "XSS payload detected in HTTP request",
    } for h in hits]


def rule_web_scanner(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Automated Scanner / Recon Traffic"""
    body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"user_agent.original": "sqlmap"}},
                    {"match_phrase": {"user_agent.original": "nikto"}},
                    {"match_phrase": {"user_agent.original": "nmap"}},
                    {"match_phrase": {"user_agent.original": "python-requests"}},
                    {"match_phrase": {"user_agent.original": "dirbuster"}},
                    {"match_phrase": {"user_agent.original": "gobuster"}},
                    {"match_phrase": {"user_agent.original": "masscan"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-web", body, "WEB_SCANNER")
    return [{
        "rule_id": "WEB_SCANNER", "log_type": "web", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("source_ip", ""),
        "pivot_user": None,
        "ueba_flags": ["scanner_traffic"],
        "detail": f"Automated scanner detected: {h.get('user_agent', {}).get('original', 'Unknown')}",
    } for h in hits]


def rule_web_ssrf(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Server-Side Request Forgery (SSRF) — targeting cloud metadata"""
    body = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"request.uri": "169.254.169.254"}},
                    {"match_phrase": {"request.uri": "metadata.google"}},
                    {"match_phrase": {"request.uri": "100.100.100.200"}},  # Alibaba
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-web", body, "WEB_SSRF")
    return [{
        "rule_id": "WEB_SSRF", "log_type": "web", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name"),
        "ueba_flags": ["ssrf_attempt"],
        "detail": "SSRF attempt targeting cloud metadata endpoint",
    } for h in hits]


# ═════════════════════════════════════════════════════════════════
# 2. AUTHENTICATION ATTACK RULES  (index: logs-auth)
# ═════════════════════════════════════════════════════════════════

def rule_auth_bruteforce(es: Elasticsearch, time_range: str = "now-1m") -> list[dict]:
    """Brute Force — >20 failures from single source_ip in 1 minute"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    {"match": {"event.outcome": "failure"}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "min_doc_count": 21, "size": 100},
            }
        },
    }
    resp = _safe_agg_search(es, "logs-auth", body, "AUTH_BRUTEFORCE")
    if not resp:
        return []

    detections = []
    buckets = resp.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    for b in buckets:
        detections.append({
            "rule_id":    "AUTH_BRUTEFORCE",
            "log_type":   "auth",
            "raw_hits":   [],
            "pivot_ip":   b["key"],
            "pivot_user": None,
            "ueba_flags": ["credential_stuffing_pattern"],
            "detail":     f"Brute force: {b['doc_count']} failed logins from {b['key']} in 1 minute",
        })
    return detections


def rule_auth_spray(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Password Spraying — single IP targeting >10 distinct accounts in 5 min"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    {"match": {"event.outcome": "failure"}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 200},
                "aggs": {
                    "unique_users": {
                        "cardinality": {"field": "raw_event.affected_user.keyword"}
                    }
                },
            }
        },
    }
    resp = _safe_agg_search(es, "logs-auth", body, "AUTH_SPRAY")
    if not resp:
        return []

    detections = []
    for b in resp.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        unique = b.get("unique_users", {}).get("value", 0)
        if unique > 10:
            detections.append({
                "rule_id":    "AUTH_SPRAY",
                "log_type":   "auth",
                "raw_hits":   [],
                "pivot_ip":   b["key"],
                "pivot_user": None,
                "ueba_flags": ["password_spraying"],
                "detail":     f"Password spraying: {b['key']} targeted {unique} unique accounts in 5 min",
            })
    return detections


def rule_auth_mfa_fatigue(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """MFA Fatigue — High MFA prompt frequency followed by a success"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    {"term": {"event.category": "authentication"}},
                    {"term": {"event.action": "mfa_prompt"}},
                ]
            }
        },
        "aggs": {
            "by_user": {
                "terms": {"field": "raw_event.affected_user.keyword", "min_doc_count": 5, "size": 100},
            }
        },
    }
    resp = _safe_agg_search(es, "logs-auth", body, "AUTH_MFA_FATIGUE")
    if not resp:
        return []

    detections = []
    for b in resp.get("aggregations", {}).get("by_user", {}).get("buckets", []):
        detections.append({
            "rule_id":    "AUTH_MFA_FATIGUE",
            "log_type":   "auth",
            "raw_hits":   [],
            "pivot_ip":   "",
            "pivot_user": b["key"],
            "ueba_flags": ["mfa_fatigue_attack"],
            "detail":     f"MFA fatigue: {b['doc_count']} MFA prompts for user {b['key']} in 5 min",
        })
    return detections


def rule_auth_priv_abuse(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Privileged Account Abuse — admin/root logins from unexpected sources"""
    PRIV_ACCOUNTS = ["admin", "root", "Administrator", "domain_admin"]
    SAFE_SUBNETS = ["10.0.99.", "10.0.100."]  # Jump-box / PAM subnets

    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    {"terms": {"raw_event.affected_user.keyword": PRIV_ACCOUNTS}},
                    {"match": {"event.outcome": "success"}},
                ],
            }
        },
    }
    hits = _safe_search(es, "logs-auth", body, "AUTH_PRIV_ABUSE")
    detections = []
    for h in hits:
        src_ip = h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", "")
        if not any(src_ip.startswith(prefix) for prefix in SAFE_SUBNETS):
            detections.append({
                "rule_id":    "AUTH_PRIV_ABUSE",
                "log_type":   "auth",
                "raw_hits":   [h],
                "pivot_ip":   src_ip,
                "pivot_user": h.get("raw_event", {}).get("affected_user"),
                "ueba_flags": ["privileged_account_abuse", "unusual_source"],
                "detail":     f"Privileged account login from unexpected source {src_ip}",
            })
    return detections


# ═════════════════════════════════════════════════════════════════
# 3. ENDPOINT ATTACK RULES  (index: logs-endpoint)
# ═════════════════════════════════════════════════════════════════

def rule_ep_ransomware(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Ransomware Behaviour — mass file mods, .encrypted extensions, VSS deletion"""
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"wildcard": {"process.command_line.keyword": "*.encrypted*"}},
                    {"wildcard": {"process.command_line.keyword": "*.locked*"}},
                    {"match_phrase": {"process.command_line": "vssadmin.exe delete shadows"}},
                    {"match_phrase": {"process.command_line": "vssadmin delete shadows"}},
                    {"match_phrase": {"raw_event.action": "mass_file_modification"}},
                    {"wildcard": {"raw_event.action.keyword": "*ransomware*"}},
                    {"wildcard": {"raw_event.action.keyword": "*.encrypted*"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-endpoint", body, "EP_RANSOMWARE")
    return [{
        "rule_id": "EP_RANSOMWARE", "log_type": "endpoint", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name") or h.get("raw_event", {}).get("affected_user"),
        "ueba_flags": ["mass_file_modification", "ransomware_behavior"],
        "detail": "Ransomware behaviour detected: mass file encryption or VSS deletion",
    } for h in hits]


def rule_ep_lolbin(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Living off the Land / LOLBins — suspicious PowerShell execution"""
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"process.command_line": "-ExecutionPolicy Bypass"}},
                    {"match_phrase": {"process.command_line": "-EncodedCommand"}},
                    {"match_phrase": {"process.command_line": "Invoke-WebRequest"}},
                    {"match_phrase": {"process.command_line": "Invoke-Expression"}},
                    {"match_phrase": {"process.command_line": "IEX"}},
                    {"match_phrase": {"process.command_line": "DownloadString"}},
                    {"match_phrase": {"process.command_line": "-WindowStyle Hidden"}},
                    {"wildcard": {"raw_event.action.keyword": "*powershell*-ExecutionPolicy Bypass*"}},
                    {"wildcard": {"raw_event.action.keyword": "*powershell*-EncodedCommand*"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-endpoint", body, "EP_LOLBIN")
    return [{
        "rule_id": "EP_LOLBIN", "log_type": "endpoint", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name") or h.get("raw_event", {}).get("affected_user"),
        "ueba_flags": ["suspicious_process_arguments"],
        "detail": "Suspicious PowerShell / LOLBin execution detected",
    } for h in hits]


def rule_ep_credential_dump(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Credential Dumping — lsass access, mimikatz, procdump"""
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"process.command_line": "lsass.exe"}},
                    {"match_phrase": {"process.command_line": "mimikatz"}},
                    {"match_phrase": {"process.command_line": "procdump"}},
                    {"match_phrase": {"process.command_line": "sekurlsa::logonpasswords"}},
                    {"match_phrase": {"process.name": "mimikatz.exe"}},
                    {"wildcard": {"process.command_line.keyword": "*procdump*-ma lsass*"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-endpoint", body, "EP_CREDENTIAL_DUMP")
    return [{
        "rule_id": "EP_CREDENTIAL_DUMP", "log_type": "endpoint", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name") or h.get("raw_event", {}).get("affected_user"),
        "ueba_flags": ["credential_dumping"],
        "detail": "Credential dumping technique detected",
    } for h in hits]


def rule_ep_def_evasion(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Defense Evasion — Windows Event Log clearing"""
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"process.command_line": "wevtutil cl Security"}},
                    {"match_phrase": {"process.command_line": "wevtutil cl Setup"}},
                    {"match_phrase": {"process.command_line": "wevtutil cl Application"}},
                    {"match_phrase": {"process.command_line": "Clear-EventLog"}},
                    {"wildcard": {"raw_event.action.keyword": "*wevtutil*cl*"}},
                    {"wildcard": {"raw_event.action.keyword": "*Event Log Cleared*"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-endpoint", body, "EP_DEF_EVASION")
    return [{
        "rule_id": "EP_DEF_EVASION", "log_type": "endpoint", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name") or h.get("raw_event", {}).get("affected_user"),
        "ueba_flags": ["defense_evasion", "log_clearing"],
        "detail": "Windows Event Log clearing detected",
    } for h in hits]


def rule_ep_persistence(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Persistence — Registry Run keys or Scheduled Task creation"""
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "should": [
                    {"match_phrase": {"process.command_line": "CurrentVersion\\Run"}},
                    {"match_phrase": {"process.command_line": "schtasks /create"}},
                    {"match_phrase": {"process.command_line": "schtasks.exe /create"}},
                    {"match_phrase": {"registry.path": "CurrentVersion\\Run"}},
                    {"wildcard": {"raw_event.action.keyword": "*schtasks*/create*"}},
                    {"wildcard": {"raw_event.action.keyword": "*Cron job created*"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-endpoint", body, "EP_PERSISTENCE")
    return [{
        "rule_id": "EP_PERSISTENCE", "log_type": "endpoint", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", ""),
        "pivot_user": h.get("user", {}).get("name") or h.get("raw_event", {}).get("affected_user"),
        "ueba_flags": ["persistence_mechanism"],
        "detail": "Persistence mechanism detected (Run key or Scheduled Task)",
    } for h in hits]


# ═════════════════════════════════════════════════════════════════
# 4. NETWORK ATTACK RULES  (index: logs-network)
# ═════════════════════════════════════════════════════════════════

def rule_net_portscan(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Port Scan — single IP hitting >50 ports on one host (vertical) or sweeping subnet"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip.keyword", "size": 200},
                "aggs": {
                    "unique_ports": {
                        "cardinality": {"field": "destination.port.keyword"}
                    },
                    "unique_dest_ips": {
                        "cardinality": {"field": "destination.ip.keyword"}
                    },
                },
            }
        },
    }
    resp = _safe_agg_search(es, "logs-network", body, "NET_PORTSCAN")
    if not resp:
        return []

    detections = []
    for b in resp.get("aggregations", {}).get("by_source", {}).get("buckets", []):
        ports = b.get("unique_ports", {}).get("value", 0)
        dest_ips = b.get("unique_dest_ips", {}).get("value", 0)
        if ports > 50 or dest_ips > 50:
            detections.append({
                "rule_id":    "NET_PORTSCAN",
                "log_type":   "network",
                "raw_hits":   [],
                "pivot_ip":   b["key"],
                "pivot_user": None,
                "ueba_flags": ["high_connection_rate", "internal_scanning"] if dest_ips > 50 else ["high_connection_rate"],
                "detail":     f"Port scan: {b['key']} → {ports} ports / {dest_ips} destinations",
            })
    return detections


def rule_net_c2_beacon(es: Elasticsearch, time_range: str = "now-15m") -> list[dict]:
    """C2 Beaconing — periodic outbound connections with consistent intervals"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    # Only outbound: source is internal (10.x, 172.16-31.x, 192.168.x)
                ],
            }
        },
        "aggs": {
            "by_pair": {
                "composite": {
                    "size": 200,
                    "sources": [
                        {"src": {"terms": {"field": "source.ip.keyword"}}},
                        {"dst": {"terms": {"field": "destination.ip.keyword"}}},
                    ],
                },
                "aggs": {
                    "conn_count": {"value_count": {"field": "@timestamp"}},
                    "time_stats": {"extended_stats": {"field": "@timestamp"}},
                },
            }
        },
    }
    resp = _safe_agg_search(es, "logs-network", body, "NET_C2_BEACON")
    if not resp:
        return []

    detections = []
    for b in resp.get("aggregations", {}).get("by_pair", {}).get("buckets", []):
        count = b.get("conn_count", {}).get("value", 0)
        std_dev = b.get("time_stats", {}).get("std_deviation", None)
        if count >= 10 and std_dev is not None:
            # Low std_dev in timestamps means highly periodic → beacon
            # std_dev < 5000ms means nearly uniform spacing
            if std_dev < 5000:
                src = b["key"]["src"]
                dst = b["key"]["dst"]
                detections.append({
                    "rule_id":    "NET_C2_BEACON",
                    "log_type":   "network",
                    "raw_hits":   [],
                    "pivot_ip":   src,
                    "pivot_user": None,
                    "ueba_flags": ["periodic_beaconing"],
                    "detail":     f"C2 beaconing: {src} → {dst} ({count} connections, σ={std_dev:.0f}ms)",
                })
    return detections


def rule_net_dns_tunnel(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """DNS Tunneling — long TXT records or high-entropy subdomains"""
    body = {
        "size": 50,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    {"term": {"destination.port": 53}},
                ],
                "should": [
                    {"script": {
                        "script": {
                            "source": "doc['dns.question.name.keyword'].size() > 0 && doc['dns.question.name.keyword'].value.length() > 60",
                            "lang": "painless",
                        }
                    }},
                    {"term": {"dns.question.type": "TXT"}},
                    {"wildcard": {"raw_event.action.keyword": "*DNS TXT*"}},
                    {"wildcard": {"raw_event.action.keyword": "*dns*tunnel*"}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    hits = _safe_search(es, "logs-network", body, "NET_DNS_TUNNEL")
    return [{
        "rule_id": "NET_DNS_TUNNEL", "log_type": "network", "raw_hits": [h],
        "pivot_ip": h.get("source", {}).get("ip") or h.get("raw_event", {}).get("source_ip", ""),
        "pivot_user": None,
        "ueba_flags": ["dns_tunneling_pattern"],
        "detail": "DNS tunneling detected: anomalous DNS TXT/long subdomain queries",
    } for h in hits]


def rule_net_exfil(es: Elasticsearch, time_range: str = "now-10m") -> list[dict]:
    """Data Exfiltration — massive outbound byte transfer to external IPs"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": time_range}}}],
                "must_not": [
                    # Exclude known internal RFC1918
                    {"wildcard": {"destination.ip": "10.*"}},
                    {"wildcard": {"destination.ip": "192.168.*"}},
                    {"wildcard": {"destination.ip": "172.16.*"}},
                ],
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip.keyword", "size": 100},
                "aggs": {
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                },
            }
        },
    }
    resp = _safe_agg_search(es, "logs-network", body, "NET_EXFIL")
    if not resp:
        return []

    THRESHOLD_BYTES = 1_073_741_824  # 1 GB
    detections = []
    for b in resp.get("aggregations", {}).get("by_source", {}).get("buckets", []):
        total = b.get("total_bytes", {}).get("value", 0)
        if total >= THRESHOLD_BYTES:
            gb = total / (1024**3)
            detections.append({
                "rule_id":    "NET_EXFIL",
                "log_type":   "network",
                "raw_hits":   [],
                "pivot_ip":   b["key"],
                "pivot_user": None,
                "ueba_flags": ["high_volume_outbound", "data_exfiltration"],
                "detail":     f"Data exfiltration: {b['key']} transferred {gb:.2f} GB outbound in 10 min",
            })
    return detections


def rule_net_lateral(es: Elasticsearch, time_range: str = "now-5m") -> list[dict]:
    """Lateral Movement — rapid internal SMB/RDP spread"""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range}}},
                    {"terms": {"destination.port": [445, 3389, 5985, 135]}},
                ],
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip.keyword", "size": 100},
                "aggs": {
                    "unique_targets": {
                        "cardinality": {"field": "destination.ip.keyword"}
                    }
                },
            }
        },
    }
    resp = _safe_agg_search(es, "logs-network", body, "NET_LATERAL")
    if not resp:
        return []

    detections = []
    for b in resp.get("aggregations", {}).get("by_source", {}).get("buckets", []):
        targets = b.get("unique_targets", {}).get("value", 0)
        if targets > 5:
            detections.append({
                "rule_id":    "NET_LATERAL",
                "log_type":   "network",
                "raw_hits":   [],
                "pivot_ip":   b["key"],
                "pivot_user": None,
                "ueba_flags": ["lateral_movement_pattern"],
                "detail":     f"Lateral movement: {b['key']} → {targets} internal targets via SMB/RDP/WMI",
            })
    return detections


# ═════════════════════════════════════════════════════════════════
# MASTER RUNNER
# ═════════════════════════════════════════════════════════════════

ALL_RULES = [
    # Web
    rule_web_sqli,
    rule_web_cmdi,
    rule_web_lfi,
    rule_web_xss,
    rule_web_scanner,
    rule_web_ssrf,
    # Auth
    rule_auth_bruteforce,
    rule_auth_spray,
    rule_auth_mfa_fatigue,
    rule_auth_priv_abuse,
    # Endpoint
    rule_ep_ransomware,
    rule_ep_lolbin,
    rule_ep_credential_dump,
    rule_ep_def_evasion,
    rule_ep_persistence,
    # Network
    rule_net_portscan,
    rule_net_c2_beacon,
    rule_net_dns_tunnel,
    rule_net_exfil,
    rule_net_lateral,
]


def run_all_rules(es: Elasticsearch) -> list[dict]:
    """
    Executes every detection rule against Elasticsearch.
    Returns a flat list of all detections.
    """
    all_detections: list[dict] = []
    for rule_fn in ALL_RULES:
        try:
            detections = rule_fn(es)
            if detections:
                print(f"[L2-RULES] DETECT {rule_fn.__name__}] triggered {len(detections)} detection(s)")
                all_detections.extend(detections)
        except Exception as e:
            print(f"[L2-RULES] WARN RulesEngine] Rule {rule_fn.__name__} crashed: {e}")
    return all_detections
