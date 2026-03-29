"""
rules_registry.py
-----------------
All 20 detection rules defined as structured metadata.
Rules are loaded dynamically and can be enabled/disabled at runtime.
"""

from typing import Optional

# ── Rule schema ────────────────────────────────────────────────────────────
# rule_id      : unique identifier
# category     : web | auth | endpoint | network
# mitre        : primary ATT&CK technique ID
# severity     : low | medium | high | critical
# risk_weight  : 0.0–1.0 contribution to risk score
# cooldown     : suppression window in seconds
# confidence   : base detection confidence 0.0–1.0
# index        : Elasticsearch index to query
# enabled      : bool

RULES: list[dict] = [

    # ── WEB ───────────────────────────────────────────────────────────
    {
        "rule_id":     "WEB_SQLI",
        "name":        "SQL Injection Attempt",
        "category":    "web",
        "mitre":       "T1190",
        "severity":    "high",
        "risk_weight": 0.80,
        "cooldown":    60,
        "confidence":  0.85,
        "index":       "logs-web",
        "enabled":     True,
    },
    {
        "rule_id":     "WEB_CMDI",
        "name":        "Command Injection Attempt",
        "category":    "web",
        "mitre":       "T1059",
        "severity":    "critical",
        "risk_weight": 0.90,
        "cooldown":    60,
        "confidence":  0.88,
        "index":       "logs-web",
        "enabled":     True,
    },
    {
        "rule_id":     "WEB_LFI",
        "name":        "Local File Inclusion Attempt",
        "category":    "web",
        "mitre":       "T1190",
        "severity":    "high",
        "risk_weight": 0.75,
        "cooldown":    60,
        "confidence":  0.82,
        "index":       "logs-web",
        "enabled":     True,
    },
    {
        "rule_id":     "WEB_XSS",
        "name":        "Cross-Site Scripting Attempt",
        "category":    "web",
        "mitre":       "T1189",
        "severity":    "medium",
        "risk_weight": 0.55,
        "cooldown":    120,
        "confidence":  0.75,
        "index":       "logs-web",
        "enabled":     True,
    },
    {
        "rule_id":     "WEB_SCANNER",
        "name":        "Web Scanner Detected",
        "category":    "web",
        "mitre":       "T1595.002",
        "severity":    "medium",
        "risk_weight": 0.50,
        "cooldown":    300,
        "confidence":  0.90,
        "index":       "logs-web",
        "enabled":     True,
    },
    {
        "rule_id":     "WEB_SSRF",
        "name":        "Server-Side Request Forgery Attempt",
        "category":    "web",
        "mitre":       "T1190",
        "severity":    "high",
        "risk_weight": 0.80,
        "cooldown":    60,
        "confidence":  0.87,
        "index":       "logs-web",
        "enabled":     True,
    },

    # ── AUTH ──────────────────────────────────────────────────────────
    {
        "rule_id":     "AUTH_BRUTEFORCE",
        "name":        "Authentication Brute Force",
        "category":    "auth",
        "mitre":       "T1110",
        "severity":    "high",
        "risk_weight": 0.80,
        "cooldown":    300,
        "confidence":  0.90,
        "index":       "logs-auth",
        "enabled":     True,
    },
    {
        "rule_id":     "AUTH_SPRAY",
        "name":        "Password Spray Attack",
        "category":    "auth",
        "mitre":       "T1110.003",
        "severity":    "high",
        "risk_weight": 0.80,
        "cooldown":    300,
        "confidence":  0.88,
        "index":       "logs-auth",
        "enabled":     True,
    },
    {
        "rule_id":     "AUTH_MFA_FATIGUE",
        "name":        "MFA Fatigue Attack",
        "category":    "auth",
        "mitre":       "T1621",
        "severity":    "high",
        "risk_weight": 0.85,
        "cooldown":    300,
        "confidence":  0.82,
        "index":       "logs-auth",
        "enabled":     True,
    },
    {
        "rule_id":     "AUTH_PRIV_ABUSE",
        "name":        "Privileged Account Abuse",
        "category":    "auth",
        "mitre":       "T1078",
        "severity":    "high",
        "risk_weight": 0.85,
        "cooldown":    600,
        "confidence":  0.80,
        "index":       "logs-auth",
        "enabled":     True,
    },

    # ── ENDPOINT ──────────────────────────────────────────────────────
    {
        "rule_id":     "EP_RANSOMWARE",
        "name":        "Ransomware Activity Detected",
        "category":    "endpoint",
        "mitre":       "T1486",
        "severity":    "critical",
        "risk_weight": 1.00,
        "cooldown":    60,
        "confidence":  0.92,
        "index":       "logs-endpoint",
        "enabled":     True,
    },
    {
        "rule_id":     "EP_LOLBIN",
        "name":        "Living-off-the-Land Binary Abuse",
        "category":    "endpoint",
        "mitre":       "T1059.001",
        "severity":    "high",
        "risk_weight": 0.80,
        "cooldown":    120,
        "confidence":  0.85,
        "index":       "logs-endpoint",
        "enabled":     True,
    },
    {
        "rule_id":     "EP_CREDENTIAL_DUMP",
        "name":        "Credential Dumping Detected",
        "category":    "endpoint",
        "mitre":       "T1003",
        "severity":    "critical",
        "risk_weight": 0.95,
        "cooldown":    60,
        "confidence":  0.93,
        "index":       "logs-endpoint",
        "enabled":     True,
    },
    {
        "rule_id":     "EP_DEF_EVASION",
        "name":        "Defense Evasion — Log Clearing",
        "category":    "endpoint",
        "mitre":       "T1070.001",
        "severity":    "high",
        "risk_weight": 0.85,
        "cooldown":    120,
        "confidence":  0.90,
        "index":       "logs-endpoint",
        "enabled":     True,
    },
    {
        "rule_id":     "EP_PERSISTENCE",
        "name":        "Persistence Mechanism Installed",
        "category":    "endpoint",
        "mitre":       "T1547.001",
        "severity":    "high",
        "risk_weight": 0.80,
        "cooldown":    300,
        "confidence":  0.85,
        "index":       "logs-endpoint",
        "enabled":     True,
    },

    # ── NETWORK ───────────────────────────────────────────────────────
    {
        "rule_id":     "NET_PORTSCAN",
        "name":        "Port Scan Detected",
        "category":    "network",
        "mitre":       "T1046",
        "severity":    "medium",
        "risk_weight": 0.60,
        "cooldown":    300,
        "confidence":  0.88,
        "index":       "logs-network",
        "enabled":     True,
    },
    {
        "rule_id":     "NET_C2_BEACON",
        "name":        "C2 Beacon Pattern Detected",
        "category":    "network",
        "mitre":       "T1071.001",
        "severity":    "critical",
        "risk_weight": 0.95,
        "cooldown":    120,
        "confidence":  0.80,
        "index":       "logs-network",
        "enabled":     True,
    },
    {
        "rule_id":     "NET_DNS_TUNNEL",
        "name":        "DNS Tunneling Detected",
        "category":    "network",
        "mitre":       "T1071.004",
        "severity":    "high",
        "risk_weight": 0.85,
        "cooldown":    300,
        "confidence":  0.78,
        "index":       "logs-network",
        "enabled":     True,
    },
    {
        "rule_id":     "NET_EXFIL",
        "name":        "Large Data Exfiltration Detected",
        "category":    "network",
        "mitre":       "T1048",
        "severity":    "critical",
        "risk_weight": 0.95,
        "cooldown":    300,
        "confidence":  0.90,
        "index":       "logs-network",
        "enabled":     True,
    },
    {
        "rule_id":     "NET_LATERAL",
        "name":        "Lateral Movement via SMB/RDP",
        "category":    "network",
        "mitre":       "T1021",
        "severity":    "high",
        "risk_weight": 0.85,
        "cooldown":    300,
        "confidence":  0.87,
        "index":       "logs-network",
        "enabled":     True,
    },
]

# ── Registry helpers ───────────────────────────────────────────────────────

_REGISTRY: dict[str, dict] = {r["rule_id"]: r for r in RULES}


def get_rule(rule_id: str) -> Optional[dict]:
    return _REGISTRY.get(rule_id)


def get_enabled_rules() -> list[dict]:
    return [r for r in RULES if r.get("enabled", True)]


def get_rules_by_category(category: str) -> list[dict]:
    return [r for r in get_enabled_rules() if r["category"] == category]


def disable_rule(rule_id: str):
    if rule_id in _REGISTRY:
        _REGISTRY[rule_id]["enabled"] = False


def enable_rule(rule_id: str):
    if rule_id in _REGISTRY:
        _REGISTRY[rule_id]["enabled"] = True
