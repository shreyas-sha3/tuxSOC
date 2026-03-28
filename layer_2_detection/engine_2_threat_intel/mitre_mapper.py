# mitre_mapper.py
# Location: layer_2_detection/engine_2_threat_intel/mitre_mapper.py
# ─────────────────────────────────────────────────────────────────
# Maps rule IDs from the Rules Engine to their MITRE ATT&CK
# Tactic / Technique / Technique Name for downstream enrichment.
# ─────────────────────────────────────────────────────────────────

MITRE_MAP: dict[str, dict] = {
    # ── Web Attacks ──────────────────────────────────────────
    "WEB_SQLI":        {"tactic": "Initial Access",      "technique": "T1190",      "name": "Exploit Public-Facing Application"},
    "WEB_CMDI":        {"tactic": "Execution",            "technique": "T1059",      "name": "Command and Scripting Interpreter"},
    "WEB_LFI":         {"tactic": "Initial Access",      "technique": "T1190",      "name": "Exploit Public-Facing Application"},
    "WEB_XSS":         {"tactic": "Initial Access",      "technique": "T1189",      "name": "Drive-by Compromise"},
    "WEB_SCANNER":     {"tactic": "Reconnaissance",      "technique": "T1595.002",  "name": "Vulnerability Scanning"},
    "WEB_SSRF":        {"tactic": "Initial Access",      "technique": "T1190",      "name": "Exploit Public-Facing Application"},

    # ── Auth Attacks ─────────────────────────────────────────
    "AUTH_BRUTEFORCE":     {"tactic": "Credential Access",   "technique": "T1110",      "name": "Brute Force"},
    "AUTH_SPRAY":          {"tactic": "Credential Access",   "technique": "T1110.003",  "name": "Password Spraying"},
    "AUTH_MFA_FATIGUE":    {"tactic": "Credential Access",   "technique": "T1621",      "name": "Multi-Factor Authentication Request Generation"},
    "AUTH_PRIV_ABUSE":     {"tactic": "Privilege Escalation","technique": "T1078",      "name": "Valid Accounts"},

    # ── Endpoint Attacks ─────────────────────────────────────
    "EP_RANSOMWARE":       {"tactic": "Impact",             "technique": "T1486",      "name": "Data Encrypted for Impact"},
    "EP_LOLBIN":           {"tactic": "Execution",          "technique": "T1059.001",  "name": "PowerShell"},
    "EP_CREDENTIAL_DUMP":  {"tactic": "Credential Access",  "technique": "T1003",      "name": "OS Credential Dumping"},
    "EP_DEF_EVASION":      {"tactic": "Defense Evasion",    "technique": "T1070.001",  "name": "Clear Windows Event Logs"},
    "EP_PERSISTENCE":      {"tactic": "Persistence",        "technique": "T1547.001",  "name": "Registry Run Keys / Startup Folder"},

    # ── Network Attacks ──────────────────────────────────────
    "NET_PORTSCAN":        {"tactic": "Discovery",          "technique": "T1046",      "name": "Network Service Discovery"},
    "NET_C2_BEACON":       {"tactic": "Command and Control","technique": "T1071.001",  "name": "Web Protocols"},
    "NET_DNS_TUNNEL":      {"tactic": "Command and Control","technique": "T1071.004",  "name": "DNS"},
    "NET_EXFIL":           {"tactic": "Exfiltration",       "technique": "T1048",      "name": "Exfiltration Over Alternative Protocol"},
    "NET_LATERAL":         {"tactic": "Lateral Movement",   "technique": "T1021",      "name": "Remote Services"},
}


def get_mitre_mapping(rule_id: str) -> dict:
    """
    Returns the MITRE ATT\u0026CK enrichment dict for a given rule_id.
    Falls back to 'Unknown' if the rule is not in the map.
    """
    mapping = MITRE_MAP.get(rule_id)
    if mapping:
        return {
            "mitre_tactic":         mapping["tactic"],
            "mitre_technique":      mapping["technique"],
            "mitre_technique_name": mapping["name"],
        }
    return {
        "mitre_tactic":         "Unknown",
        "mitre_technique":      "Unknown",
        "mitre_technique_name": "Unknown",
    }
