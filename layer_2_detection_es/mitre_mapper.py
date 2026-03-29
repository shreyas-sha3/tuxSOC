"""
mitre_mapper.py
---------------
Maps rule IDs and detection types to MITRE ATT&CK techniques.
Provides enriched technique objects with name, tactic, and URL.
"""

# Full technique reference — expanded coverage
_TECHNIQUES: dict[str, dict] = {
    # ── Initial Access ────────────────────────────────────────────────
    "T1190":     {"name": "Exploit Public-Facing Application",                  "tactic": "Initial Access"},
    "T1189":     {"name": "Drive-by Compromise",                                "tactic": "Initial Access"},
    "T1566":     {"name": "Phishing",                                           "tactic": "Initial Access"},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment",                 "tactic": "Initial Access"},
    "T1133":     {"name": "External Remote Services",                           "tactic": "Initial Access"},
    # ── Reconnaissance ────────────────────────────────────────────────
    "T1595":     {"name": "Active Scanning",                                    "tactic": "Reconnaissance"},
    "T1595.002": {"name": "Active Scanning: Vulnerability Scanning",            "tactic": "Reconnaissance"},
    "T1592":     {"name": "Gather Victim Host Information",                     "tactic": "Reconnaissance"},
    # ── Execution ─────────────────────────────────────────────────────
    "T1059":     {"name": "Command and Scripting Interpreter",                  "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell",                                         "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell",                              "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell",                                         "tactic": "Execution"},
    # ── Persistence ───────────────────────────────────────────────────
    "T1547":     {"name": "Boot or Logon Autostart Execution",                  "tactic": "Persistence"},
    "T1547.001": {"name": "Boot or Logon Autostart: Registry Run Keys",         "tactic": "Persistence"},
    "T1053":     {"name": "Scheduled Task/Job",                                 "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task",                                     "tactic": "Persistence"},
    # ── Privilege Escalation ──────────────────────────────────────────
    "T1055":     {"name": "Process Injection",                                  "tactic": "Defense Evasion"},
    "T1078":     {"name": "Valid Accounts",                                     "tactic": "Defense Evasion"},
    # ── Defense Evasion ───────────────────────────────────────────────
    "T1070":     {"name": "Indicator Removal",                                  "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs",        "tactic": "Defense Evasion"},
    "T1218":     {"name": "Signed Binary Proxy Execution",                      "tactic": "Defense Evasion"},
    "T1218.011": {"name": "Signed Binary Proxy Execution: Rundll32",            "tactic": "Defense Evasion"},
    # ── Credential Access ─────────────────────────────────────────────
    "T1110":     {"name": "Brute Force",                                        "tactic": "Credential Access"},
    "T1110.001": {"name": "Brute Force: Password Guessing",                     "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying",                                  "tactic": "Credential Access"},
    "T1003":     {"name": "OS Credential Dumping",                              "tactic": "Credential Access"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory",                "tactic": "Credential Access"},
    "T1621":     {"name": "Multi-Factor Authentication Request Generation",      "tactic": "Credential Access"},
    # ── Discovery ─────────────────────────────────────────────────────
    "T1046":     {"name": "Network Service Discovery",                          "tactic": "Discovery"},
    "T1082":     {"name": "System Information Discovery",                       "tactic": "Discovery"},
    "T1083":     {"name": "File and Directory Discovery",                       "tactic": "Discovery"},
    # ── Lateral Movement ──────────────────────────────────────────────
    "T1021":     {"name": "Remote Services",                                    "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol",           "tactic": "Lateral Movement"},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares",          "tactic": "Lateral Movement"},
    # ── Collection ────────────────────────────────────────────────────
    "T1560":     {"name": "Archive Collected Data",                             "tactic": "Collection"},
    "T1074":     {"name": "Data Staged",                                        "tactic": "Collection"},
    # ── Command and Control ───────────────────────────────────────────
    "T1071":     {"name": "Application Layer Protocol",                         "tactic": "Command and Control"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols",          "tactic": "Command and Control"},
    "T1071.004": {"name": "Application Layer Protocol: DNS",                    "tactic": "Command and Control"},
    "T1105":     {"name": "Ingress Tool Transfer",                              "tactic": "Command and Control"},
    # ── Exfiltration ──────────────────────────────────────────────────
    "T1041":     {"name": "Exfiltration Over C2 Channel",                       "tactic": "Exfiltration"},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol",             "tactic": "Exfiltration"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol",      "tactic": "Exfiltration"},
    # ── Impact ────────────────────────────────────────────────────────
    "T1486":     {"name": "Data Encrypted for Impact",                          "tactic": "Impact"},
    "T1490":     {"name": "Inhibit System Recovery",                            "tactic": "Impact"},
    "T1498":     {"name": "Network Denial of Service",                          "tactic": "Impact"},
}

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


def get_technique(technique_id: str) -> dict:
    """Return enriched technique object for a given technique ID."""
    info = _TECHNIQUES.get(technique_id, {})
    return {
        "technique_id":   technique_id,
        "technique_name": info.get("name", "Unknown"),
        "tactic":         info.get("tactic", "Unknown"),
        "url":            _MITRE_BASE_URL + technique_id.replace(".", "/"),
    }


def map_detections_to_mitre(detections: list[dict]) -> list[dict]:
    """
    Given a list of detection dicts (each with a 'mitre' field),
    return a deduplicated list of enriched MITRE technique objects.
    """
    seen: set = set()
    techniques: list[dict] = []
    for det in detections:
        tid = det.get("mitre", "")
        if tid and tid not in seen:
            seen.add(tid)
            techniques.append(get_technique(tid))
    return techniques


def map_rule_to_mitre(rule_id: str) -> dict | None:
    """Look up the MITRE technique for a rule by rule_id."""
    from layer_2_detection_es.rules_registry import get_rule
    rule = get_rule(rule_id)
    if not rule:
        return None
    return get_technique(rule["mitre"])


def get_tactics_for_techniques(technique_ids: list[str]) -> list[str]:
    """Return unique tactic names for a list of technique IDs."""
    seen = set()
    tactics = []
    for tid in technique_ids:
        info = _TECHNIQUES.get(tid, {})
        tactic = info.get("tactic", "")
        if tactic and tactic not in seen:
            seen.add(tactic)
            tactics.append(tactic)
    return tactics
