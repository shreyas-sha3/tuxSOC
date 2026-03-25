"""
mitre_mapper.py
---------------
Maps IOC matches and UEBA flags to MITRE ATT&CK tactics and techniques.

Priority order:
1) Direct MITRE technique from raw event (highest confidence)
2) IOC matches
3) UEBA behavioural flags
4) Static fallback map
"""

import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ioc_database"))

from ioc_db import lookup_mitre, DEFAULT_DB_PATH

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Static fallback mapping if DB lookup fails
# ──────────────────────────────────────────────────────────────

_FALLBACK_MAP = {

    "malicious_ip": ("T1071", "Command and Control", "App Layer Protocol"),
    "suspicious_domain": ("T1071", "Command and Control", "App Layer Protocol"),

    "malicious_file_hash": ("T1059", "Execution", "Command and Scripting"),
    "suspicious_process": ("T1059", "Execution", "Command and Scripting"),

    "off_hours_activity": ("T1078", "Defense Evasion", "Valid Accounts"),

    "excessive_failed_logins": ("T1110", "Credential Access", "Brute Force"),

    "lateral_movement_indicator": ("T1021", "Lateral Movement", "Remote Services"),

    "privilege_escalation": (
        "T1068",
        "Privilege Escalation",
        "Exploitation for Privilege Escalation"
    ),

    "suspicious_process_chain": ("T1059", "Execution", "Command and Scripting"),

    "large_data_transfer": ("T1041", "Exfiltration", "Exfiltration Over C2 Channel"),

    "impossible_travel": ("T1078", "Defense Evasion", "Valid Accounts"),
}


# ──────────────────────────────────────────────────────────────
# Main mapper
# ──────────────────────────────────────────────────────────────

def map_to_mitre(
        ioc_matches: list[str],
        ueba_flags: list[str],
        db_path: str = DEFAULT_DB_PATH,
        raw_event: dict | None = None
    ) -> dict:

    # ──────────────────────────────────────────────────────────
    # STEP 1 — direct MITRE technique from event
    # ──────────────────────────────────────────────────────────

    if raw_event:

        technique = raw_event.get("mitre_technique")

        if technique:

            db_hits = lookup_mitre(keyword=technique, db_path=db_path)

            if db_hits:

                hit = db_hits[0]

                return {
                    "mitre_tactic": hit["tactic"],
                    "mitre_technique": hit["technique_id"],
                    "mitre_technique_name": hit["technique_name"],
                    "all_techniques": [
                        {
                            "technique_id": hit["technique_id"],
                            "technique_name": hit["technique_name"],
                            "tactic": hit["tactic"],
                            "signal": "direct_event_mapping"
                        }
                    ]
                }

    # ──────────────────────────────────────────────────────────
    # STEP 2 — combine IOC + UEBA signals
    # ──────────────────────────────────────────────────────────

    all_signals = list(dict.fromkeys(ioc_matches + ueba_flags))

    if not all_signals:
        return {
            "mitre_tactic": "Unknown",
            "mitre_technique": "T0000",
            "mitre_technique_name": "Unknown",
            "all_techniques": []
        }

    found_techniques = []

    # ──────────────────────────────────────────────────────────
    # STEP 3 — database lookup
    # ──────────────────────────────────────────────────────────

    for signal in all_signals:

        db_hits = lookup_mitre(
            keyword=signal.replace("_", " "),
            db_path=db_path
        )

        if db_hits:

            for hit in db_hits:

                entry = {
                    "technique_id": hit["technique_id"],
                    "technique_name": hit["technique_name"],
                    "tactic": hit["tactic"],
                    "signal": signal
                }

                if entry not in found_techniques:
                    found_techniques.append(entry)

        # ──────────────────────────────────────────────────────
        # STEP 4 — fallback mapping
        # ──────────────────────────────────────────────────────

        elif signal in _FALLBACK_MAP:

            tid, tactic, tname = _FALLBACK_MAP[signal]

            entry = {
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "signal": signal
            }

            if entry not in found_techniques:
                found_techniques.append(entry)

    if not found_techniques:
        return {
            "mitre_tactic": "Unknown",
            "mitre_technique": "T0000",
            "mitre_technique_name": "Unknown",
            "all_techniques": []
        }

    # ──────────────────────────────────────────────────────────
    # STEP 5 — choose primary technique
    # IOC > UEBA priority
    # ──────────────────────────────────────────────────────────

    primary = found_techniques[0]

    return {
        "mitre_tactic": primary["tactic"],
        "mitre_technique": primary["technique_id"],
        "mitre_technique_name": primary["technique_name"],
        "all_techniques": found_techniques
    }