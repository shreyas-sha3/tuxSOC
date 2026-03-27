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


def _lookup_by_technique_id(technique_id: str, db_path: str) -> dict | None:
    """
    Direct technique_id lookup — bypasses keyword search entirely.
    Queries the mitre_mappings table by technique_id column directly.
    """
    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM mitre_mappings WHERE technique_id = ? AND 1=1",
            (technique_id.strip().upper(),)
        )
        row = cur.fetchone()
        conn.close()
        if row:
            return dict(row)
    except Exception as e:
        logger.warning("Direct technique_id lookup failed: %s", e)
    return None


def map_to_mitre(
        ioc_matches: list[str],
        ueba_flags: list[str],
        db_path: str = DEFAULT_DB_PATH,
        raw_event: dict | None = None
    ) -> dict:

    # ── STEP 1 — direct technique_id from raw_event ──────────────────
    if raw_event:
        technique = str(raw_event.get("mitre_technique") or "").strip().upper()
        logger.debug("MITRE technique from event: %s", technique)

        if technique and technique not in ("", "T0000"):

            # Direct DB lookup by technique_id column
            hit = _lookup_by_technique_id(technique, db_path)

            if hit:
                return {
                    "mitre_tactic":         hit["tactic"],
                    "mitre_technique":      hit["technique_id"],
                    "mitre_technique_name": hit["technique_name"],
                    "all_techniques": [{
                        "technique_id":   hit["technique_id"],
                        "technique_name": hit["technique_name"],
                        "tactic":         hit["tactic"],
                        "signal":         "direct_event_mapping"
                    }]
                }

            # DB miss — inline fallback by technique_id
            _ID_FALLBACK = {
                "T1110": ("Credential Access",   "Brute Force"),
                "T1078": ("Defense Evasion",     "Valid Accounts"),
                "T1041": ("Exfiltration",        "Exfiltration Over C2 Channel"),
                "T1059": ("Execution",           "Command and Scripting"),
                "T1021": ("Lateral Movement",    "Remote Services"),
                "T1071": ("Command and Control", "App Layer Protocol"),
                "T1055": ("Defense Evasion",     "Process Injection"),
                "T1498": ("Impact",              "Network DoS"),
                "T1557": ("Credential Access",   "Adversary-in-the-Middle"),
                "T1565": ("Impact",              "Data Manipulation"),
                "T1133": ("Persistence",         "External Remote Services"),
                "T1190": ("Initial Access",      "Exploit Public-Facing"),
            }
            if technique in _ID_FALLBACK:
                tactic, tname = _ID_FALLBACK[technique]
                return {
                    "mitre_tactic":         tactic,
                    "mitre_technique":      technique,
                    "mitre_technique_name": tname,
                    "all_techniques": [{
                        "technique_id": technique, "technique_name": tname,
                        "tactic": tactic, "signal": "direct_event_mapping_fallback"
                    }]
                }

    # ──────────────────────────────────────────────────────────
    # STEP 2 — build candidate techniques from signals
    # ──────────────────────────────────────────────────────────

    all_signals = list(dict.fromkeys(ioc_matches + ueba_flags))

    if not all_signals:
        return {
            "mitre_tactic": "Unknown",
            "mitre_technique": "T0000",
            "mitre_technique_name": "Unknown",
            "all_techniques": []
        }

    technique_scores = {}

    for signal in all_signals:
        db_hits = lookup_mitre(
            keyword=signal.replace("_", " "),
            db_path=db_path
        )

        if not db_hits and signal in _FALLBACK_MAP:
            tid, tactic, tname = _FALLBACK_MAP[signal]
            db_hits = [{"technique_id": tid, "tactic": tactic, "technique_name": tname}]

        for hit in db_hits:
            tid = hit["technique_id"]
            if tid not in technique_scores:
                technique_scores[tid] = {
                    "score": 0.0,
                    "tactic": hit["tactic"],
                    "technique_name": hit["technique_name"],
                    "signals": []
                }
            # Add score based on signal type
            if signal in ioc_matches:
                technique_scores[tid]["score"] += 0.5
            elif signal in ueba_flags:
                technique_scores[tid]["score"] += 0.3
            technique_scores[tid]["signals"].append(signal)

    # Add anomaly context if present
    anomaly_bonus = 0.0
    if raw_event and raw_event.get("anomaly_score", 0) > 0.7:
        anomaly_bonus = 0.2
        for tid in technique_scores:
            technique_scores[tid]["score"] += anomaly_bonus

    logger.debug("MITRE candidate techniques: %s", technique_scores)

    if not technique_scores:
        return {
            "mitre_tactic": "Unknown",
            "mitre_technique": "T0000",
            "mitre_technique_name": "Unknown",
            "all_techniques": []
        }

    # Find the technique with the highest score
    best_tid = max(technique_scores, key=lambda tid: technique_scores[tid]["score"])
    best = technique_scores[best_tid]

    logger.debug("MITRE selected technique: %s", best)

    # Build ranked list
    ranked_list = [
        {"technique_id": tid, "score": data["score"]}
        for tid, data in sorted(technique_scores.items(), key=lambda x: x[1]["score"], reverse=True)
    ]

    return {
        "mitre_tactic": best["tactic"],
        "mitre_technique": best_tid,
        "mitre_technique_name": best["technique_name"],
        "all_techniques": ranked_list
    }