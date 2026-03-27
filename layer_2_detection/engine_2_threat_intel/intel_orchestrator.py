"""
intel_orchestrator.py
Engine 2: IOC + MITRE mapping
"""

import logging
import sys
import os
import sqlite3

# allow DB imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../ioc_database"))

from engine_2_threat_intel import ioc_matcher
from engine_2_threat_intel import mitre_mapper
from ioc_db import DEFAULT_DB_PATH

logger = logging.getLogger(__name__)


def lookup_mitre_name(technique_id: str, db_path: str):
    """Fetch technique name from MITRE table."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute(
            "SELECT technique_name FROM mitre_mappings WHERE technique_id=?",
            (technique_id,)
        )

        row = cur.fetchone()
        conn.close()

        if row:
            return row[0]

    except Exception as e:
        logger.warning("MITRE lookup failed: %s", e)

    return ""


def run(raw_event: dict,
        log_type: str,
        anomaly_score: float,
        ueba_flags: list[str],
        db_path: str = DEFAULT_DB_PATH) -> dict:

    logger.debug("Engine 2 starting for log_type=%s", log_type)

    # STEP 1 — IOC MATCHING
    match_result = ioc_matcher.match(
        raw_event=raw_event,
        log_type=log_type,
        anomaly_score=anomaly_score,
        db_path=db_path
    )

    ioc_matches = match_result.get("ioc_matches", [])
    ioc_details = match_result.get("matched_ioc_details", [])

    mitre_result = None

    # STEP 2 — DIRECT MITRE FROM IOC
    if ioc_details:

        first = ioc_details[0]

        mitre_tactic = first.get("mitre_tactic")
        mitre_technique = first.get("mitre_technique")

        if mitre_technique and mitre_technique != "T0000":

            technique_name = lookup_mitre_name(mitre_technique, db_path)

            mitre_result = {
                "mitre_tactic": mitre_tactic,
                "mitre_technique": mitre_technique,
                "mitre_technique_name": technique_name,
                "all_techniques": [
                    {
                        "technique_id": mitre_technique,
                        "tactic": mitre_tactic,
                        "signal": "ioc_direct"
                    }
                ]
            }

    # STEP 3 — FALLBACK MITRE MAPPER
    if not mitre_result:

        mitre_result = mitre_mapper.map_to_mitre(
            ioc_matches=ioc_matches,
            ueba_flags=ueba_flags,
            db_path=db_path,
            raw_event=raw_event
        )

    # STEP 4 — FINAL RESULT
    result = {
        "ioc_matches": ioc_matches,
        "matched_ioc_details": ioc_details,
        "iot_threshold_hits": match_result.get("iot_threshold_hits", []),
        "threat_intel_match": match_result.get("threat_intel_match", False),

        "mitre_tactic": mitre_result.get("mitre_tactic"),
        "mitre_technique": mitre_result.get("mitre_technique"),
        "mitre_technique_name": mitre_result.get("mitre_technique_name"),
        "all_techniques": mitre_result.get("all_techniques", [])
    }

    logger.debug(
        "Engine 2 complete — IOC=%s MITRE=%s",
        result["ioc_matches"],
        result["mitre_technique"]
    )

    return result