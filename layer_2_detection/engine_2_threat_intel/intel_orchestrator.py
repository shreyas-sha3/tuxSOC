"""
intel_orchestrator.py
---------------------
Engine 2 orchestrator. Coordinates ioc_matcher and mitre_mapper,
combines outputs into the engine_2_threat_intel block.

Only called by detection_orchestrator if anomaly_score >= threshold.
"""

import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../ioc_database"))

import ioc_matcher
import mitre_mapper
from ioc_db import DEFAULT_DB_PATH

logger = logging.getLogger(__name__)


def run(raw_event: dict,
        log_type: str,
        anomaly_score: float,
        ueba_flags: list[str],
        db_path: str = DEFAULT_DB_PATH) -> dict:
    """
    Run Engine 2: IOC matching + MITRE mapping.

    Args:
        raw_event     : Normalized event fields
        log_type      : 'endpoint' | 'network' | 'iot' | 'auth' | 'firewall'
        anomaly_score : From Engine 1
        ueba_flags    : UEBA behavioural flags
        db_path       : SQLite DB path

    Returns engine_2_threat_intel block:
        {
          "ioc_matches": list[str],
          "matched_ioc_details": list[dict],
          "iot_threshold_hits": list[dict],
          "threat_intel_match": bool,

          "mitre_tactic": str,
          "mitre_technique": str,
          "mitre_technique_name": str,
          "all_techniques": list
        }
    """

    logger.debug("Engine 2 starting for log_type=%s", log_type)

    # STEP 1 — IOC matching
    match_result = ioc_matcher.match(
        raw_event=raw_event,
        log_type=log_type,
        anomaly_score=anomaly_score,
        db_path=db_path
    )

    # STEP 2 — MITRE mapping (IOC signals + UEBA signals)
    mitre_result = mitre_mapper.map_to_mitre(
        ioc_matches=match_result.get("ioc_matches", []),
        ueba_flags=ueba_flags,
        db_path=db_path,
        raw_event=raw_event
    )

    # STEP 3 — Merge results
    result = {
        "ioc_matches": match_result.get("ioc_matches", []),
        "matched_ioc_details": match_result.get("matched_ioc_details", []),
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