# intel_orchestrator.py
# Location: layer_2_detection/engine_2_threat_intel/intel_orchestrator.py
# ─────────────────────────────────────────────────────────────────
# Thin orchestration wrapper. Given a raw ES hit, runs IOC matching
# and MITRE mapping, returning the full engine_2_threat_intel block.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from typing import Optional
from elasticsearch import Elasticsearch

from layer_2_detection.engine_2_threat_intel.ioc_matcher import match_iocs
from layer_2_detection.engine_2_threat_intel.mitre_mapper import get_mitre_mapping


def enrich_threat_intel(
    raw_event: dict,
    rule_id: str,
    es_client: Optional[Elasticsearch] = None,
) -> dict:
    """
    Produces the `engine_2_threat_intel` block for a single event.

    Parameters
    ----------
    raw_event : dict
        The normalised raw_event dict (source_ip, destination_ip, …).
    rule_id : str
        The detection rule that fired (e.g. "WEB_SQLI", "AUTH_BRUTEFORCE").
    es_client : Elasticsearch, optional
        Live ES client for IOC feed look-ups.

    Returns
    -------
    dict
        A dict matching the Layer 3 contract:
        {
            "ioc_matches": [...],
            "threat_intel_match": bool,
            "mitre_tactic": str,
            "mitre_technique": str,
            "mitre_technique_name": str,
        }
    """
    # IOC enrichment
    ioc_result = match_iocs(
        source_ip=raw_event.get("source_ip"),
        destination_ip=raw_event.get("destination_ip"),
        es_client=es_client,
    )

    # MITRE mapping
    mitre = get_mitre_mapping(rule_id)

    return {
        **ioc_result,
        **mitre,
    }
