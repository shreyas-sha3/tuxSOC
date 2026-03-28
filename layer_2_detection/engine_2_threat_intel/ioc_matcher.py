# ioc_matcher.py
# Location: layer_2_detection/engine_2_threat_intel/ioc_matcher.py
# ─────────────────────────────────────────────────────────────────
# Lightweight IOC enrichment. Checks source/destination IPs and
# domains against known blacklists and threat feeds stored in ES.
# If ES-based feeds are unavailable, falls back to a static seed
# list for demo / offline operation.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from typing import Optional
from elasticsearch import Elasticsearch

# ── Static Fallback Seed List ─────────────────────────────────────
# Used when ES threat-intel index is not yet populated.
_STATIC_BLACKLIST_IPS: set[str] = {
    "194.5.6.7",
    "185.192.69.5",
    "45.33.22.11",
    "203.0.113.50",
    "114.114.114.114",
    "45.45.45.45",
}

_STATIC_MALWARE_HASHES: set[str] = set()

_STATIC_MALICIOUS_DOMAINS: set[str] = {
    "evil-c2.example.com",
    "update.malware.biz",
}


def match_iocs(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    domain: Optional[str] = None,
    file_hash: Optional[str] = None,
    es_client: Optional[Elasticsearch] = None,
) -> dict:
    """
    Checks the provided observables against threat intelligence.
    Returns:
      {
        "ioc_matches":       ["blacklist_hit_X", ...],
        "threat_intel_match": True/False
      }
    """
    matches: list[str] = []

    # ── 1. Try ES-based threat feed first ─────────────────────
    if es_client is not None:
        try:
            for ip in filter(None, [source_ip, destination_ip]):
                resp = es_client.search(
                    index="threat-intel-iocs",
                    body={
                        "size": 1,
                        "query": {"term": {"indicator.ip": ip}},
                    },
                    request_timeout=3,
                )
                if resp["hits"]["total"]["value"] > 0:
                    matches.append(f"threat_feed_hit_{ip}")
        except Exception:
            pass  # Fall through to static list

    # ── 2. Static blacklist fallback ──────────────────────────
    for ip in filter(None, [source_ip, destination_ip]):
        if ip in _STATIC_BLACKLIST_IPS:
            tag = f"blacklist_hit_{ip}"
            if tag not in matches:
                matches.append(tag)

    if domain and domain in _STATIC_MALICIOUS_DOMAINS:
        matches.append(f"malicious_domain_{domain}")

    if file_hash and file_hash in _STATIC_MALWARE_HASHES:
        matches.append(f"malware_hash_{file_hash}")

    return {
        "ioc_matches":       matches,
        "threat_intel_match": len(matches) > 0,
    }
