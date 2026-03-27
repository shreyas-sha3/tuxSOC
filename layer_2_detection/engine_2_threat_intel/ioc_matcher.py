"""
ioc_matcher.py
--------------
Matches fields from a normalized log event against the IOC database.
Handles three log types with different matching strategies:
  - network  : matches IPs + CIS benchmark rules
  - iot      : matches device IDs + IoT thresholds + CIS rules
  - endpoint : matches IPs, domains, file hashes
  - auth     : matches IPs, usernames (future: compromised credential DB)
  - firewall : matches IPs, ports
"""

import logging
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ioc_database"))

from ioc_db import lookup_ioc, lookup_iot_thresholds, DEFAULT_DB_PATH
from auto_enricher import (
    check_unknown_ip_frequency,
    check_flagged_domain,
    check_unknown_file_hash,
    check_iot_cis_violation,
)

logger = logging.getLogger(__name__)

PORT_PROTOCOL_MAP = {
    179:  "bgp routing",
    88:   "eigrp ospf routing adjacency",
    520:  "rip routing",
    161:  "snmp management",
    162:  "snmp trap management",
    22:   "ssh management authentication",
    23:   "telnet management authentication",
    443:  "https ssl management",
    80:   "http management",
    514:  "syslog logging",
    636:  "ldap authentication",
    389:  "ldap authentication",
    1812: "radius authentication",
    49:   "tacacs authentication",
}


def _extract_fields(raw_event: dict, log_type: str) -> dict:
    """Extract relevant fields per log type for IOC matching."""
    return {
        "source_ip":   raw_event.get("source_ip") or raw_event.get("src_ip"),
        "dest_ip":     raw_event.get("destination_ip") or raw_event.get("dst_ip"),
        "domain":      raw_event.get("domain") or raw_event.get("hostname"),
        "file_hash":   raw_event.get("file_hash") or raw_event.get("md5") or raw_event.get("sha256"),
        "port":        raw_event.get("port") or raw_event.get("destination_port"),
        "device_id":   raw_event.get("device_id") or raw_event.get("source_ip"),
        "device_type": raw_event.get("device_type", "generic_iot"),
    }


def match(raw_event: dict, log_type: str,
          anomaly_score: float = 0.0,
          db_path: str = DEFAULT_DB_PATH) -> dict:
    """
    Match a log event against the IOC database.

    Returns:
        {
          "ioc_matches":         list[str],
          "matched_ioc_details": list[dict],
          "cis_violations":      list[dict],
          "iot_threshold_hits":  list[dict],
          "threat_intel_match":  bool,
        }
    """
    fields        = _extract_fields(raw_event, log_type)
    ioc_matches   = []
    ioc_details   = []
    cis_violations = []
    iot_hits      = []
    print("IOC CHECK:", raw_event.get("source_ip"), raw_event.get("destination_ip"))
    # ---- IP matching ----
    for ip_key in ("source_ip", "dest_ip"):
        ip = fields.get(ip_key)
        if ip:
            hits = lookup_ioc(ip, ioc_type="ip", db_path=db_path)
            for h in hits:
                label = h.get("threat_type") or "malicious_ip"
                if label not in ioc_matches:
                    ioc_matches.append(label)
                    ioc_details.append(h)

    # ---- Domain matching ----
    domain = fields.get("domain")
    if domain:
        hits = lookup_ioc(domain, ioc_type="domain", db_path=db_path)
        for h in hits:
            label = h.get("threat_type") or "suspicious_domain"
            if label not in ioc_matches:
                ioc_matches.append(label)
                ioc_details.append(h)

    # ---- File hash matching ----
    file_hash = fields.get("file_hash")
    if file_hash:
        hits = lookup_ioc(file_hash, ioc_type="file_hash", db_path=db_path)
        for h in hits:
            label = h.get("threat_type") or "malicious_file_hash"
            if label not in ioc_matches:
                ioc_matches.append(label)
                ioc_details.append(h)

    # ---- Process name matching ----
    process = raw_event.get("process") or ""
    if process:
        hits = lookup_ioc(process.lower(), ioc_type="domain", db_path=db_path)
        for h in hits:
            label = h.get("threat_type") or "suspicious_process"
            if label not in ioc_matches:
                ioc_matches.append(label)
                ioc_details.append(h)

    # ---- CIS Benchmark matching (network + iot + firewall) ----
    if log_type in ("network", "iot", "firewall"):
        # Enrich terse logs with protocol name from port number
        enriched_event = dict(raw_event)
        port = raw_event.get("port") or raw_event.get("destination_port")
        if port:
            try:
                hint = PORT_PROTOCOL_MAP.get(int(port))
                if hint:
                    enriched_event["protocol_hint"] = hint
            except (ValueError, TypeError):
                pass


    # ---- IoT threshold checking ----
    if log_type == "iot":
        device_type = fields.get("device_type", "generic_iot")
        thresholds  = lookup_iot_thresholds(device_type, db_path=db_path)
        for thresh in thresholds:
            metric = thresh["metric"]
            value  = raw_event.get(metric)
            if value is None:
                continue
            value = float(value)
            violated = False
            if thresh["threshold_max"] is not None and value > thresh["threshold_max"]:
                violated = True
            if thresh["threshold_min"] is not None and value < thresh["threshold_min"]:
                violated = True
            if violated:
                hit = dict(thresh)
                hit["observed_value"] = value
                iot_hits.append(hit)

    # ---- Auto-enrichment triggers ----
    src_ip = fields.get("source_ip")
    if src_ip:
        check_unknown_ip_frequency(src_ip, raw_event, anomaly_score, log_type, db_path)

    if domain:
        check_flagged_domain(domain, raw_event, anomaly_score, log_type, db_path)

    if file_hash:
        check_unknown_file_hash(file_hash, raw_event, anomaly_score, log_type, db_path)

    if log_type == "iot" and iot_hits:
        device_id = fields.get("device_id", "")
        for hit in iot_hits:
            check_iot_cis_violation(
                device_id=device_id,
                device_type=fields.get("device_type", "generic_iot"),
                violated_rule=hit,
                raw_event=raw_event,
                anomaly_score=anomaly_score,
                db_path=db_path
            )

    threat_intel_match = bool(ioc_matches or cis_violations or iot_hits)

    return {
    "ioc_matches":         ioc_matches,
    "matched_ioc_details": ioc_details,
    "iot_threshold_hits":  iot_hits,
    "threat_intel_match":  bool(ioc_matches or iot_hits),
    "ioc_confidence":      round(len(ioc_matches) * 0.2, 2),
}