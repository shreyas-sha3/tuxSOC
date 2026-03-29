from copy import deepcopy
from layer_3_domain_recommendation.benchmark_matcher import retrieve_benchmarks


def process_iot_entry(entry: dict) -> dict:
    enriched = deepcopy(entry)

    raw_event = entry.get("raw_event", {}) or {}
    anomaly = entry.get("engine_1_anomaly", {}) or {}
    threat = entry.get("engine_2_threat_intel", {}) or {}

    ueba_flags = anomaly.get("ueba_flags", []) or []
    mitre_technique = str(threat.get("mitre_technique", "") or "").lower()
    mitre_name = str(threat.get("mitre_technique_name", "") or "").lower()

    query_tags = []
    query_keywords = []
    section_hint = []

    if "off_hours_activity" in [str(x).lower() for x in ueba_flags]:
        query_tags.extend(["account_access", "monitoring", "anomalous_access"])
        query_keywords.extend(["off hours access", "unusual access"])

    if mitre_technique == "t1078" or "valid accounts" in mitre_name:
        query_tags.extend(["authentication", "credentials", "valid_accounts"])
        query_keywords.extend(["valid accounts", "credential use"])
        section_hint.extend(["authentication", "access control"])

    if raw_event.get("affected_host"):
        query_keywords.append(str(raw_event.get("affected_host")).lower())

    matched = retrieve_benchmarks(
        domain="iot",
        query_tags=query_tags,
        query_keywords=query_keywords,
        section_hint=section_hint,
        max_results=1
    )

    enriched["iot_context"] = {
        "framework": "iot_cis_catalog",
        "retrieval_query": {
            "query_tags": query_tags,
            "query_keywords": query_keywords,
            "section_hint": section_hint,
        },
        "matched_benchmarks": matched
    }

    return enriched