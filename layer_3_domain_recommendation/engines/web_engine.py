from copy import deepcopy
from layer_3_domain_recommendation.benchmark_matcher import retrieve_benchmarks


def process_web_entry(entry: dict) -> dict:
    enriched = deepcopy(entry)

    raw_event = entry.get("raw_event", {}) or {}
    threat = entry.get("engine_2_threat_intel", {}) or {}
    correlation = entry.get("engine_3_correlation", {}) or {}

    host = str(raw_event.get("affected_host", "") or "").lower()
    mitre_tactic = str(threat.get("mitre_tactic", "") or "").lower()
    mitre_name = str(threat.get("mitre_technique_name", "") or "").lower()

    query_tags = []
    query_keywords = []
    section_hint = []

    if "web" in host:
        query_tags.extend(["web_application", "application_security"])
        query_keywords.extend(["web", "application"])

    if "authentication" in mitre_name or "credential" in mitre_name:
        query_tags.extend(["authentication", "login", "credential_security"])
        section_hint.extend(["authentication"])

    if "injection" in mitre_name:
        query_tags.extend(["injection", "input_validation"])
        query_keywords.extend(["sql injection", "injection"])
        section_hint.extend(["injection"])

    timeline = correlation.get("attack_timeline", []) or []
    if timeline:
        for item in timeline:
            detail = str(item.get("detail", "") or "").lower()
            if "login" in detail or "failed" in detail or "authentication" in detail:
                query_tags.extend(["authentication", "login_abuse"])
                query_keywords.extend(["login", "failed authentication"])
                section_hint.extend(["authentication"])

    matched = retrieve_benchmarks(
        domain="web",
        query_tags=query_tags,
        query_keywords=query_keywords,
        section_hint=section_hint,
        max_results=1
    )

    enriched["web_context"] = {
        "framework": "web_owasp_catalog",
        "retrieval_query": {
            "query_tags": query_tags,
            "query_keywords": query_keywords,
            "section_hint": section_hint,
        },
        "matched_benchmarks": matched
    }

    return enriched