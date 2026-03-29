from layer_3_domain_recommendation.engines.web_engine import process_web_entry
from layer_3_domain_recommendation.engines.network_engine import process_network_entry
from layer_3_domain_recommendation.engines.iot_engine import process_iot_entry


def route_entry(entry: dict) -> dict:
    log_type = str(entry.get("log_type", "unknown") or "unknown").strip().lower()

    if log_type == "web":
        return process_web_entry(entry)

    if log_type == "network":
        return process_network_entry(entry)

    if log_type == "iot":
        return process_iot_entry(entry)

    enriched = dict(entry)
    enriched["generic_context"] = {
        "framework": "generic",
        "retrieval_query": {
            "query_tags": [],
            "query_keywords": [],
            "section_hint": []
        },
        "matched_benchmarks": []
    }
    return enriched