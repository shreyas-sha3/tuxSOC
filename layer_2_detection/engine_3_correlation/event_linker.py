# event_linker.py
# Location: layer_2_detection/engine_3_correlation/event_linker.py
# ─────────────────────────────────────────────────────────────────
# The ES "Time-Machine" correlator.
#
# When a detection fires for a pivot_ip or pivot_user, this module
# queries ALL indices (logs-*) for related events within a ±5-min
# window, building a correlated event cluster.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from elasticsearch import Elasticsearch


def correlate_events(
    es: Elasticsearch,
    pivot_ip: str | None = None,
    pivot_user: str | None = None,
    pivot_host: str | None = None,
    pivot_dest_ip: str | None = None,
    time_range: str = "now-5m",
    max_events: int = 200,
) -> list[dict]:
    """
    The ES Time-Machine Query.

    Given pivot fields (IP, user, host, destination), pull ALL related
    logs from every index across the last 5 minutes.

    Returns raw ES source dicts sorted by timestamp.
    """
    should_clauses: list[dict] = []

    if pivot_ip:
        should_clauses.extend([
            {"term": {"source.ip": pivot_ip}},
            {"term": {"destination.ip": pivot_ip}},
            {"term": {"raw_event.source_ip.keyword": pivot_ip}},
            {"term": {"raw_event.destination_ip.keyword": pivot_ip}},
        ])
    if pivot_user:
        should_clauses.extend([
            {"term": {"raw_event.affected_user.keyword": pivot_user}},
            {"term": {"user.name.keyword": pivot_user}},
        ])
    if pivot_host:
        should_clauses.extend([
            {"term": {"raw_event.affected_host.keyword": pivot_host}},
            {"term": {"host.name.keyword": pivot_host}},
        ])
    if pivot_dest_ip:
        should_clauses.extend([
            {"term": {"destination.ip": pivot_dest_ip}},
            {"term": {"raw_event.destination_ip.keyword": pivot_dest_ip}},
        ])

    if not should_clauses:
        return []

    body = {
        "size": max_events,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                ],
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
    }

    try:
        resp = es.search(index="logs-*", body=body, request_timeout=10)
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    except Exception as e:
        print(f"[L2-CORRELATOR] WARN Correlator] Time-machine query failed: {e}")
        return []
