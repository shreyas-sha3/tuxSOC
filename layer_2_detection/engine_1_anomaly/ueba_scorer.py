# ueba_scorer.py
# Location: layer_2_detection/engine_1_anomaly/ueba_scorer.py
# ─────────────────────────────────────────────────────────────────
# User & Entity Behaviour Analytics (UEBA) backed by ES aggregations.
#
# Two detections:
#   1. Impossible Travel  – compares current login country against
#      the user's 30-day country baseline from ES.
#   2. Temporal Anomaly   – compares current login hour against the
#      user's historical hour-of-day distribution from ES.
# ─────────────────────────────────────────────────────────────────

from __future__ import annotations
from typing import Optional
from elasticsearch import Elasticsearch


def detect_impossible_travel(
    es: Elasticsearch,
    user: str,
    current_country: Optional[str],
    auth_index: str = "logs-auth",
) -> bool:
    """
    Returns True if `current_country` has never appeared in the user's
    last-30-day login history stored in ES.
    """
    if not current_country or not user:
        return False

    try:
        resp = es.search(
            index=auth_index,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"raw_event.affected_user.keyword": user}},
                            {"range": {"@timestamp": {"gte": "now-30d"}}},
                        ]
                    }
                },
                "aggs": {
                    "countries": {
                        "terms": {
                            "field": "geoip.country_name.keyword",
                            "size": 50,
                        }
                    }
                },
            },
            request_timeout=5,
        )
        known_countries = {
            b["key"] for b in resp["aggregations"]["countries"]["buckets"]
        }
        return current_country not in known_countries

    except Exception as e:
        print(f"[L2-UEBA] WARN UEBA] Impossible-travel query failed: {e}")
        return False


def detect_temporal_anomaly(
    es: Elasticsearch,
    user: str,
    current_hour: int,
    auth_index: str = "logs-auth",
) -> bool:
    """
    Returns True if `current_hour` falls outside the user's typical
    login-hour range (below 5th or above 95th percentile bucket) over
    the last 90 days.
    """
    if not user:
        return False

    try:
        resp = es.search(
            index=auth_index,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"raw_event.affected_user.keyword": user}},
                            {"range": {"@timestamp": {"gte": "now-90d"}}},
                        ]
                    }
                },
                "aggs": {
                    "login_hours": {
                        "histogram": {
                            "field": "hour_of_day",
                            "interval": 1,
                            "min_doc_count": 0,
                        }
                    }
                },
            },
            request_timeout=5,
        )
        buckets = resp["aggregations"]["login_hours"]["buckets"]
        total = sum(b["doc_count"] for b in buckets)
        if total == 0:
            return True  # No history at all → flag as unusual

        # Identify hours that cover < 5% of total logins (rare hours)
        threshold = total * 0.05
        rare_hours = {int(b["key"]) for b in buckets if b["doc_count"] < threshold}

        return current_hour in rare_hours

    except Exception as e:
        print(f"[L2-UEBA] WARN UEBA] Temporal-anomaly query failed: {e}")
        return False


def run_ueba(
    es: Elasticsearch,
    user: str,
    current_country: Optional[str] = None,
    current_hour: Optional[int] = None,
    auth_index: str = "logs-auth",
) -> list[str]:
    """
    Master UEBA entry-point. Returns a list of triggered UEBA flags:
      ["impossible_travel", "off_hours_activity"]
    """
    flags: list[str] = []

    if detect_impossible_travel(es, user, current_country, auth_index):
        flags.append("impossible_travel")

    if current_hour is not None and detect_temporal_anomaly(es, user, current_hour, auth_index):
        flags.append("off_hours_activity")

    return flags
