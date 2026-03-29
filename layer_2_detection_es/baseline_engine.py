"""
baseline_engine.py
------------------
Computes and caches behavioral baselines from historical Elasticsearch data.
Baselines are used by the UEBA engine for anomaly comparison.

Baselines computed:
  - user_login_hours      : set of normal login hours (0-23) per user
  - user_login_countries  : set of normal countries per user
  - user_avg_bytes_out    : average outbound bytes per user per session
  - user_known_hosts      : set of hosts a user normally accesses
  - dns_avg_query_length  : average DNS query length per source IP
"""

import logging
from datetime import datetime, timezone, timedelta

from layer_2_detection_es.elastic_client import run_aggregation
from layer_2_detection_es.config import BASELINE_LOOKBACK_DAYS, BASELINE_MIN_SAMPLES, INDICES

logger = logging.getLogger(__name__)

# In-memory baseline cache
# { "user_login_hours":   { user: set(hours) }
#   "user_login_countries": { user: set(countries) }
#   "user_avg_bytes_out": { user: float }
#   "user_known_hosts":   { user: set(hosts) }
#   "dns_avg_query_len":  { src_ip: float }
# }
_baselines: dict = {
    "user_login_hours":     {},
    "user_login_countries": {},
    "user_avg_bytes_out":   {},
    "user_known_hosts":     {},
    "dns_avg_query_len":    {},
}
_last_computed: datetime | None = None


def _lookback_ts() -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=BASELINE_LOOKBACK_DAYS)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_baselines():
    """
    Run all baseline aggregations against Elasticsearch.
    Should be called once at startup and periodically (e.g. every hour).
    """
    global _last_computed
    logger.info("Computing behavioral baselines (lookback=%dd)", BASELINE_LOOKBACK_DAYS)
    since = _lookback_ts()

    _compute_user_login_hours(since)
    _compute_user_login_countries(since)
    _compute_user_avg_bytes(since)
    _compute_user_known_hosts(since)
    _compute_dns_query_lengths(since)

    _last_computed = datetime.now(timezone.utc)
    logger.info("Baselines computed at %s", _last_computed.isoformat())


def _compute_user_login_hours(since: str):
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": since}}},
            {"term": {"action": "login_success"}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 1000},
            "aggs": {"hours": {"terms": {"field": "hour_of_day", "size": 24}}}
        }}
    }
    aggs = run_aggregation(INDICES["auth"], query)
    result = {}
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        if bucket["doc_count"] < BASELINE_MIN_SAMPLES:
            continue
        hours = {h["key"] for h in bucket.get("hours", {}).get("buckets", [])}
        result[user] = hours
    _baselines["user_login_hours"] = result
    logger.debug("Login hour baselines: %d users", len(result))


def _compute_user_login_countries(since: str):
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": since}}},
            {"term": {"action": "login_success"}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 1000},
            "aggs": {"countries": {"terms": {"field": "geoip.country_name.keyword", "size": 50}}}
        }}
    }
    aggs = run_aggregation(INDICES["auth"], query)
    result = {}
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        if bucket["doc_count"] < BASELINE_MIN_SAMPLES:
            continue
        countries = {c["key"] for c in bucket.get("countries", {}).get("buckets", [])}
        result[user] = countries
    _baselines["user_login_countries"] = result
    logger.debug("Login country baselines: %d users", len(result))


def _compute_user_avg_bytes(since: str):
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": since}}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 1000},
            "aggs": {"avg_bytes": {"avg": {"field": "bytes_out"}}}
        }}
    }
    aggs = run_aggregation(INDICES["network"], query)
    result = {}
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        avg  = bucket.get("avg_bytes", {}).get("value")
        if avg is not None and bucket["doc_count"] >= BASELINE_MIN_SAMPLES:
            result[user] = float(avg)
    _baselines["user_avg_bytes_out"] = result
    logger.debug("Avg bytes baselines: %d users", len(result))


def _compute_user_known_hosts(since: str):
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": since}}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 1000},
            "aggs": {"hosts": {"terms": {"field": "affected_host.keyword", "size": 100}}}
        }}
    }
    aggs = run_aggregation(INDICES["auth"], query)
    result = {}
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user  = bucket["key"]
        hosts = {h["key"] for h in bucket.get("hosts", {}).get("buckets", [])}
        result[user] = hosts
    _baselines["user_known_hosts"] = result
    logger.debug("Known host baselines: %d users", len(result))


def _compute_dns_query_lengths(since: str):
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": since}}},
            {"term": {"protocol": "dns"}},
        ]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "size": 1000},
            "aggs": {"avg_len": {"avg": {"field": "dns_query_length"}}}
        }}
    }
    aggs = run_aggregation(INDICES["network"], query)
    result = {}
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        src = bucket["key"]
        avg = bucket.get("avg_len", {}).get("value")
        if avg is not None and bucket["doc_count"] >= BASELINE_MIN_SAMPLES:
            result[src] = float(avg)
    _baselines["dns_avg_query_len"] = result
    logger.debug("DNS query length baselines: %d IPs", len(result))


# ── Accessor API ───────────────────────────────────────────────────────────

def get_user_login_hours(user: str) -> set:
    return _baselines["user_login_hours"].get(user, set())


def get_user_login_countries(user: str) -> set:
    return _baselines["user_login_countries"].get(user, set())


def get_user_avg_bytes(user: str) -> float | None:
    return _baselines["user_avg_bytes_out"].get(user)


def get_user_known_hosts(user: str) -> set:
    return _baselines["user_known_hosts"].get(user, set())


def get_dns_avg_query_len(src_ip: str) -> float | None:
    return _baselines["dns_avg_query_len"].get(src_ip)


def baselines_ready() -> bool:
    return _last_computed is not None
