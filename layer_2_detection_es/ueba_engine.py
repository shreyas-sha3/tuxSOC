"""
ueba_engine.py
--------------
User and Entity Behavior Analytics engine.

Runs Elasticsearch aggregations to detect behavioral anomalies by
comparing current activity against baselines.

Detectors:
  1. Impossible Travel     — login from two distant countries in unrealistic time
  2. Temporal Anomaly      — login outside user's normal hour distribution
  3. Device Anomaly        — new host/device not in user's baseline
  4. Excessive Data Volume — outbound bytes >> user baseline
  5. DNS Anomaly           — DNS query length >> baseline
"""

import logging
import math
from datetime import datetime, timezone, timedelta

from layer_2_detection_es.elastic_client import search_index, run_aggregation
from layer_2_detection_es.baseline_engine import (
    get_user_login_hours,
    get_user_login_countries,
    get_user_avg_bytes,
    get_user_known_hosts,
    get_dns_avg_query_len,
)
from layer_2_detection_es.config import INDICES

logger = logging.getLogger(__name__)

# Approximate km between country centroids (simplified lookup)
_COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "United States": (37.09, -95.71),
    "United Kingdom": (55.37, -3.43),
    "China": (35.86, 104.19),
    "Russia": (61.52, 105.31),
    "India": (20.59, 78.96),
    "Germany": (51.16, 10.45),
    "France": (46.22, 2.21),
    "Brazil": (-14.23, -51.92),
    "Australia": (-25.27, 133.77),
    "Canada": (56.13, -106.34),
    "Japan": (36.20, 138.25),
    "South Korea": (35.90, 127.76),
    "Netherlands": (52.13, 5.29),
    "Singapore": (1.35, 103.81),
    "Nigeria": (9.08, 8.67),
    "Iran": (32.42, 53.68),
    "North Korea": (40.33, 127.51),
}
_MAX_TRAVEL_SPEED_KMH = 900  # faster than commercial flight = impossible


def _haversine(lat1, lon1, lat2, lon2) -> float:
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _now_minus(minutes: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Individual detectors ───────────────────────────────────────────────────

def detect_impossible_travel(lookback_minutes: int = 120) -> list[dict]:
    """
    Find users who logged in from two geographically distant countries
    within a time window that makes physical travel impossible.
    """
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(lookback_minutes)}}},
            {"term": {"action": "login_success"}},
            {"exists": {"field": "geoip.country_name"}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 500},
            "aggs": {
                "countries": {
                    "terms": {"field": "geoip.country_name.keyword", "size": 10}
                },
                "first_seen": {"min": {"field": "timestamp"}},
                "last_seen":  {"max": {"field": "timestamp"}},
            }
        }}
    }
    aggs = run_aggregation(INDICES["auth"], query)
    flags = []
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        country_buckets = bucket.get("countries", {}).get("buckets", [])
        if len(country_buckets) < 2:
            continue
        countries = [b["key"] for b in country_buckets]
        # Check all pairs
        for i in range(len(countries)):
            for j in range(i + 1, len(countries)):
                c1, c2 = countries[i], countries[j]
                coords1 = _COUNTRY_COORDS.get(c1)
                coords2 = _COUNTRY_COORDS.get(c2)
                if not coords1 or not coords2:
                    continue
                dist_km = _haversine(*coords1, *coords2)
                # Time window in hours
                window_h = lookback_minutes / 60
                required_speed = dist_km / max(window_h, 0.01)
                if required_speed > _MAX_TRAVEL_SPEED_KMH:
                    flags.append({
                        "flag": "impossible_travel",
                        "user": user,
                        "countries": [c1, c2],
                        "distance_km": round(dist_km),
                        "required_speed_kmh": round(required_speed),
                        "anomaly_score": min(1.0, required_speed / 5000),
                    })
    return flags


def detect_temporal_anomaly(lookback_minutes: int = 60) -> list[dict]:
    """
    Detect logins outside a user's normal hour distribution.
    """
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(lookback_minutes)}}},
            {"term": {"action": "login_success"}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 500},
            "aggs": {"hours": {"terms": {"field": "hour_of_day", "size": 24}}}
        }}
    }
    aggs = run_aggregation(INDICES["auth"], query)
    flags = []
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        normal_hours = get_user_login_hours(user)
        if not normal_hours:
            continue
        current_hours = {h["key"] for h in bucket.get("hours", {}).get("buckets", [])}
        anomalous = current_hours - normal_hours
        if anomalous:
            flags.append({
                "flag": "temporal_anomaly",
                "user": user,
                "anomalous_hours": sorted(anomalous),
                "normal_hours": sorted(normal_hours),
                "anomaly_score": min(1.0, len(anomalous) / 24),
            })
    return flags


def detect_device_anomaly(lookback_minutes: int = 60) -> list[dict]:
    """
    Detect users accessing hosts not in their baseline.
    """
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(lookback_minutes)}}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 500},
            "aggs": {"hosts": {"terms": {"field": "affected_host.keyword", "size": 50}}}
        }}
    }
    aggs = run_aggregation(INDICES["auth"], query)
    flags = []
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user = bucket["key"]
        known_hosts = get_user_known_hosts(user)
        if not known_hosts:
            continue
        current_hosts = {h["key"] for h in bucket.get("hosts", {}).get("buckets", [])}
        new_hosts = current_hosts - known_hosts
        if new_hosts:
            flags.append({
                "flag": "device_anomaly",
                "user": user,
                "new_hosts": sorted(new_hosts),
                "known_hosts": sorted(known_hosts),
                "anomaly_score": min(1.0, len(new_hosts) / max(len(known_hosts), 1)),
            })
    return flags


def detect_excessive_data(lookback_minutes: int = 60) -> list[dict]:
    """
    Detect users transferring significantly more data than their baseline.
    """
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(lookback_minutes)}}},
        ]}},
        "aggs": {"by_user": {
            "terms": {"field": "affected_user.keyword", "size": 500},
            "aggs": {"total_bytes": {"sum": {"field": "bytes_out"}}}
        }}
    }
    aggs = run_aggregation(INDICES["network"], query)
    flags = []
    for bucket in aggs.get("by_user", {}).get("buckets", []):
        user  = bucket["key"]
        total = bucket.get("total_bytes", {}).get("value", 0) or 0
        baseline_avg = get_user_avg_bytes(user)
        if baseline_avg is None or baseline_avg == 0:
            continue
        ratio = total / baseline_avg
        if ratio >= 5.0:  # 5x above baseline
            flags.append({
                "flag": "excessive_data_transfer",
                "user": user,
                "current_bytes": total,
                "baseline_avg_bytes": round(baseline_avg),
                "ratio": round(ratio, 2),
                "anomaly_score": min(1.0, ratio / 20),
            })
    return flags


def detect_dns_anomaly(lookback_minutes: int = 60) -> list[dict]:
    """
    Detect DNS query lengths significantly above baseline (tunneling indicator).
    """
    query = {
        "query": {"bool": {"must": [
            {"range": {"timestamp": {"gte": _now_minus(lookback_minutes)}}},
            {"term": {"protocol": "dns"}},
        ]}},
        "aggs": {"by_src": {
            "terms": {"field": "source_ip.keyword", "size": 500},
            "aggs": {"avg_len": {"avg": {"field": "dns_query_length"}}}
        }}
    }
    aggs = run_aggregation(INDICES["network"], query)
    flags = []
    for bucket in aggs.get("by_src", {}).get("buckets", []):
        src = bucket["key"]
        current_avg = bucket.get("avg_len", {}).get("value", 0) or 0
        baseline_avg = get_dns_avg_query_len(src)
        if baseline_avg is None or baseline_avg == 0:
            continue
        ratio = current_avg / baseline_avg
        if ratio >= 3.0:
            flags.append({
                "flag": "dns_query_anomaly",
                "source_ip": src,
                "current_avg_len": round(current_avg, 1),
                "baseline_avg_len": round(baseline_avg, 1),
                "ratio": round(ratio, 2),
                "anomaly_score": min(1.0, ratio / 10),
            })
    return flags


# ── Public API ─────────────────────────────────────────────────────────────

def run_ueba(lookback_minutes: int = 60) -> dict:
    """
    Run all UEBA detectors and return a consolidated result.

    Returns:
        {
          "ueba_flags":      list[dict],
          "anomaly_score":   float,
          "anomaly_flagged": bool,
        }
    """
    all_flags: list[dict] = []

    detectors = [
        (detect_impossible_travel, {"lookback_minutes": lookback_minutes}),
        (detect_temporal_anomaly,  {"lookback_minutes": lookback_minutes}),
        (detect_device_anomaly,    {"lookback_minutes": lookback_minutes}),
        (detect_excessive_data,    {"lookback_minutes": lookback_minutes}),
        (detect_dns_anomaly,       {"lookback_minutes": lookback_minutes}),
    ]

    for detector, kwargs in detectors:
        try:
            flags = detector(**kwargs)
            all_flags.extend(flags)
            if flags:
                logger.info(
                    "UEBA %s: %d anomalies detected",
                    detector.__name__, len(flags)
                )
        except Exception as exc:
            logger.error("UEBA detector %s failed: %s", detector.__name__, exc)

    # Aggregate anomaly score as max across all flags
    scores = [f.get("anomaly_score", 0.0) for f in all_flags]
    anomaly_score = max(scores) if scores else 0.0

    return {
        "ueba_flags":      all_flags,
        "anomaly_score":   round(anomaly_score, 3),
        "anomaly_flagged": anomaly_score >= 0.5,
    }
