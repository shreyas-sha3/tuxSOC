"""
SOC Log Normalizer - Unified Flat Schema for Feature Engineering Engines
=========================================================================

Transforms ANY parsed log → FIXED flat dict with ZERO nesting (prevents engine crashes).
GUARANTEED OUTPUT SCHEMA (every log produces exactly these fields):
──────────────────────────────────────────────────────────────────────

Core Timestamps:
    "@timestamp": ISO8601 string (parsed/normalized)
    "timestamp": ISO8601 string (alias for user_profiler)

Classification (from log_classifier):
    "log_family": "network" | "web" | "iot" | "unknown"
    "classification_scores": {"network": 4, "web": 0, "iot": 3}
    "classification_confidence": "high" | "medium" | "low"

Network Fields (FLAT - no nesting):
    "src_ip": str | null
    "dst_ip": str | null  
    "src_port": int | null
    "dst_port": int | null
    "protocol": "tcp" | "udp" | "mqtt" | "ssh" | null
    "bytes_in": int | null
    "bytes_out": int | null  
    "network_bytes": int | null (bytes_in + bytes_out)

Behavioral Engine Aliases (exact names engines expect):
    "user": str | null
    "source_ip": str | null (src_ip alias)
    "username": str | null

Event Semantics (auto-inferred from message content):
    "event_type": "authentication_failure" | "attack" | "unknown"
    "action": "logon_failed" | "brute_force_detected" | "unknown"
    "event_category": ["network", "web", "iot", "authentication"]
    "event_duration": int/ms | null

HTTP/Web:
    "http_method": "GET" | "POST" | null
    "http_status_code": 200 | 401 | null  
    "url_path": "/api/users" | null
    "user_agent": "Mozilla/5.0..." | null

IoT/OT:
    "device_id": "SENSOR_001" | null
    "device_type": "temperature_sensor" | null
    "topic": "factory/temp" | null
    "command": "PUBLISH" | null
    "telemetry_value": 72.4 | null

Host/Meta:
    "hostname": "fw01" | null
    "raw_message": original line
    "priority": "34" | null (syslog)
    "format": "syslog" | "json" | "csv"

Time Aliases (backfilled after temporal_features):
    "current_hour": 10
    "hour_of_day": 10
    "day_of_week": "Wednesday"  
    "is_off_hours": false

Pass-through (unmapped scalars preserved):
    "source_file", "source_line", "observer_hostname", etc.

Normalizer: takes parsed_dict from log_parsers → ECS-style normalized dict
plus flattened fields for current engines.
Also stamps @timestamp and log_family (via classify_log) before passing to feature_orchestrator.
"""
from datetime import datetime
from dateutil import parser as date_parser
from typing import Dict, Any
import re
import sys

sys.path.append("layer_1_feature_engineering")
from log_classifier import classify_log


# Well-known port → protocol mapping used for classification hints
_WELL_KNOWN_PORTS = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 443: "https", 3389: "rdp", 445: "smb",
    110: "pop3", 143: "imap", 21: "ftp", 3306: "mysql",
    5432: "postgres", 6379: "redis", 27017: "mongodb",
    1883: "mqtt", 8883: "mqtt", 8080: "http", 8443: "https",
}


def parse_timestamp(value: Any) -> str:
    if value is None:
        return datetime.utcnow().isoformat()
    try:
        return date_parser.parse(str(value)).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()


def normalize_parsed_log(parsed_log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a parsed dict from log_parsers and returns a fully flat dict
    ready for the feature engineering engines.
    No nested dicts are left in the output — engines only see scalar values.
    """

    def get(k: str) -> Any:
        for key in [k, k.lower(), k.upper(), k.title()]:
            if key in parsed_log:
                return parsed_log[key]
        return None

    # ── Raw field extraction ──────────────────────────────
    src_ip        = get("src_ip")
    dst_ip        = get("dst_ip")
    src_port      = get("src_port")
    dst_port      = get("dst_port")
    protocol      = get("protocol")
    bytes_in      = get("bytes_in")
    bytes_out     = get("bytes_out")
    total_bytes   = get("bytes")
    username      = get("username")
    hostname      = get("hostname") or get("host") or get("observer")
    method        = get("method") or get("http_method") or get("request_method")
    status_code   = get("status_code") or get("http_status") or get("response_code")
    url_path      = get("path") or get("url_path") or get("uri") or get("request_uri")
    user_agent    = get("user_agent") or get("useragent") or get("http_user_agent")
    device_id     = get("device_id")
    device_type   = get("device_type")
    topic         = get("topic")
    command       = get("command")
    telemetry_val = get("telemetry_value") or get("telemetry")

    # ── Safe type coercions ───────────────────────────────
    def to_int(v):
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def to_float(v):
        try:
            return float(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    src_port      = to_int(src_port)
    dst_port      = to_int(dst_port)
    status_code   = to_int(status_code)
    bytes_in      = to_int(bytes_in)
    bytes_out     = to_int(bytes_out)
    telemetry_val = to_float(telemetry_val)

    # ── Bytes resolution ──────────────────────────────────
    if total_bytes is not None:
        network_bytes = to_int(total_bytes)
    elif bytes_in is not None and bytes_out is not None:
        network_bytes = bytes_in + bytes_out
    else:
        network_bytes = bytes_in

    # ── Protocol normalisation ────────────────────────────
    protocol_str = str(protocol).lower() if protocol else None

    # Infer protocol from dst_port if not present
    if not protocol_str and dst_port:
        protocol_str = _WELL_KNOWN_PORTS.get(dst_port)

    # ── Method normalisation ──────────────────────────────
    method_str = str(method).upper() if method else None

    # ── User agent — ensure scalar ────────────────────────
    ua_str = user_agent if isinstance(user_agent, str) else None

    # ── Event categories ──────────────────────────────────
    categories = []
    if protocol_str or src_ip or dst_ip or src_port or dst_port:
        categories.append("network")
    if method_str or url_path or status_code:
        categories.append("web")
    if device_id or device_type or telemetry_val is not None:
        categories.append("iot")
    if username:
        categories.append("authentication")

    # ── Event type and action — inferred from message ─────
    _msg = str(parsed_log.get("message", "")).lower()

    if re.search(r'failed password|authentication failure|invalid user|failed login', _msg):
        event_type = "authentication_failure"
        action     = "logon_failed"
    elif re.search(r'accepted password|session opened|logged in', _msg):
        event_type = "authentication_success"
        action     = "logon"
    elif re.search(r'brute force|bruteforce', _msg):
        event_type = "attack"
        action     = "brute_force_detected"
    elif re.search(r'sudo', _msg):
        event_type = "privilege_escalation"
        action     = "sudo"
    elif re.search(r'denied|deny|blocked|drop', _msg):
        event_type = "connection_blocked"
        action     = "deny"
    elif re.search(r'allowed|permit|accept|established', _msg):
        event_type = "connection_allowed"
        action     = "allow"
    else:
        event_type = "unknown"
        action     = "unknown"

    # ── Timestamp ─────────────────────────────────────────
    ts = parse_timestamp(parsed_log.get("timestamp") or parsed_log.get("time"))

    # ── Build flat output dict ────────────────────────────
    # NO nested dicts — everything is a scalar so engines
    # never encounter "unhashable type: dict"
    ecs: Dict[str, Any] = {
        # Timestamps
        "@timestamp":       ts,
        "timestamp":        ts,          # user_profiler reads "timestamp"

        # Classification (filled below)
        "log_family":       "unknown",

        # Network — flat keys
        "src_ip":           src_ip,
        "dst_ip":           dst_ip,
        "src_port":         src_port,
        "dst_port":         dst_port,
        "protocol":         protocol_str,
        "bytes_in":         bytes_in,
        "bytes_out":        bytes_out,
        "network_bytes":    network_bytes,

        # Behavioral engine aliases
        # user_profiler reads "user" not "username"
        # user_profiler reads "source_ip" not "src_ip"
        "user":             username,
        "source_ip":        src_ip,
        "username":         username,    # keep both

        # Event type and action for behavioral engine
        "event_type":       event_type,
        "action":           action,

        # Host
        "hostname":         str(hostname) if hostname else None,

        # HTTP
        "http_method":      method_str,
        "http_status_code": status_code,
        "url_path":         url_path,
        "user_agent":       ua_str,

        # IoT
        "device_id":        str(device_id) if device_id else None,
        "device_type":      str(device_type) if device_type else None,
        "topic":            str(topic) if topic else None,
        "command":          str(command) if command else None,
        "telemetry_value":  telemetry_val,

        # Event meta
        "event_category":   categories,
        "event_duration":   parsed_log.get("duration") or parsed_log.get("duration_ms"),

        # Raw
        "raw_message":      parsed_log.get("raw_message", str(parsed_log)),

        # Time aliases — backfilled after temporal engine runs
        "current_hour":     None,
        "hour_of_day":      None,
        "day_of_week":      None,
        "is_off_hours":     None,
    }

    # ── Pass-through unmapped fields ──────────────────────
    ALREADY_MAPPED = {
        "timestamp", "time", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "bytes_in", "bytes_out", "bytes", "username", "hostname",
        "host", "method", "http_method", "request_method", "status_code",
        "http_status", "response_code", "path", "url_path", "uri",
        "request_uri", "user_agent", "useragent", "http_user_agent",
        "device_id", "device_type", "topic", "command", "telemetry_value",
        "telemetry", "raw_message", "duration", "duration_ms", "observer",
        "format", "source_file", "source_line",
    }
    for k, v in parsed_log.items():
        if k not in ALREADY_MAPPED and k not in ecs and not isinstance(v, dict):
            ecs[k] = v

    # ── Classify → stamp log_family ──────────────────────
    try:
        ecs = classify_log(ecs)
    except Exception as e:
        ecs["classification_error"] = str(e)

    return ecs


def backfill_time_aliases(ecs: dict) -> dict:
    """
    Call this AFTER temporal engine has run.
    Copies time_windows fields to the flat keys behavioral engine expects.
    """
    tw = ecs.get("time_windows") or {}
    ecs["hour_of_day"]  = tw.get("hour_of_day")
    ecs["current_hour"] = tw.get("hour_of_day")   # alias
    ecs["day_of_week"]  = tw.get("day_of_week")
    ecs["is_off_hours"] = tw.get("is_off_hours")
    return ecs