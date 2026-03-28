from copy import deepcopy


def _safe_get(data, *keys, default=None):
    """
    Safely get nested values from dictionaries.
    Example:
        _safe_get(log, "identity_features", "location")
    """
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _infer_log_type(log: dict) -> str:
    """
    Best-effort log type inference when log_type is missing.
    Priority:
    web -> endpoint -> network -> auth
    """

    # Web indicators
    if (
        _safe_get(log, "request", "uri")
        or _safe_get(log, "request", "body")
        or _safe_get(log, "user_agent", "original")
        or log.get("uri")
        or log.get("http_method")
        or log.get("http_body")
        or log.get("user_agent")
    ):
        return "web"

    # Endpoint indicators
    if (
        _safe_get(log, "process", "name")
        or _safe_get(log, "process", "command_line")
        or _safe_get(log, "registry", "path")
        or log.get("process_name")
        or log.get("command_line")
        or log.get("registry_path")
    ):
        return "endpoint"

    # Network indicators
    if (
        _safe_get(log, "network", "bytes") is not None
        or _safe_get(log, "network", "transport")
        or _safe_get(log, "dns", "question", "name")
        or log.get("bytes_out") is not None
        or log.get("bytes_transferred") is not None
        or log.get("transport")
        or log.get("dns_query")
        or log.get("destination_port") is not None
        or log.get("dest_port") is not None
    ):
        return "network"

    # Auth indicators
    if (
        _safe_get(log, "identity_features", "is_identity_event")
        or _safe_get(log, "identity_features", "is_signin_activity")
        or _safe_get(log, "identity_features", "is_successful_login")
        or _safe_get(log, "identity_features", "is_failed_login")
        or log.get("UserPrincipalName")
        or log.get("UserId")
        or log.get("username")
        or log.get("user")
        or log.get("auth_status")
        or log.get("event_id")
        or log.get("EventID")
    ):
        return "auth"

    return "auth"


def _extract_source_ip(log: dict) -> str:
    return (
        _safe_get(log, "source", "ip")
        or log.get("source_ip")
        or log.get("src_ip")
        or log.get("IpAddress")
        or log.get("ClientIP")
        or _safe_get(log, "user_profile", "current_source_ip")
        or ""
    )


def _extract_destination_ip(log: dict) -> str:
    return (
        _safe_get(log, "destination", "ip")
        or log.get("destination_ip")
        or log.get("dest_ip")
        or ""
    )


def _extract_destination_port(log: dict):
    return (
        _safe_get(log, "destination", "port")
        or log.get("destination_port")
        or log.get("dest_port")
        or None
    )


def _extract_affected_user(log: dict) -> str:
    return (
        _safe_get(log, "raw_event", "affected_user")
        or log.get("affected_user")
        or log.get("UserPrincipalName")
        or log.get("UserId")
        or log.get("username")
        or log.get("user")
        or ""
    )


def _extract_affected_host(log: dict) -> str:
    return (
        _safe_get(log, "raw_event", "affected_host")
        or log.get("affected_host")
        or log.get("hostname")
        or log.get("host")
        or log.get("ComputerName")
        or ""
    )


def _extract_action(log: dict, log_type: str) -> str:
    existing_action = (
        _safe_get(log, "raw_event", "action")
        or _safe_get(log, "event", "action")
        or log.get("action")
        or log.get("OperationName")
        or log.get("Operation")
    )
    if existing_action:
        return str(existing_action)

    if log_type == "web":
        http_method = log.get("http_method", "")
        return f"HTTP {http_method}".strip() or "HTTP request"

    if log_type == "auth":
        return "logon"

    if log_type == "endpoint":
        return "process_execution"

    if log_type == "network":
        if log.get("dns_query") or _safe_get(log, "dns", "question", "name"):
            return "dns_query"
        return "network_connection"

    return "unknown"


def _build_auth_block(log: dict) -> dict:
    identity = log.get("identity_features", {})
    time_windows = log.get("time_windows", {})

    outcome = (
        _safe_get(log, "event", "outcome")
        or log.get("auth_status")
        or (
            "success" if identity.get("is_successful_login") else
            "failure" if identity.get("is_failed_login") else
            ""
        )
    )

    action = (
        _safe_get(log, "event", "action")
        or log.get("auth_action")
        or ("mfa_prompt" if "mfa" in str(log.get("OperationName", "")).lower() else "logon")
    )

    country_name = (
        _safe_get(log, "geoip", "country_name")
        or log.get("country_name")
        or identity.get("location")
        or ""
    )

    hour_of_day = (
        log.get("hour_of_day")
        if log.get("hour_of_day") is not None
        else time_windows.get("hour_of_day")
    )

    return {
        "event": {
            "category": "authentication",
            "outcome": outcome,
            "action": action
        },
        "geoip": {
            "country_name": country_name
        },
        "hour_of_day": hour_of_day
    }


def _build_web_block(log: dict) -> dict:
    return {
        "request": {
            "uri": (
                _safe_get(log, "request", "uri")
                or log.get("uri")
                or ""
            ),
            "body": (
                _safe_get(log, "request", "body")
                or log.get("http_body")
                or ""
            )
        },
        "user_agent": {
            "original": (
                _safe_get(log, "user_agent", "original")
                or log.get("user_agent")
                or ""
            )
        }
    }


def _build_endpoint_block(log: dict) -> dict:
    return {
        "process": {
            "name": (
                _safe_get(log, "process", "name")
                or log.get("process_name")
                or ""
            ),
            "command_line": (
                _safe_get(log, "process", "command_line")
                or log.get("command_line")
                or ""
            )
        },
        "registry": {
            "path": (
                _safe_get(log, "registry", "path")
                or log.get("registry_path")
                or ""
            )
        }
    }


def _build_network_block(log: dict) -> dict:
    return {
        "network": {
            "bytes": (
                _safe_get(log, "network", "bytes")
                if _safe_get(log, "network", "bytes") is not None
                else log.get("bytes_transferred")
                if log.get("bytes_transferred") is not None
                else log.get("bytes_out", 0)
            ),
            "transport": (
                _safe_get(log, "network", "transport")
                or log.get("transport")
                or ""
            )
        },
        "dns": {
            "question": {
                "name": (
                    _safe_get(log, "dns", "question", "name")
                    or log.get("dns_query")
                    or ""
                ),
                "type": (
                    _safe_get(log, "dns", "question", "type")
                    or log.get("dns_type")
                    or ""
                )
            }
        }
    }


def format_detection_ready_log(enriched_log: dict) -> dict:
    """
    Convert one enriched log into Layer-2-ready ECS-style structure
    while preserving existing enrichment fields.
    """
    log = deepcopy(enriched_log)

    log_type = log.get("log_type")
    if log_type not in {"web", "auth", "endpoint", "network"}:
        log_type = _infer_log_type(log)

    formatted = {
        "@timestamp": log.get("@timestamp") or log.get("timestamp"),
        "log_type": log_type,
        "source": {
            "ip": _extract_source_ip(log)
        },
        "destination": {
            "ip": _extract_destination_ip(log),
            "port": _extract_destination_port(log)
        },
        "raw_event": {
            "action": _extract_action(log, log_type),
            "affected_host": _extract_affected_host(log),
            "affected_user": _extract_affected_user(log)
        }
    }

    if log_type == "auth":
        formatted.update(_build_auth_block(log))
    elif log_type == "web":
        formatted.update(_build_web_block(log))
    elif log_type == "endpoint":
        formatted.update(_build_endpoint_block(log))
    elif log_type == "network":
        formatted.update(_build_network_block(log))

    # Preserve all other enrichment fields without overwriting contract fields
    reserved_keys = {
        "@timestamp",
        "timestamp",
        "log_type",
        "source",
        "destination",
        "raw_event",
        "event",
        "geoip",
        "hour_of_day",
        "request",
        "user_agent",
        "process",
        "registry",
        "network",
        "dns",
    }

    for key, value in log.items():
        if key not in reserved_keys:
            formatted[key] = value

    return formatted


def format_detection_ready_logs(enriched_logs: list[dict]) -> list[dict]:
    """
    Convert a list of enriched logs into detection-ready output.
    """
    return [format_detection_ready_log(log) for log in enriched_logs]