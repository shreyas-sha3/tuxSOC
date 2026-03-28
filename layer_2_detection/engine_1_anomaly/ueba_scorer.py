"""
ueba_scorer.py
--------------
User and Entity Behaviour Analytics scorer.
Applies rule-based behavioural checks on top of the PyOD score
and produces ueba_flags and a risk_boost.

Flags and their risk boosts (additive):
  off_hours_activity          +0.10
  excessive_failed_logins     +0.15
  impossible_travel           +0.20
  privilege_escalation        +0.15
  lateral_movement_indicator  +0.15
  suspicious_process_chain    +0.12
  large_data_transfer         +0.10
  new_device_first_seen       +0.08
"""

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Business hours config (24h, local server time)
BUSINESS_HOURS_START = 8   # 08:00
BUSINESS_HOURS_END   = 19  # 19:00

# Thresholds
FAILED_LOGIN_THRESHOLD    = 4       # failures in the event window
LARGE_TRANSFER_MB         = 50      # outbound MB threshold
IMPOSSIBLE_TRAVEL_KM_H    = 800     # speed that implies account sharing or VPN hop

FLAG_BOOSTS = {
    "off_hours_activity":          0.10,
    "excessive_failed_logins":     0.15,
    "impossible_travel":           0.20,
    "privilege_escalation":        0.15,
    "lateral_movement_indicator":  0.15,
    "suspicious_process_chain":    0.12,
    "large_data_transfer":         0.10,
    "new_device_first_seen":       0.08,
}

# Suspicious process parent→child chains
SUSPICIOUS_CHAINS = [
    ("powershell.exe", "cmd.exe"),
    ("powershell.exe", "wscript.exe"),
    ("winword.exe",    "cmd.exe"),
    ("excel.exe",      "powershell.exe"),
    ("outlook.exe",    "cmd.exe"),
    ("explorer.exe",   "powershell.exe"),
    ("svchost.exe",    "cmd.exe"),
]

# Privilege escalation indicators
PRIV_ESC_PROCESSES = {
    "getsystem", "bypassuac", "mimikatz", "whoami /priv",
    "net localgroup administrators", "runas"
}

# Lateral movement port indicators
LATERAL_MOVEMENT_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}


def evaluate(raw_event: dict) -> dict:
    """
    Evaluate a normalized log event for behavioural anomalies.

    Args:
        raw_event: the raw_event block from the feature matrix / log.

    Returns:
        {
          "ueba_flags":      list[str],
          "ueba_risk_boost": float,   # cumulative boost 0.0–1.0 (capped)
          "flag_details":    dict     # per-flag explanation
        }
    """
    flags   = []
    details = {}

    # ---- 1. Off-hours activity ----
    ts_str = raw_event.get("timestamp") or raw_event.get("event_time")
    if ts_str:
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            hour = ts.hour
            if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
                flags.append("off_hours_activity")
                details["off_hours_activity"] = f"event at {hour:02d}:xx, outside {BUSINESS_HOURS_START}–{BUSINESS_HOURS_END}"
        except Exception:
            pass

    # ---- 2. Excessive failed logins ----
    failures = raw_event.get("failed_attempts") or raw_event.get("failed_logins") or 0
    if int(failures) >= FAILED_LOGIN_THRESHOLD:
        flags.append("excessive_failed_logins")
        details["excessive_failed_logins"] = f"{failures} failed attempts (threshold={FAILED_LOGIN_THRESHOLD})"

    # ---- 3. Suspicious process chain ----
    parent = (raw_event.get("parent_process") or "").lower()
    process = (raw_event.get("process") or raw_event.get("child_process") or "").lower()
    if parent and process:
        for (p, c) in SUSPICIOUS_CHAINS:
            if p in parent and c in process:
                flags.append("suspicious_process_chain")
                details["suspicious_process_chain"] = f"{parent} → {process}"
                break

    # ---- 4. Privilege escalation ----
    cmd_line = (raw_event.get("command_line") or raw_event.get("process") or "").lower()
    for indicator in PRIV_ESC_PROCESSES:
        if indicator in cmd_line:
            flags.append("privilege_escalation")
            details["privilege_escalation"] = f"indicator '{indicator}' in command line"
            break

    # ---- 5. Lateral movement ----
    port = raw_event.get("port") or raw_event.get("destination_port")
    action = (raw_event.get("action") or "").lower()
    if port and int(port) in LATERAL_MOVEMENT_PORTS and "allow" in action:
        flags.append("lateral_movement_indicator")
        details["lateral_movement_indicator"] = f"traffic on lateral movement port {port}"

    # ---- 6. Large data transfer ----
    bytes_out = raw_event.get("bytes_out") or raw_event.get("outbound_bytes") or 0
    mb_out = int(bytes_out) / (1024 * 1024)
    if mb_out >= LARGE_TRANSFER_MB:
        flags.append("large_data_transfer")
        details["large_data_transfer"] = f"{mb_out:.1f} MB outbound (threshold={LARGE_TRANSFER_MB} MB)"

    # ---- 7. Impossible travel (basic — requires previous_location in event) ----
    if raw_event.get("impossible_travel") is True:
        flags.append("impossible_travel")
        details["impossible_travel"] = "flagged by upstream geolocation enrichment"

    # ---- 8. New device first seen ----
    if raw_event.get("new_device") is True or raw_event.get("first_seen") is True:
        flags.append("new_device_first_seen")
        details["new_device_first_seen"] = "device not in baseline profile"

    # ---- Compute cumulative risk boost (cap at 0.50 to not overwhelm PyOD score) ----
    boost = sum(FLAG_BOOSTS.get(f, 0.0) for f in flags)
    boost = round(min(boost, 0.50), 4)

    return {
        "ueba_flags":      flags,
        "ueba_risk_boost": boost,
        "flag_details":    details,
    }