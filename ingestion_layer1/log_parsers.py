""""
Parsing layer: no ECS mapping.

- detect_file_format(filename, content_preview) → format
- parse_*_line(line) → raw dict
- file_to_parsed_list(filepath) → List[raw_log_dict]
"""

import os
import json
import csv
import re
from typing import Dict, Any, List, Optional, Callable

try:
    import pycef
    PYCEF_AVAILABLE = True
except ImportError:
    PYCEF_AVAILABLE = False


def detect_file_format(filename: str, content_preview: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    lower_preview = content_preview.lower()

    if ext in ['.json', '.jsonl']:
        return "json"
    elif ext == '.cef':
        return "cef"
    elif ext in ['.log', '.syslog', '.txt']:
        if 'cef:0|' in lower_preview:
            return "cef"
        elif re.search(r'\w{3,4}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', lower_preview):
            return "syslog"
        else:
            return "keyvalue"
    elif ext == '.csv':
        return "csv"
    else:
        if 'cef:0|' in lower_preview:
            return "cef"
        elif lower_preview.startswith('{'):
            return "json"
        else:
            return "syslog"


def parse_syslog_line(line: str) -> Dict[str, Any]:
    """
    Parses RFC-style syslog line:
        <PRI>Mar 25 10:15:23 fw01 kernel: ... message ...
    """
    syslog_re = r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+):?\s*(.*)$'
    match = re.match(syslog_re, line)
    if not match:
        return {"raw_message": line}

    pri, ts, host, msg = match.groups()
    result = {
        "priority": pri,
        "timestamp": ts,
        "hostname": host,
        "message": msg,
    }

    # ── IPs ───────────────────────────────────────────────
    # Collect all IPs found in message
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', msg)
    if len(ips) >= 1:
        result["src_ip"] = ips[0]
    if len(ips) >= 2:
        result["dst_ip"] = ips[1]

    # ── Source port ───────────────────────────────────────
    # Handles: SPT=54321, src_port=54321, sport=54321, "port 54321"
    src_port_match = re.search(
        r'(?:SPT|src_port|sport)=(\d+)|(?:\bport\s+(\d+))',
        msg, re.IGNORECASE
    )
    if src_port_match:
        result["src_port"] = int(
            src_port_match.group(1) or src_port_match.group(2)
        )

    # ── Destination port ──────────────────────────────────
    # Handles: DPT=22, dst_port=22, dport=22, "-> IP:22", ":22" at end
    dst_port_match = re.search(
        r'(?:DPT|dst_port|dport)=(\d+)|(?:->.*?:(\d+))|(?::\b(\d{2,5})\b\s*$)',
        msg, re.IGNORECASE
    )
    if dst_port_match:
        result["dst_port"] = int(
            dst_port_match.group(1) or
            dst_port_match.group(2) or
            dst_port_match.group(3)
        )

    # ── Protocol ─────────────────────────────────────────
    # Handles: PROTO=TCP, proto=udp, or bare TCP/UDP/ICMP keyword
    protocol_match = re.search(
        r'(?:PROTO=|proto=)(\w+)|\b(TCP|UDP|ICMP)\b',
        msg, re.IGNORECASE
    )
    if protocol_match:
        result["protocol"] = (
            protocol_match.group(1) or protocol_match.group(2)
        ).upper()

    # ── Bytes ─────────────────────────────────────────────
    # Handles: LEN=64, bytes=1024, len=84
    bytes_match = re.search(r'(?:LEN|bytes|len)=(\d+)', msg, re.IGNORECASE)
    if bytes_match:
        result["bytes_in"] = int(bytes_match.group(1))

    # ── HTTP fields (webproxy lines) ──────────────────────
    # e.g: HTTP GET /admin from 10.0.4.50 user_agent=Mozilla/5.0 status=403 bytes=1024
    http_method_match = re.search(
        r'\bHTTP\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b',
        msg, re.IGNORECASE
    )
    if http_method_match:
        result["method"] = http_method_match.group(1).upper()

    url_path_match = re.search(r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)', msg, re.IGNORECASE)
    if url_path_match:
        result["path"] = url_path_match.group(1)

    status_match = re.search(r'\bstatus=(\d{3})\b', msg, re.IGNORECASE)
    if status_match:
        result["status_code"] = int(status_match.group(1))

    ua_match = re.search(r'user_agent=(\S+)', msg, re.IGNORECASE)
    if ua_match:
        result["user_agent"] = ua_match.group(1)

    # ── Username ──────────────────────────────────────────
    # Handles: "for root from", "for mlee from", sudo lines
    user_match = re.search(r'(?:for\s+(\w+)\s+from|sudo:\s+(\w+)\s+:)', msg, re.IGNORECASE)
    if user_match:
        result["username"] = user_match.group(1) or user_match.group(2)

    result["raw_message"] = line
    return result


def parse_cef_line(line: str) -> Dict[str, Any]:
    if PYCEF_AVAILABLE:
        try:
            parsed = pycef.parse(line)
            if isinstance(parsed, dict):
                parsed.setdefault("raw_message", line)
                return parsed
        except Exception:
            pass

    parts = line.split(' CEF:0|', 1)
    if len(parts) > 1:
        return {
            "cef_device": parts[0].strip(),
            "cef_payload": parts[1].strip(),
            "raw_message": line
        }
    return {"raw_message": line}


def parse_json_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except Exception:
        return None


def parse_csv_line(row: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    if "timestamp" in row:
        result["timestamp"] = row["timestamp"]
    if "host" in row:
        result["hostname"] = row["host"]
    if "src_ip" in row:
        result["src_ip"] = row["src_ip"]
    if "dst_ip" in row:
        result["dst_ip"] = row["dst_ip"]
    if "src_port" in row:
        result["src_port"] = int(row["src_port"]) if row["src_port"] else None
    if "dst_port" in row:
        result["dst_port"] = int(row["dst_port"]) if row["dst_port"] else None
    if "protocol" in row:
        result["protocol"] = row["protocol"]
    if "username" in row:
        result["username"] = row["username"]
    if "bytes_in" in row:
        result["bytes_in"] = float(row["bytes_in"]) if row["bytes_in"] else None
    if "device_id" in row:
        result["device_id"] = row["device_id"]
    if "device_type" in row:
        result["device_type"] = row["device_type"]
    if "topic" in row:
        result["topic"] = row["topic"]
    if "command" in row:
        result["command"] = row["command"]
    if "telemetry" in row or "telemetry_value" in row:
        key = "telemetry" if "telemetry" in row else "telemetry_value"
        val = row[key]
        result["telemetry_value"] = float(val) if val else None

    result["raw_message"] = json.dumps(row)
    return result


def parse_keyvalue_line(line: str) -> Dict[str, Any]:
    result = {}
    parts = re.split(r'\s+|,', line)
    for part in parts:
        if '=' in part:
            try:
                k, v = part.split('=', 1)
                k = k.strip()
                v = v.strip()
                if v.isdigit():
                    v = int(v)
                elif v.replace('.', '').replace('-', '').isdigit() and v.count('.') <= 1:
                    v = float(v)
                result[k] = v
            except Exception:
                result.setdefault("raw_message_parts", []).append(part)
        else:
            result.setdefault("raw_message_parts", []).append(part)

    if "src_ip" in result and "dst_ip" not in result:
        ip_parts = [x for x in result.get("raw_message_parts", [])
                    if re.match(r'\d+\.\d+\.\d+\.\d+', x)]
        if ip_parts and len(ip_parts) > 1:
            result["dst_ip"] = ip_parts[1]

    result["raw_message"] = line
    return result

def file_to_parsed_list(filepath: str) -> List[Dict[str, Any]]:
    parsed_logs: List[Dict[str, Any]] = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        preview_lines = [f.readline() for _ in range(5)]

    preview = ''.join(preview_lines)
    base_format = detect_file_format(os.path.basename(filepath), preview)

    # ── CSV needs DictReader — handle separately ──────────
    if base_format == "csv":
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for line_num, row in enumerate(reader, 2):  # start at 2 — row 1 is header
                raw_log = parse_csv_line(dict(row))
                raw_log.setdefault("format", "csv")
                raw_log["source_file"] = os.path.basename(filepath)
                raw_log["source_line"] = line_num
                parsed_logs.append(raw_log)
        return parsed_logs

    # ── All other formats — line by line ──────────────────
    PARSER_MAP: Dict[str, Callable[[str], Dict[str, Any]]] = {
        "syslog":   parse_syslog_line,
        "cef":      parse_cef_line,
        "json":     lambda line: parse_json_line(line) or {"raw_message": line},
        "jsonl":    lambda line: parse_json_line(line) or {"raw_message": line},
        "keyvalue": parse_keyvalue_line,
    }

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parser = PARSER_MAP.get(base_format, parse_keyvalue_line)
            raw_log = parser(line)

            raw_log.setdefault("format", base_format)
            raw_log["source_file"] = os.path.basename(filepath)
            raw_log["source_line"] = line_num

            parsed_logs.append(raw_log)

    return parsed_logs