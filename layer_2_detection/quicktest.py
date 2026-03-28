import sys
import json
import uuid
import numpy as np
from datetime import datetime, timezone

# ─── Import project modules ───────────────────────────────────────────────────

sys.path.insert(0, ".")
sys.path.insert(0, "engine_1_anomaly")
sys.path.insert(0, "engine_2_threat_intel")
sys.path.insert(0, "engine_3_correlation")
sys.path.insert(0, "ioc_database")

import detection_orchestrator
import pyod_detector

# ─── Load Layer 1 output ──────────────────────────────────────────────────────

with open("layer1_output.json", "r") as f:
    layer1_output = json.load(f)

enriched_logs = layer1_output.get("enriched_logs", [])

# ─── Feature extraction (same 23-vector used earlier) ─────────────────────────

def extract_feature_vector(event: dict) -> list:
    tf  = event.get("temporal_features", {})
    bf  = event.get("behavioral_features", {})
    ff  = event.get("frequency_features", {})
    pf  = event.get("pattern_features", {})
    nf  = event.get("network_traffic_features", {})

    return [
        tf.get("event_count_1m", 0),
        tf.get("event_count_5m", 0),
        tf.get("event_count_15m", 0),
        tf.get("event_count_1h", 0),
        int(tf.get("is_frequency_accelerating", False)),

        bf.get("deviation_score", 0),
        int(bf.get("is_off_hours_for_user", False)),
        int(bf.get("is_new_ip_for_user", False)),
        int(bf.get("excessive_failed_logins", False)),

        ff.get("current_window_count", 0),
        ff.get("zscore", 0),
        int(ff.get("spike_detected", False)),

        int(pf.get("port_scan_detected", False)),
        int(pf.get("brute_force_detected", False)),
        int(pf.get("exfiltration_detected", False)),
        int(pf.get("lateral_movement_detected", False)),
        pf.get("unique_ports_seen", 0),
        pf.get("failed_login_count", 0),

        nf.get("bytes_ratio", 0),
        int(nf.get("is_high_risk_port", False)),
        int(nf.get("is_syn_only", False)),
        nf.get("packet_count", 0),
        nf.get("duration_ms", 0),
    ]

# ─── Fit PyOD model on all events ─────────────────────────────────────────────

print(f"Fitting PyOD on {len(enriched_logs)} events...")

X_train = np.array([extract_feature_vector(e) for e in enriched_logs], dtype=float)

pyod_detector.fit(X_train)

print("PyOD fitted.\n")

# ─── Incident ID generator ────────────────────────────────────────────────────

def make_incident_id(timestamp: str) -> str:

    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        date_part = dt.strftime("%Y-%m%d")
    except Exception:
        date_part = datetime.now(timezone.utc).strftime("%Y-%m%d")

    suffix = uuid.uuid4().hex[:5].upper()

    return f"INC-{date_part}-SOC-{suffix}"

# ─── Main detection loop ──────────────────────────────────────────────────────

saved_results = []

for i, event in enumerate(enriched_logs):

    fv = extract_feature_vector(event)

    bf  = event.get("behavioral_features", {})
    pf  = event.get("pattern_features", {})
    nf  = event.get("network_traffic_features", {})
    up  = event.get("user_profile", {})
    npf = event.get("network_protocol_features", {})

    action    = str(event.get("action", "")).lower()
    protocol  = str(event.get("protocol", "")).lower()
    dest_port = event.get("dest_port") or event.get("destination_port")
    timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    # ─── Flattened raw event passed to detection orchestrator ─────────────────

    flattened_raw = {

        "source_ip":      event.get("source_ip"),
        "destination_ip": event.get("dest_ip"),
        "port":           dest_port,
        "protocol":       protocol,
        "action":         event.get("action", ""),
        "timestamp":      timestamp,
        "user":           event.get("user"),

        # MITRE hint from layer 1
        "mitre_technique": event.get("mitre_technique", ""),

        # UEBA signals
        "failed_attempts":           up.get("failed_login_count", 0),
        "is_off_hours":              event.get("time_windows", {}).get("is_off_hours", False),
        "brute_force_detected":      pf.get("brute_force_detected", False),
        "exfiltration_detected":     pf.get("exfiltration_detected", False),
        "lateral_movement_detected": pf.get("lateral_movement_detected", False),
        "port_scan_detected":        pf.get("port_scan_detected", False),

        "is_off_hours_for_user": bf.get("is_off_hours_for_user", False),
        "is_new_ip_for_user":    bf.get("is_new_ip_for_user", False),

        "protocol_anomaly_detected": npf.get("protocol_anomaly_detected", False),

        # action hints
        "action_is_exfiltration": "exfiltration" in action,
        "action_is_bruteforce":   "brute" in action,
        "action_is_auth_failure": "auth" in action or "authentication" in action,
    }

    orchestrator_input = {
        "raw_event":      flattened_raw,
        "log_type":       event.get("log_family", "network"),
        "feature_vector": fv,
        "fidelity_score": 0.7 if event.get("classification_confidence") == "medium" else 0.5,
        "timestamp":      timestamp,
    }

    result = detection_orchestrator.run(orchestrator_input)

    e1 = result["engine_1_anomaly"]
    e2 = result["engine_2_threat_intel"]
    e3 = result["engine_3_correlation"]

    incident_id = make_incident_id(timestamp)

    output_dict = {

        "incident_id": incident_id,
        "timestamp":   timestamp,
        "log_type":    event.get("log_family", "network"),

        "raw_event": {

            "source_ip":      event.get("source_ip"),
            "destination_ip": event.get("dest_ip"),
            "affected_user":  event.get("user"),
            "affected_host":  event.get("host") or event.get("affected_host"),
            "port":           dest_port,
            "protocol":       protocol,
            "action":         event.get("action", ""),
            "mitre_technique": event.get("mitre_technique", ""),
            "timestamp":      timestamp,
        },

        "engine_1_anomaly": {

            "pyod_score":      e1.get("pyod_score", 0),
            "is_outlier":      e1.get("is_outlier", False),
            "ueba_flags":      e1.get("ueba_flags", []),
            "anomaly_score":   e1.get("anomaly_score", 0),
            "anomaly_flagged": e1.get("anomaly_flagged", False),
        },

        "engine_2_threat_intel": {

            "ioc_matches":        e2.get("ioc_matches", []),
            "threat_intel_match": bool(e2.get("ioc_matches")),
            "mitre_tactic":       e2.get("mitre_tactic", "Unknown"),
            "mitre_technique":    e2.get("mitre_technique", "Unknown"),
            "mitre_technique_name": e2.get("mitre_technique_name", "Unknown"),
        },

        "engine_3_correlation": {

            "event_count":    e3.get("event_count", len(e3.get("attack_timeline", []))),
            "attack_timeline": e3.get("attack_timeline", [])
        }
    }

    saved_results.append(output_dict)

    print(f"\nIncident {i+1}")
    print(json.dumps(output_dict, indent=2))

# ─── Save output ──────────────────────────────────────────────────────────────

with open("layer2_output.json", "w") as f:
    json.dump(saved_results, f, indent=2)

print(f"\nSaved {len(saved_results)} detection results → layer2_output.json")