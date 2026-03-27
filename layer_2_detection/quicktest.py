import sys
import json
import uuid
from datetime import datetime, timezone

# ─── Import project modules ─────────────────────────────────────────────

sys.path.insert(0, ".")
sys.path.insert(0, "engine_1_anomaly")
sys.path.insert(0, "engine_2_threat_intel")
sys.path.insert(0, "engine_3_correlation")
sys.path.insert(0, "ioc_database")

import detection_orchestrator
import pyod_detector


# ─── Load Layer 1 output ─────────────────────────────────────────────────

with open("layer1_output.json", "r") as f:
    layer1_output = json.load(f)

enriched_logs = (
    layer1_output.get("enriched_logs")
    or layer1_output.get("sample_enriched")
    or []
)

if len(enriched_logs) == 0:
    raise ValueError("No enriched logs found in layer1_output.json")

print(f"Loaded {len(enriched_logs)} events from Layer 1\n")

# ─── Feature extraction (MUST MATCH TRAINING FEATURES) ───────────────────

def extract_feature_vector(event):

    df = event.get("detection_features", {})
    ff = event.get("family_detection_features", {})

    family_map = {
        "network": 0,
        "endpoint": 1,
        "auth": 2,
        "firewall": 3,
        "iot": 4
    }

    family = family_map.get(event.get("log_family", "network"), 0)

    return [

        int(df.get("is_off_hours", False)),
        df.get("event_count_5m", 0),
        df.get("deviation_score", 0.0),

        int(ff.get("spike_detected", False)),
        int(ff.get("protocol_anomaly_detected", False)),
        ff.get("unique_destinations_seen", 0),

        family
    ]


print("Using trained PyOD model for scoring...\n")

# ─── Incident ID generator ───────────────────────────────────────────────

def make_incident_id(timestamp):

    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        date_part = dt.strftime("%Y-%m%d")
    except Exception:
        date_part = datetime.now(timezone.utc).strftime("%Y-%m%d")

    suffix = str(uuid.uuid4()).split("-")[0].upper()

    return f"INC-{date_part}-SOC-{suffix}"


# ─── Main detection loop ─────────────────────────────────────────────────

saved_results = []

for i, event in enumerate(enriched_logs):

    feature_vector = extract_feature_vector(event)

    action = str(event.get("action", "")).lower()
    protocol = str(event.get("network", {}).get("protocol", "")).lower()

    timestamp = event.get(
        "timestamp",
        datetime.now(timezone.utc).isoformat()
    )

    # ─── Flatten event for detection engine ─────────────────────────────

    flattened_raw = {

        "source_ip": event.get("source", {}).get("ip"),
        "destination_ip": event.get("destination", {}).get("ip"),

        "port": event.get("destination", {}).get("port"),
        "protocol": protocol,

        "action": event.get("action", ""),
        "timestamp": timestamp,

        "user": event.get("source", {}).get("user"),

        # MITRE hint from Layer 1
        "mitre_technique": event.get("mitre_technique", ""),

        # UEBA signals
        "failed_attempts": event.get("failed_attempts", 0),

        "is_off_hours": event.get("detection_features", {}).get("is_off_hours", False),

        "brute_force_detected": event.get("pattern_features", {}).get("brute_force_detected", False),
        "exfiltration_detected": event.get("pattern_features", {}).get("exfiltration_detected", False),
        "lateral_movement_detected": event.get("pattern_features", {}).get("lateral_movement_detected", False),
        "port_scan_detected": event.get("pattern_features", {}).get("port_scan_detected", False),

        "protocol_anomaly_detected":
            event.get("family_detection_features", {}).get("protocol_anomaly_detected", False),

        # Action hints
        "action_is_exfiltration": "exfiltration" in action,
        "action_is_bruteforce": "brute" in action,
        "action_is_auth_failure": "auth" in action,
    }

    orchestrator_input = {

        "raw_event": flattened_raw,
        "log_type": event.get("log_family", "network"),

        "feature_vector": feature_vector,

        "timestamp": timestamp,

        "fidelity_score":
            0.7 if event.get("classification_confidence") == "medium"
            else 0.5,
    }

    result = detection_orchestrator.run(orchestrator_input)

    e1 = result["engine_1_anomaly"]
    e2 = result["engine_2_threat_intel"]
    e3 = result["engine_3_correlation"]

    incident_id = make_incident_id(timestamp)

    output_dict = {

        "incident_id": incident_id,
        "timestamp": timestamp,
        "log_type": event.get("log_family", "network"),

        "raw_event": {

            "source_ip": event.get("source", {}).get("ip"),
            "destination_ip": event.get("destination", {}).get("ip"),

            "affected_user": event.get("source", {}).get("user"),
            "affected_host": event.get("source", {}).get("host"),

            "port": event.get("destination", {}).get("port"),
            "protocol": protocol,

            "action": event.get("action"),
            "timestamp": timestamp,
        },

        "engine_1_anomaly": {

            "pyod_score": e1.get("pyod_score", 0),
            "is_outlier": e1.get("is_outlier", False),

            "ueba_flags": e1.get("ueba_flags", []),

            "anomaly_score": e1.get("anomaly_score", 0),
            "anomaly_flagged": e1.get("anomaly_flagged", False),
        },

        "engine_2_threat_intel": {

            "ioc_matches": e2.get("ioc_matches", []),
            "threat_intel_match": bool(e2.get("ioc_matches")),

            "mitre_tactic": e2.get("mitre_tactic", "Unknown"),
            "mitre_technique": e2.get("mitre_technique", "Unknown"),
            "mitre_technique_name": e2.get("mitre_technique_name", "Unknown"),
        },

        "engine_3_correlation": {

            "event_count":
                e3.get("event_count", len(e3.get("attack_timeline", []))),

            "attack_timeline":
                e3.get("attack_timeline", [])
        }
    }

    saved_results.append(output_dict)

    print(f"\nIncident {i+1}")
    print(json.dumps(output_dict, indent=2))


# ─── Save output ─────────────────────────────────────────────────────────

with open("layer2_output.json", "w") as f:
    json.dump(saved_results, f, indent=2)

print(f"\nSaved {len(saved_results)} detection results → layer2_output.json")