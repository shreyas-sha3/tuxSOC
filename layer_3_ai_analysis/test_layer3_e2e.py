import json
from ai_orchestrator import run_ai_analysis

# 1. This is your high-fidelity mock data (as requested)
high_fidelity_incident = log_3 = scenario_5_lolbin = [
  {
  "incident_id": "INC-2024-0405-SOC-94306395",
  "timestamp": "2024-04-05T03:10:22Z",
  "log_type": "network",
  "raw_event": {
    "source_ip": "10.0.4.233",
    "destination_ip": "91.195.240.6",
    "affected_user": null,
    "affected_host": "laptop-019",
    "port": 53,
    "protocol": "dns",
    "action": "Abnormal DNS TXT record flood - data exfil via DNS",
    "timestamp": "2024-04-05T03:10:22Z"
  },
  "engine_1_anomaly": {
    "pyod_score": 0.7449,
    "is_outlier": false,
    "ueba_flags": [
      "off_hours_activity"
    ],
    "anomaly_score": 0.8449,
    "anomaly_flagged": true
  },
  "engine_2_threat_intel": {
    "ioc_matches": [],
    "threat_intel_match": false,
    "mitre_tactic": "Defense Evasion",
    "mitre_technique": "T1078",
    "mitre_technique_name": "Valid Accounts"
  },
  "engine_3_correlation": {
    "event_count": 2,
    "attack_timeline": [
      {
        "timestamp": "2024-04-05T03:10:22+00:00",
        "event": "firewall_action",
        "detail": "ABNORMAL DNS TXT RECORD FLOOD - DATA EXFIL VIA DNS from 10.0.4.233 \u2192 91.195.240.6 on port 53"
      },
      {
        "timestamp": "2024-04-05T03:10:22+00:00",
        "event": "anomaly_detected",
        "detail": "Anomaly detected \u2014 score 0.84, fidelity 0.33"
      },
      {
        "timestamp": "2024-04-05T03:10:22+00:00",
        "event": "behavioral_anomaly",
        "detail": "Behavioural flags raised: off_hours_activity"
      }
    ]
  }
}
]

print("\n================ HIGH-FIDELITY TEST START ================\n")

# Run the full LangGraph AI Analysis
# Note: We are passing it as a list [incident] to trigger your Batch Logic
result = run_ai_analysis([high_fidelity_incident])

# 2. Extract and display the Banking Report
ai = result.get("ai_analysis", {})

if ai.get("ai_failed"):
    print(f"❌ ANALYSIS FAILED: {ai.get('ai_failure_reason')}")
else:
    print(f"✅ ANALYSIS SUCCESSFUL")
    print("-" * 50)
    print(f"INTENT     : {ai.get('intent')}")
    print(f"SEVERITY   : {ai.get('severity')}")
    print(f"CVSS VECTOR: {ai.get('cvss_vector')}")
    print(f"NARRATIVE  : {ai.get('narrative')}")
    print("-" * 50)
    print("RECOMMENDED ACTIONS:")
    for action in ai.get("recommended_actions", []):
        print(f"  - {action}")

print("\n================ TEST COMPLETE ================\n")