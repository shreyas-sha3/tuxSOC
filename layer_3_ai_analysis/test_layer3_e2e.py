import json
from ai_orchestrator import run_ai_analysis

# 1. This is your high-fidelity mock data (as requested)
high_fidelity_incident = log_3 = scenario_5_lolbin = [
  {
    "incident_id": "INC-2026-0326-REAL-ATTACK",
    "timestamp": "2026-03-26T04:20:00+00:00",
    "log_type": "network",
    "raw_event": {
      "source_ip": "10.0.3.18",
      "destination_ip": "194.5.6.7", 
      "affected_user": "jdoe_contractor",
      "affected_host": "DEV-LAPTOP-04",
      "port": 443,
      "protocol": "tcp",
      "action": "Outbound Transfer",
      "mitre_technique": "T1048",
      "timestamp": "2026-03-26T04:20:00+00:00"
    },
    "engine_1_anomaly": {
      "pyod_score": 0.92,
      "is_outlier": True,
      "anomaly_flagged": True
    },
    "engine_2_threat_intel": {
      "ioc_matches": ["blacklisted_ip_russia"],
      "threat_intel_match": True,
      "mitre_tactic": "Exfiltration"
    },
    "engine_3_correlation": {
      "event_count": 1,
      "attack_timeline": [
        {"timestamp": "04:20:00", "event": "data_leak", "detail": "50GB sent to 194.5.6.7 (External/Untrusted)"}
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