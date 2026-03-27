import requests
import json
import time

# 1. The Mock Input from AI Analysis (Layer 3)
# 1. The Mock Input from AI Analysis (Layer 3)
simulated_threat = {
    "event_id": "evt_99x_brute",
    "ai_analysis": {
        "intent": "Internal Brute Force — Credential Access via SSH",
        "severity": "high",
        "cvss_vector": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"
        },
        # ADDED THESE THREE REQUIRED FIELDS:
        "narrative": "Attacker successfully brute-forced SSH credentials after 50 attempts.",
        "recommended_actions": ["Isolate host", "Reset credentials"],
        "ai_failed": False,
        
        "cis_violations": [
            {
                "rule_id": "CIS-AUTH-002",
                "cvss_impact": {"metric": "PR", "escalate_to": "N"}
            }
        ]
    }
}
print("🚀 [TEST] Firing Simulated Threat into Layer 4 (CVSS Scoring)...")
try:
    # 2. Hit Layer 4
    l4_response = requests.post("http://localhost:8004/api/v1/score", json=simulated_threat)
    l4_data = l4_response.json()
    print(f"✅ [LAYER 4 SUCCESS] Scored as {l4_data['severity']} ({l4_data['base_score']}/10.0)")
    
    time.sleep(1) # Dramatic pause for the demo
    
    # 3. Construct Payload for Layer 5
    l5_payload = {
        "event_id": l4_data["event_id"],
        "base_score": l4_data["base_score"],
        "severity": l4_data["severity"],
        "requires_auto_block": l4_data["requires_auto_block"],
        "attacker_ip": "185.220.101.45", # Simulating data passed from ingestion
        "affected_entity": "SRV-WEB01",
        "intent": simulated_threat["ai_analysis"]["intent"]
    }
    
    print("\n⚡ [TEST] Forwarding scored incident to Layer 5 (Response)...")
    
    # 4. Hit Layer 5
    l5_response = requests.post("http://localhost:8005/api/v1/respond", json=l5_payload)
    
    print("\n🎉 [PIPELINE COMPLETE] Final Response from Layer 5:")
    print(json.dumps(l5_response.json(), indent=2))
    
except Exception as e:
    print(f"❌ [ERROR] Make sure both Layer 4 (8004) and Layer 5 (8005) servers are running! Details: {e}")