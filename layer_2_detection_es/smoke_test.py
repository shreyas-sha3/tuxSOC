"""
smoke_test.py — Layer-2 ES Engine verification
"""
import sys
sys.path.insert(0, "..")

print("=== Layer-2 ES Engine Smoke Test ===\n")

# 1. ES connectivity
from layer_2_detection_es.elastic_client import get_client
es = get_client()
print(f"[1] ES ping: {es.ping()}")

# 2. Rules registry
from layer_2_detection_es.rules_registry import get_enabled_rules, get_rules_by_category
rules = get_enabled_rules()
print(f"[2] Rules loaded: {len(rules)} total")
for cat in ["web", "auth", "endpoint", "network"]:
    n = len(get_rules_by_category(cat))
    print(f"    {cat}: {n} rules")

# 3. Suppression engine
from layer_2_detection_es.suppression_engine import record_alert, is_suppressed, clear_all
record_alert("AUTH_BRUTEFORCE", "1.2.3.4", 300)
assert is_suppressed("AUTH_BRUTEFORCE", "1.2.3.4"), "Suppression should be active"
clear_all()
assert not is_suppressed("AUTH_BRUTEFORCE", "1.2.3.4"), "Suppression should be cleared"
print("[3] Suppression engine: OK")

# 4. MITRE mapper
from layer_2_detection_es.mitre_mapper import get_technique, map_detections_to_mitre
t = get_technique("T1110")
assert t["technique_name"] == "Brute Force"
assert t["tactic"] == "Credential Access"
dets = [{"mitre": "T1110"}, {"mitre": "T1046"}, {"mitre": "T1110"}]
mapped = map_detections_to_mitre(dets)
assert len(mapped) == 2, f"Expected 2 unique techniques, got {len(mapped)}"
print(f"[4] MITRE mapper: OK — {[m['technique_id'] for m in mapped]}")

# 5. Incident merger
from layer_2_detection_es.incident_merger import merge_detections
fake_dets = [
    {
        "rule_id": "AUTH_BRUTEFORCE", "category": "auth", "severity": "high",
        "risk_weight": 0.8, "confidence": 0.9, "mitre": "T1110",
        "source_ip": "10.0.0.1", "affected_user": "alice",
        "affected_host": "ws-01", "destination_ip": "",
        "timestamp": "2026-03-28T10:00:00Z", "context": {}, "raw_event": {},
    },
    {
        "rule_id": "NET_LATERAL", "category": "network", "severity": "high",
        "risk_weight": 0.85, "confidence": 0.87, "mitre": "T1021",
        "source_ip": "10.0.0.1", "affected_user": "alice",
        "affected_host": "ws-02", "destination_ip": "",
        "timestamp": "2026-03-28T10:02:00Z", "context": {}, "raw_event": {},
    },
    {
        "rule_id": "NET_EXFIL", "category": "network", "severity": "critical",
        "risk_weight": 0.95, "confidence": 0.90, "mitre": "T1048",
        "source_ip": "10.0.0.99", "affected_user": "bob",
        "affected_host": "", "destination_ip": "",
        "timestamp": "2026-03-28T10:01:00Z", "context": {}, "raw_event": {},
    },
]
clusters = merge_detections(fake_dets)
print(f"[5] Incident merger: {len(fake_dets)} detections -> {len(clusters)} cluster(s)")
for c in clusters:
    print(f"    rules={c['rule_ids']}  entities={c['entities']}")

# 6. Risk engine
from layer_2_detection_es.risk_engine import compute_risk
ueba_mock = {"anomaly_score": 0.6, "ueba_flags": [], "anomaly_flagged": True}
risk = compute_risk(clusters[0], ueba_mock, ioc_count=2)
print(f"[6] Risk engine: score={risk['risk_score']} severity={risk['severity']} confidence={risk['confidence']}")

# 7. Incident builder
from layer_2_detection_es.incident_builder import build_incident
inc = build_incident(clusters[0], risk, ueba_mock)
assert inc["incident_id"].startswith("INC-")
assert inc["severity"] in ("low", "medium", "high", "critical")
assert len(inc["mitre_attack"]) > 0
print(f"[7] Incident builder: id={inc['incident_id']} severity={inc['severity']} risk={inc['risk_score']}")
print(f"    summary : {inc['incident_summary']}")
print(f"    mitre   : {[m['technique_id'] for m in inc['mitre_attack']]}")
print(f"    rules   : {inc['rule_ids']}")

# 8. Baseline engine (no-op when ES empty)
from layer_2_detection_es.baseline_engine import compute_baselines, baselines_ready
assert not baselines_ready()
compute_baselines()
assert baselines_ready()
print("[8] Baseline engine: computed (empty ES — baselines are empty dicts, which is correct)")

# 9. UEBA engine (no-op when ES empty)
from layer_2_detection_es.ueba_engine import run_ueba
ueba = run_ueba(lookback_minutes=60)
assert "ueba_flags" in ueba
assert "anomaly_score" in ueba
print(f"[9] UEBA engine: flags={len(ueba['ueba_flags'])} score={ueba['anomaly_score']}")

# 10. Replay engine import
from layer_2_detection_es.replay_engine import run_detection_replay
print("[10] Replay engine: import OK")

# 11. Orchestrator import
from layer_2_detection_es.layer2_es_orchestrator import run_once
print("[11] Orchestrator: import OK")

print("\n=== ALL CHECKS PASSED ===")
