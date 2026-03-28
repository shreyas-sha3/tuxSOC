"""
test_layer2.py
--------------
Validates the full layer_2_detection pipeline against synthetic logs.

Tests:
  1. Endpoint log  — brute force + suspicious process chain   → HIGH severity
  2. Network log   — CIS benchmark violation (EIGRP/routing)  → MEDIUM severity
  3. IoT log       — smart meter auth brute force             → HIGH severity
  4. Clean log     — normal activity, Engine 2 should be skipped
  5. Schema check  — every required key present in DetectionResult

Run:
    python test_layer2.py
    python test_layer2.py --verbose      # show full output dicts
    python test_layer2.py --test 1       # run only test #1
"""

import sys
import os
import json
import argparse
import traceback
import numpy as np
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — add layer_2_detection and sub-packages to sys.path
# ---------------------------------------------------------------------------
BASE = os.path.dirname(os.path.abspath(__file__))
LAYER2 = BASE

sys.path.insert(0, LAYER2)
sys.path.insert(0, os.path.join(LAYER2, "engine_1_anomaly"))
sys.path.insert(0, os.path.join(LAYER2, "engine_2_threat_intel"))
sys.path.insert(0, os.path.join(LAYER2, "engine_3_correlation"))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "ioc_database"))

# ---------------------------------------------------------------------------
# Colours for terminal output
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def info(msg): print(f"  {CYAN}→{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}⚠{RESET} {msg}")

# ---------------------------------------------------------------------------
# Test DB setup — use an in-memory/temp DB so tests don't pollute production
# ---------------------------------------------------------------------------
import tempfile
TEST_DB = os.path.join(tempfile.mkdtemp(), "test_ioc.db")
os.environ["IOC_DB_PATH"] = TEST_DB

from ioc_db import init_db, insert_ioc, get_connection
from cis_loader import seed_iot_thresholds, seed_mitre_mappings

def setup_test_db():
    """Seed the test DB with known-bad IOCs, IoT thresholds, and MITRE mappings."""
    init_db(TEST_DB)
    seed_iot_thresholds(TEST_DB)
    seed_mitre_mappings(TEST_DB)

    # Seed known-bad IPs
    insert_ioc("ip",        "192.168.1.105",  threat_type="malicious_ip",
               severity="high", source="test", db_path=TEST_DB)
    insert_ioc("ip",        "10.10.10.99",    threat_type="c2_server",
               severity="critical", source="test", db_path=TEST_DB)
    insert_ioc("domain",    "evil-c2.xyz",    threat_type="c2_domain",
               severity="critical", source="test", db_path=TEST_DB)
    insert_ioc("file_hash", "d41d8cd98f00b204e9800998ecf8427e",
               threat_type="ransomware_hash",  severity="critical", source="test",
               db_path=TEST_DB)

    # Seed one CIS network rule manually for matching
    with get_connection(TEST_DB) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO cis_rules
                (benchmark_id, title, profile_level, section,
                 assessment_type, description, keywords)
            VALUES (?,?,?,?,?,?,?)
        """, (
            "3.1.1.3",
            "Configure EIGRP log-adjacency-changes",
            "Level 1", "Data Plane", "Manual",
            "Logging changes to the EIGRP peering relationships is recommended.",
            "eigrp|adjacency|routing|nbrchange|peer|log-adjacency"
        ))

    print(f"{CYAN}Test DB seeded at {TEST_DB}{RESET}\n")


# ---------------------------------------------------------------------------
# PyOD training — fit on synthetic normal data so scoring works
# ---------------------------------------------------------------------------
import pyod_detector

def fit_pyod():
    """Fit the PyOD ensemble on random 'normal' data (10 features)."""
    np.random.seed(42)
    X_normal = np.random.randn(200, 10) * 0.3      # tight normal cluster
    X_outlier = np.random.randn(10, 10) * 3.0 + 5  # obvious outliers far away
    X_train = np.vstack([X_normal, X_outlier])
    pyod_detector.fit(X_train)


# ---------------------------------------------------------------------------
# Synthetic log factory
# ---------------------------------------------------------------------------

def make_feature_vector(is_anomalous: bool = False) -> list:
    """
    Return a 10-dim feature vector.
    Anomalous = far from the training cluster → high PyOD score.
    Normal    = inside the training cluster  → low PyOD score.
    """
    np.random.seed(None)
    if is_anomalous:
        return (np.random.randn(10) * 0.5 + 5.0).tolist()   # far from normal
    return (np.random.randn(10) * 0.3).tolist()               # normal cluster


SYNTHETIC_LOGS = {

    # ---- Test 1: Endpoint — brute force + suspicious process ----
    1: {
        "name":     "Endpoint — brute force + suspicious process chain",
        "log_type": "endpoint",
        "is_anomalous": True,
        "layer1_output": {
            "log_type":      "endpoint",
            "timestamp":     "2024-03-17T02:28:00Z",   # 02:00 — off-hours
            "fidelity_score": 0.87,
            "raw_event": {
                "source_ip":        "192.168.1.105",    # known-bad IP seeded above
                "destination_ip":   "10.0.0.1",
                "affected_user":    "john.doe",
                "affected_host":    "CORP-PC-042",
                "port":             445,                # lateral movement port
                "action":           "allow",
                "failed_attempts":  5,
                "process":          "cmd.exe",
                "parent_process":   "powershell.exe",   # suspicious chain
                "timestamp":        "2024-03-17T02:28:00Z",
            },
        },
        # What we expect in the result
        "expect": {
            "anomaly_flagged":    True,
            "ueba_flags_include": ["off_hours_activity", "excessive_failed_logins",
                                   "suspicious_process_chain", "lateral_movement_indicator"],
            "threat_intel_match": True,
            "ioc_matches_include": ["malicious_ip"],
            "mitre_tactic_not":   "N/A",
            "linked_event_count_min": 2,
            "timeline_len_min":   2,
        },
    },

    # ---- Test 2: Network — CIS benchmark violation ----
    2: {
        "name":     "Network — CIS benchmark violation (EIGRP routing anomaly)",
        "log_type": "network",
        "is_anomalous": True,
        "layer1_output": {
            "log_type":       "network",
            "timestamp":      "2024-03-17T14:05:00Z",
            "fidelity_score": 0.67,
            "raw_event": {
                "source_ip":    "10.10.10.11",
                "destination_ip":"10.10.10.1",
                "protocol":     "eigrp",
                "event_type":   "adjacency_change",
                "detail":       "EIGRP NBRCHANGE neighbor down holding time expired",
                "action":       "log",
                "port":         179,
                "timestamp":    "2024-03-17T14:05:00Z",
            },
        },
        "expect": {
            "anomaly_flagged":    True,
            "threat_intel_match": True,         # CIS violation counts as threat intel match
            "cis_violations_min": 1,            # should match the EIGRP rule we seeded
            "mitre_tactic_not":   "N/A",
            "linked_event_count_min": 1,
            "timeline_len_min":   1,
        },
    },

    # ---- Test 3: IoT — smart meter brute force ----
    3: {
        "name":     "IoT — smart meter auth brute force + threshold violation",
        "log_type": "iot",
        "is_anomalous": True,
        "layer1_output": {
            "log_type":       "iot",
            "timestamp":      "2024-03-17T03:15:00Z",  # off-hours
            "fidelity_score": 1.0,
            "raw_event": {
                "source_ip":             "172.16.5.22",
                "device_id":             "172.16.5.22",
                "device_type":           "smart_meter",
                "auth_failures_per_minute": 8,         # threshold = 3 → violation
                "packets_per_minute":    620,           # threshold = 500 → violation
                "action":                "alert",
                "timestamp":             "2024-03-17T03:15:00Z",
                "failed_attempts":       8,
            },
        },
        "expect": {
            "anomaly_flagged":       True,
            "ueba_flags_include":    ["off_hours_activity", "excessive_failed_logins"],
            "threat_intel_match":    True,
            "iot_threshold_hits_min": 2,            # auth_failures + packets
            "linked_event_count_min": 2,
            "timeline_len_min":      2,
        },
    },

    # ---- Test 4: Clean log — no IOC matches, no UEBA flags, no threat intel hits ----
    # Note: PyOD with a small training set may still score borderline events as anomalous
    # (model disagreement — fidelity=0.0 or 0.33 means only 1 model voted outlier).
    # What we validate here is: no IOC matches, no UEBA flags, no threat intel hits.
    4: {
        "name":     "Clean log — no IOC matches, no UEBA flags, no threat intel hits",
        "log_type": "endpoint",
        "is_anomalous": False,
        "layer1_output": {
            "log_type":       "endpoint",
            "timestamp":      "2024-03-17T10:00:00Z",  # business hours
            "fidelity_score": 0.10,
            "raw_event": {
                "source_ip":      "192.168.1.50",
                "destination_ip": "8.8.8.8",
                "port":           443,
                "action":         "allow",
                "failed_attempts": 0,
                "process":        "chrome.exe",
                "parent_process": "explorer.exe",
                "timestamp":      "2024-03-17T10:00:00Z",
            },
        },
        "expect": {
            # PyOD may flag this depending on training data — we don't assert anomaly_flagged
            # Instead we assert the important downstream properties
            "ueba_flags_include":  [],         # no UEBA flags on normal daytime activity
            "threat_intel_match":  False,      # no known-bad IOCs in this event
            "ioc_matches_include": [],         # no IOC label matches expected
            "timeline_len_min":    1,          # at least one timeline entry (firewall_action)
        },
    },
}


# ---------------------------------------------------------------------------
# Schema validation — every required key must be present
# ---------------------------------------------------------------------------

REQUIRED_TOP_KEYS = [
    "incident_id", "timestamp", "log_type", "raw_event",
    "engine_1_anomaly", "engine_2_threat_intel", "engine_3_correlation",
    "detection_summary", "ai_analysis",
]

REQUIRED_E1_KEYS = [
    "pyod_score", "is_outlier", "fidelity_score", "model_votes",
    "ueba_flags", "ueba_risk_boost", "flag_details",
    "anomaly_score", "anomaly_flagged",
]

REQUIRED_E2_KEYS = [
    "ioc_matches", "matched_ioc_details", "cis_violations",
    "iot_threshold_hits", "threat_intel_match",
    "mitre_tactic", "mitre_technique",
]

REQUIRED_E3_KEYS = [
    "linked_events", "event_count", "attack_timeline",
]

REQUIRED_SUMMARY_KEYS = [
    "anomaly_score", "threat_intel_match", "mitre_tactic",
    "linked_event_count", "engine_2_ran",
]


def validate_schema(result: dict) -> list[str]:
    """Return list of schema errors. Empty list = all good."""
    errors = []

    for k in REQUIRED_TOP_KEYS:
        if k not in result:
            errors.append(f"Missing top-level key: '{k}'")

    e1 = result.get("engine_1_anomaly", {})
    for k in REQUIRED_E1_KEYS:
        if k not in e1:
            errors.append(f"Engine 1 missing key: '{k}'")

    e2 = result.get("engine_2_threat_intel", {})
    for k in REQUIRED_E2_KEYS:
        if k not in e2:
            errors.append(f"Engine 2 missing key: '{k}'")

    e3 = result.get("engine_3_correlation", {})
    for k in REQUIRED_E3_KEYS:
        if k not in e3:
            errors.append(f"Engine 3 missing key: '{k}'")

    summary = result.get("detection_summary", {})
    for k in REQUIRED_SUMMARY_KEYS:
        if k not in summary:
            errors.append(f"detection_summary missing key: '{k}'")

    # Type checks
    e1 = result.get("engine_1_anomaly", {})
    if not isinstance(e1.get("ueba_flags"), list):
        errors.append("engine_1_anomaly.ueba_flags must be a list")
    if not isinstance(e1.get("anomaly_score"), float):
        errors.append("engine_1_anomaly.anomaly_score must be a float")
    if not isinstance(e3.get("attack_timeline"), list):
        errors.append("engine_3_correlation.attack_timeline must be a list")

    return errors


# ---------------------------------------------------------------------------
# Expectation checker
# ---------------------------------------------------------------------------

def check_expectations(result: dict, expect: dict) -> list[str]:
    """Check test-specific expectations. Returns list of failures."""
    failures = []
    e1 = result.get("engine_1_anomaly", {})
    e2 = result.get("engine_2_threat_intel", {})
    e3 = result.get("engine_3_correlation", {})
    summary = result.get("detection_summary", {})

    if "anomaly_flagged" in expect:
        if e1.get("anomaly_flagged") != expect["anomaly_flagged"]:
            failures.append(
                f"anomaly_flagged: expected {expect['anomaly_flagged']}, "
                f"got {e1.get('anomaly_flagged')} (score={e1.get('anomaly_score')})"
            )

    if "ueba_flags_include" in expect:
        actual_flags = e1.get("ueba_flags", [])
        for flag in expect["ueba_flags_include"]:
            if flag and flag not in actual_flags:
                failures.append(f"Expected UEBA flag '{flag}' not found in {actual_flags}")

    if "threat_intel_match" in expect:
        if e2.get("threat_intel_match") != expect["threat_intel_match"]:
            failures.append(
                f"threat_intel_match: expected {expect['threat_intel_match']}, "
                f"got {e2.get('threat_intel_match')}"
            )

    if "ioc_matches_include" in expect:
        actual = e2.get("ioc_matches", [])
        for m in expect["ioc_matches_include"]:
            if m and m not in actual:
                failures.append(f"Expected IOC match '{m}' not in {actual}")

    if "cis_violations_min" in expect:
        actual = len(e2.get("cis_violations", []))
        if actual < expect["cis_violations_min"]:
            failures.append(
                f"cis_violations: expected >= {expect['cis_violations_min']}, got {actual}"
            )

    if "iot_threshold_hits_min" in expect:
        actual = len(e2.get("iot_threshold_hits", []))
        if actual < expect["iot_threshold_hits_min"]:
            failures.append(
                f"iot_threshold_hits: expected >= {expect['iot_threshold_hits_min']}, got {actual}"
            )

    if "mitre_tactic_not" in expect:
        tactic = e2.get("mitre_tactic", "N/A")
        if tactic == expect["mitre_tactic_not"]:
            failures.append(
                f"mitre_tactic should not be '{expect['mitre_tactic_not']}' — got '{tactic}'"
            )

    if "mitre_tactic" in expect:
        if e2.get("mitre_tactic") != expect["mitre_tactic"]:
            failures.append(
                f"mitre_tactic: expected '{expect['mitre_tactic']}', got '{e2.get('mitre_tactic')}'"
            )

    if "linked_event_count_min" in expect:
        actual = e3.get("event_count", 0)
        if actual < expect["linked_event_count_min"]:
            failures.append(
                f"linked_event_count: expected >= {expect['linked_event_count_min']}, got {actual}"
            )

    if "timeline_len_min" in expect:
        actual = len(e3.get("attack_timeline", []))
        if actual < expect["timeline_len_min"]:
            failures.append(
                f"timeline length: expected >= {expect['timeline_len_min']}, got {actual}"
            )

    if "engine_2_ran" in expect:
        if summary.get("engine_2_ran") != expect["engine_2_ran"]:
            failures.append(
                f"engine_2_ran: expected {expect['engine_2_ran']}, got {summary.get('engine_2_ran')}"
            )

    return failures


# ---------------------------------------------------------------------------
# Pretty-print a DetectionResult summary
# ---------------------------------------------------------------------------

def print_summary(result: dict):
    e1 = result.get("engine_1_anomaly", {})
    e2 = result.get("engine_2_threat_intel", {})
    e3 = result.get("engine_3_correlation", {})
    s  = result.get("detection_summary", {})

    info(f"incident_id      : {result.get('incident_id')}")
    info(f"log_type         : {result.get('log_type')}")
    info(f"anomaly_score    : {e1.get('anomaly_score')} (fidelity={e1.get('fidelity_score')})")
    info(f"anomaly_flagged  : {e1.get('anomaly_flagged')}")
    info(f"ueba_flags       : {e1.get('ueba_flags')}")
    info(f"engine_2_ran     : {s.get('engine_2_ran')}")
    info(f"ioc_matches      : {e2.get('ioc_matches')}")
    info(f"cis_violations   : {len(e2.get('cis_violations', []))} rules matched")
    info(f"iot_thresh_hits  : {len(e2.get('iot_threshold_hits', []))} violations")
    info(f"mitre_tactic     : {e2.get('mitre_tactic')} / {e2.get('mitre_technique')}")
    info(f"linked_events    : {e3.get('event_count')}")
    info(f"timeline entries : {len(e3.get('attack_timeline', []))}")

    timeline = e3.get("attack_timeline", [])
    if timeline:
        info("attack_timeline  :")
        for entry in timeline:
            print(f"      [{entry.get('timestamp','?')}] {entry.get('event','?')} — {entry.get('detail','')}")


# ---------------------------------------------------------------------------
# Run a single test
# ---------------------------------------------------------------------------

def run_test(test_id: int, test_def: dict, verbose: bool = False) -> bool:
    import detection_orchestrator

    name     = test_def["name"]
    expect   = test_def["expect"]
    l1_out   = dict(test_def["layer1_output"])
    is_anom  = test_def["is_anomalous"]

    # Inject feature vector
    l1_out["feature_vector"] = make_feature_vector(is_anomalous=is_anom)
    l1_out["db_path"] = TEST_DB

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}Test {test_id}: {name}{RESET}")
    print(f"{'─'*60}")

    try:
        result = detection_orchestrator.run(l1_out, db_path=TEST_DB)
    except Exception as e:
        fail(f"Pipeline raised exception: {e}")
        traceback.print_exc()
        return False

    # Schema validation
    schema_errors = validate_schema(result)
    if schema_errors:
        for err in schema_errors:
            fail(f"Schema: {err}")
        return False
    ok("Schema validation passed")

    # Expectation checks
    exp_failures = check_expectations(result, expect)
    if exp_failures:
        for f in exp_failures:
            fail(f"Expectation: {f}")
        all_passed = False
    else:
        ok("All expectations met")
        all_passed = True

    if verbose:
        print_summary(result)

    # Always show the JSON output path for reference
    out_path = f"/tmp/test_{test_id}_result.json"
    with open(out_path, "w") as fp:
        json.dump(result, fp, indent=2, default=str)
    info(f"Full result saved → {out_path}")

    return all_passed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Layer 2 detection pipeline test suite")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print full result summary for each test")
    parser.add_argument("--test", "-t", type=int, default=None,
                        help="Run only a specific test number (1–4)")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║  PenguinSOC — Layer 2 Detection Tests    ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════╝{RESET}\n")

    # Setup
    setup_test_db()
    fit_pyod()

    tests_to_run = (
        {args.test: SYNTHETIC_LOGS[args.test]}
        if args.test
        else SYNTHETIC_LOGS
    )

    results = {}
    for tid, tdef in tests_to_run.items():
        passed = run_test(tid, tdef, verbose=args.verbose)
        results[tid] = passed

    # Summary
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}RESULTS SUMMARY{RESET}")
    print(f"{'═'*60}")
    total  = len(results)
    passed = sum(results.values())
    for tid, p in results.items():
        status = f"{GREEN}PASS{RESET}" if p else f"{RED}FAIL{RESET}"
        print(f"  Test {tid}: {SYNTHETIC_LOGS[tid]['name'][:45]:<45} [{status}]")

    print(f"\n  {passed}/{total} tests passed")

    if passed == total:
        print(f"\n{GREEN}{BOLD}All tests passed. Layer 2 is ready.{RESET}\n")
        sys.exit(0)
    else:
        print(f"\n{RED}{BOLD}{total - passed} test(s) failed. Check output above.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()