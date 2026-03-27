import json
from ollama_client import run_inference
from prompt_builder import build_batch_analysis_prompt
from json_parser import parse_llm_response

# ─────────────────────────────────────────
# NODE 1 — THE MASTER ANALYST
# ─────────────────────────────────────────
def analyze_incident_master(state: dict) -> dict:
    print("DEBUG: Entering Node 1 — analyze_incident_master")
    if state.get("ai_failed"):
        return {}

    # Unwrap list if needed
    incident = state["incident_data"]
    if isinstance(incident, list):
        incident = incident[0] if incident else {}

    # Extract event_id from multiple possible keys
    event_id = (
        incident.get("event_id")
        or incident.get("incident_id")
        or incident.get("id")
        or "UNKNOWN"
    )
    print(f"🧠 [NODE 1] Analyzing Event {event_id}...")

    # Pass the lean incident dict directly — no CIS cleaning, no cloning
    prompt = build_batch_analysis_prompt(incident)
    result = run_inference(prompt)

    print(f"🔍 RAW AI OUTPUT: {result['response']}")

    
    if not result["success"]:
        return {"ai_failed": True, "error": result["error"]}

    parsed = parse_llm_response(result["response"])
    update_data = parsed["data"] if parsed["parsed"] else {}

    update_data["event_id"] = event_id
    return update_data


# ─────────────────────────────────────────
# NODE 2 — THE MAPPER / PATCH
# ─────────────────────────────────────────
def patch_and_fix(state: dict) -> dict:
    print("DEBUG: Entering Node 2 — patch_and_fix")
    if state.get("ai_failed"):
        return {}

    updates = {}

    # Map attack_intent → intent
    if not state.get("intent"):
        updates["intent"] = (
            state.get("attack_intent")
            or "Anomalous Activity Detected"
        )

    # Map severity_recommendation → severity, and normalize LLM synonyms
    if not state.get("severity"):
        raw_severity = (
            state.get("severity_recommendation")
            or state.get("severity")
            or "medium"
        )
        # Normalize synonyms the LLM might return
        _severity_map = {
            "observation": "informational",
            "normal":      "informational",
            "notice":      "informational",
            "info":        "informational",
            "none":        "informational",
            "warn":        "low",
            "warning":     "low",
            "moderate":    "medium",
            "elevated":    "high",
            "severe":      "critical",
            "emergency":   "critical",
        }
        normalized = raw_severity.strip().lower()
        updates["severity"] = _severity_map.get(normalized, normalized)

    # Aggressive CVSS lookup: cvss_vector > cvss > cvss_suggestion
    # Always writes result to cvss_vector
    cvss_raw = (
        state.get("cvss_vector")
        or state.get("cvss")
        or state.get("cvss_suggestion")
    )
    if isinstance(cvss_raw, str):
        try:
            cvss_raw = json.loads(cvss_raw)
        except (json.JSONDecodeError, ValueError):
            cvss_raw = None

    if not isinstance(cvss_raw, dict):
        updates["cvss_vector"] = {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "L", "I": "L", "A": "N"
        }
    else:
        updates["cvss_vector"] = cvss_raw

    return updates


# ─────────────────────────────────────────
# NODE 3 — THE GATEKEEPER
# ─────────────────────────────────────────
def finalize_and_validate(state: dict) -> dict:
    print("DEBUG: Entering Node 3 — finalize_and_validate")
    required = ["intent", "severity", "cvss_vector", "narrative", "recommended_actions"]
    missing = [f for f in required if not state.get(f)]

    if not missing:
        print("✅ [SUCCESS] AI Analysis Validated.")
        return {"validation_passed": True}

    print(f"❌ [CRITICAL] Validation failed. Missing: {missing}")
    return {"validation_passed": False, "ai_failed": True}
