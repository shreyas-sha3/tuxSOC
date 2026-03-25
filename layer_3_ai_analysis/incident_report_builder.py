from datetime import datetime, timezone

def _get_current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

# ─────────────────────────────────────────
# PATH A — SUCCESS ASSEMBLY
# ─────────────────────────────────────────

def _build_success_block(final_state: dict) -> dict:
    """
    Returns only the five canonical keys required by the CVSS scoring layer.
    """
    return {
        "event_id":            final_state.get("event_id"),
        "intent":              final_state.get("intent") or final_state.get("attack_intent"),
        "severity":            final_state.get("severity") or final_state.get("severity_recommendation"),
        "cvss_vector":         final_state.get("cvss_vector") or final_state.get("cvss"),
        "narrative":           final_state.get("narrative"),
        "recommended_actions": final_state.get("recommended_actions", []),
        "ai_failed":           False,
        "analysis_timestamp":  _get_current_timestamp()
    }

# ─────────────────────────────────────────
# PATH B — FAILURE ASSEMBLY
# ─────────────────────────────────────────

def _build_failure_block(final_state: dict) -> dict:
    incident_data = final_state.get("incident_data", {})
    if isinstance(incident_data, list) and len(incident_data) > 0:
        incident_id = incident_data[0].get("incident_id", "BATCH_INCIDENT")
    else:
        incident_id = incident_data.get("incident_id", "UNKNOWN")

    return {
        "event_id":            incident_id,
        "intent":              None,
        "severity":            None,
        "cvss_vector":         None,
        "narrative":           None,
        "recommended_actions": [],
        "ai_failed":           True,
        "ai_failure_reason":   final_state.get("ai_failure_reason"),
        "alert": (
            f"AI ANALYSIS FAILED — MANUAL REVIEW REQUIRED\n"
            f"Incident ID: {incident_id}\n"
            f"Reason: {final_state.get('ai_failure_reason', 'Unknown')}\n"
            f"Action: SOC analyst must review detection logs immediately."
        ),
        "analysis_timestamp":  _get_current_timestamp()
    }

# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────

def build_incident_report(original_incident, final_state: dict) -> dict:
    if final_state.get("ai_failed"):
        ai_block = _build_failure_block(final_state)
    else:
        ai_block = _build_success_block(final_state)

    # Promote event_id to top level for easy access
    event_id = ai_block.get("event_id") or (
        original_incident[0].get("incident_id")
        if isinstance(original_incident, list) and original_incident
        else original_incident.get("incident_id") if isinstance(original_incident, dict)
        else None
    )

    return {
        "event_id":   event_id,
        "ai_analysis": ai_block
    }