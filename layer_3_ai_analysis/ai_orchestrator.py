# ai_orchestrator.py
# Location: layer_3_ai_analysis/ai_orchestrator.py

import sys
import os
import requests
import json
from typing import Union

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ollama_client import check_ollama_connection
from agent.agent_graph import build_graph
from agent.agent_state import AgentState
from incident_report_builder import build_incident_report

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
# Change this to your teammate's actual IP during the live demo!
CVSS_LAYER_URL = "http://127.0.0.1:8000/score"

_graph = None

def _get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph

# ─────────────────────────────────────────
# INITIAL STATE BUILDER
# ─────────────────────────────────────────

def _build_initial_state(incident_data: dict) -> AgentState:
    """
    Builds the state matching your new AgentState keys.
    """
    return {
        "incident_data": incident_data,
        "event_id": incident_data.get("event_id"),
        
        # New Target Outputs
        "intent": None,
        "severity": None,
        "cvss_vector": None,
        "narrative": None,
        "recommended_actions": None,

        # Control Fields
        "retry_count": 0,
        "validation_passed": False,
        "ai_failed": False,
        "ai_failure_reason": None,
        "error": None,
        "ai_analysis": None
    }

# ─────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────

def run_ai_analysis(incident_data: Union[dict, list]) -> dict:
    """
    Entry point for Layer 3. 
    Handles list unwrapping, graph execution, and teammate POST.
    """

    # 🛡️ STEP 0: BULLETPROOF UNWRAPPER
    # Fixes: AttributeError: 'list' object has no attribute 'get'
    while isinstance(incident_data, list) and len(incident_data) > 0:
        incident_data = incident_data[0]

    # ── Step 1: Check Ollama connection ───
    connection = check_ollama_connection()

    if not connection["connected"]:
        failure_state = {
            "incident_data": incident_data,
            "ai_failed": True,
            "ai_failure_reason": f"Ollama unreachable: {connection.get('error')}",
        }
        return build_incident_report(incident_data, failure_state)

    # ── Step 2: Build initial state ───────
    initial_state = _build_initial_state(incident_data)

    # ── Step 3: Get compiled graph ────────
    graph = _get_graph()

    # ── Step 4: Run the graph ─────────────
    try:
        final_state = graph.invoke(initial_state)
    except Exception as e:
        failure_state = {
            "incident_data": incident_data,
            "ai_failed": True,
            "ai_failure_reason": f"LangGraph Crash: {str(e)}",
        }
        return build_incident_report(incident_data, failure_state)

    # ── Step 5: Build final report for YOUR output ────────
    report = build_incident_report(incident_data, final_state)

    # ── Step 6: 📤 PUSH TO TEAMMATE (CVSS Layer) ────────
    # Only push if analysis was successful
    if not final_state.get("ai_failed") and final_state.get("validation_passed"):
        scoring_payload = {
            "incident_id": final_state.get("event_id") or incident_data.get("event_id"),
            "cvss": final_state.get("cvss_vector"),
            "threat_summary": final_state.get("threat_summary"),
            "metadata": {
                "intent": final_state.get("intent"),
                "severity": final_state.get("severity"),
                "narrative": final_state.get("narrative")
            }
        }
        
        try:
            print(f"📡 Attempting to push to CVSS Layer: {CVSS_LAYER_URL}")
            resp = requests.post(CVSS_LAYER_URL, json=scoring_payload, timeout=5)
            if resp.status_code == 200:
                print("✅ Successfully pushed analysis to teammate.")
            else:
                print(f"⚠️ Teammate server returned status: {resp.status_code}")
        except Exception as e:
            print(f"⚠️ Could not reach teammate's Scoring Layer: {e}")

    return report