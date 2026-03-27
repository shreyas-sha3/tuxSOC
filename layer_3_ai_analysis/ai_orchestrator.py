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

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
# Change this to your teammate's actual IP during the live demo!
CVSS_LAYER_URL = "http://localhost:8000/score"

_graph = None


# ─────────────────────────────────────────
# OBSERVABLES EXTRACTOR
# Handles both new (raw_event) and lean (source/destination) schemas
# ─────────────────────────────────────────

def _extract_observables(incident_data: dict) -> dict:
    """
    Builds a normalised observables block from whichever schema is present.
    Supports:
      - Incident 32 schema: raw_event / engine_1_anomaly / engine_2_threat_intel
      - Lean schema:        source / destination / mitre_attack / anomaly_detection
    """
    raw_event    = incident_data.get("raw_event", {})
    engine1      = incident_data.get("engine_1_anomaly", {})
    engine2      = incident_data.get("engine_2_threat_intel", {})
    source       = incident_data.get("source", {})
    destination  = incident_data.get("destination", {})
    mitre        = incident_data.get("mitre_attack", {})
    anomaly_lean = incident_data.get("anomaly_detection", {})

    return {
        "source_ip":       raw_event.get("source_ip")      or source.get("ip"),
        "destination_ip":  raw_event.get("destination_ip") or destination.get("ip"),
        "port":            raw_event.get("port")            or destination.get("port"),
        "protocol":        raw_event.get("protocol"),
        "affected_host":   raw_event.get("affected_host"),
        "affected_user":   raw_event.get("affected_user")  or source.get("user"),
        "action":          raw_event.get("action"),
        "mitre_technique": (
            engine2.get("mitre_technique")
            or engine2.get("mitre_technique_name")
            or mitre.get("technique_id")
        ),
        "mitre_tactic": (
            engine2.get("mitre_tactic")
            or mitre.get("tactic")
        ),
        "anomaly_score": (
            engine1.get("anomaly_score")
            or anomaly_lean.get("pyod_score")
        ),
        "ueba_flags": engine1.get("ueba_flags", []),
    }


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
    Single return at the bottom — observables always present.
    """

    # ── Step 0: Unwrap list input ─────────
    while isinstance(incident_data, list) and len(incident_data) > 0:
        incident_data = incident_data[0]

    # ── Step 1: Extract observables (always, regardless of outcome) ──
    observables = _extract_observables(incident_data)

    incident_id = (
        incident_data.get("incident_id")
        or incident_data.get("event_id")
        or "UNKNOWN"
    )

    # ── Step 2: Check Ollama connection ───
    connection = check_ollama_connection()

    if not connection["connected"]:
        return {
            "incident_id":    incident_id,
            "threat_summary": None,
            "observables":    observables,
            "ai_analysis": {
                "intent":              None,
                "severity":            None,
                "cvss_vector":         None,
                "narrative":           None,
                "recommended_actions": [],
                "ai_failed":           True,
                "ai_failure_reason":   f"Ollama unreachable: {connection.get('error')}"
            }
        }

    # ── Step 3: Build initial state ───────
    initial_state = _build_initial_state(incident_data)

    # ── Step 4: Run the graph ─────────────
    try:
        final_state = graph.invoke(initial_state) if (graph := _get_graph()) else {}
    except Exception as e:
        return {
            "incident_id":    incident_id,
            "threat_summary": None,
            "observables":    observables,
            "ai_analysis": {
                "intent":              None,
                "severity":            None,
                "cvss_vector":         None,
                "narrative":           None,
                "recommended_actions": [],
                "ai_failed":           True,
                "ai_failure_reason":   f"LangGraph Crash: {str(e)}"
            }
        }

    # ── Step 5: Push to CVSS teammate ─────
    if not final_state.get("ai_failed") and final_state.get("validation_passed"):
        scoring_payload = {
            "incident_id":    incident_id,
            "threat_summary": final_state.get("narrative"),
            "cvss":           final_state.get("cvss_vector"),
            "observables":    observables,
            "metadata": {
                "intent":              final_state.get("intent"),
                "severity":            final_state.get("severity"),
                "narrative":           final_state.get("narrative"),
                "recommended_actions": final_state.get("recommended_actions", [])
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

    # ── Step 6: Single final return ───────
    return {
        "incident_id":    incident_id,
        "threat_summary": final_state.get("narrative"),
        "observables":    observables,
        "ai_analysis": {
            "intent":              final_state.get("intent"),
            "severity":            final_state.get("severity"),
            "cvss_vector":         final_state.get("cvss_vector"),
            "narrative":           final_state.get("narrative"),
            "recommended_actions": final_state.get("recommended_actions", []),
            "ai_failed":           final_state.get("ai_failed", False)
        }
    }