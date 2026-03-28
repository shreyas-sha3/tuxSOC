# ai_orchestrator.py
# Location: layer_3_ai_analysis/ai_orchestrator.py

import sys
import os
import requests
import json
from typing import Union

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ollama_client import check_ollama_connection, run_inference
from agent.agent_graph import build_graph
from agent.agent_state import AgentState
from prompt_builder import build_dora_classification_prompt
from json_parser import parse_llm_response

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
# DORA CLASSIFICATION ENGINE
# Article 18 (6 criteria) + Article 19 (T+4h notification)
# ─────────────────────────────────────────

def _run_dora_classification(incident_id: str, observables: dict,
                              ai_analysis: dict, incident_data: dict) -> dict:
    """
    Calls the LLM with the DORA Article 18/19 prompt.
    Returns a structured dora_report dict.
    Falls back to a safe default if the LLM fails.
    """
    try:
        prompt = build_dora_classification_prompt(
            incident_id, observables, ai_analysis, incident_data
        )
        result = run_inference(prompt)

        if not result["success"]:
            raise ValueError(result["error"])

        parsed = parse_llm_response(result["response"])
        if parsed["parsed"] and isinstance(parsed["data"], dict):
            return parsed["data"]

        raise ValueError("DORA LLM response could not be parsed")

    except Exception as e:
        print(f"⚠️ DORA classification failed: {e} — returning safe default")
        return {
            "article_18_classification": {
                "is_major_incident": None,
                "criteria_triggered": [],
                "criteria_evaluation": {},
                "error": str(e)
            },
            "article_19_initial_notification": {
                "notification_type":      "T+4h Initial Notification",
                "regulation":             "EU DORA 2022/2554 — Article 19(1)(a)",
                "reporting_standard":     "ITS 2025/302",
                "incident_id":            incident_id,
                "lei":                    "BARCLAYS-LEI-213800LBQA1Y9L22JB70",
                "incident_timestamp":     None,
                "classification_time":    None,
                "affected_services":      [],
                "initial_description":    "Classification pending — manual review required.",
                "c1_to_c6_triggers":      [],
                "containment_status":     "Unknown",
                "cross_border_impact":    None,
                "escalated_to_regulator": False,
                "error":                  str(e)
            }
        }


# ─────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────

def run_ai_analysis(incident_data: Union[dict, list]) -> dict:
    """
    Bulletproof entry point for Layer 3.
    Fail-Soft pattern: every failure populates a safe fallback and continues.
    Zero early returns after Step 1 — DORA classification always runs.
    Four pillars always present in the response:
      incident_id | observables | ai_analysis | dora_compliance
    """

    # ── Step 0: Unwrap list input ─────────
    while isinstance(incident_data, list) and len(incident_data) > 0:
        incident_data = incident_data[0]

    # ── Step 1: Extract observables & ID (always — cannot fail) ──
    observables = _extract_observables(incident_data)
    incident_id = (
        incident_data.get("incident_id")
        or incident_data.get("event_id")
        or "UNKNOWN"
    )

    # ── Step 2: Safe fallback state (used if graph fails) ─────────
    # Pre-populated so Steps 5–7 always have a valid dict to read from
    final_state = {
        "intent":              None,
        "severity":            None,
        "cvss_vector":         None,
        "narrative":           None,
        "recommended_actions": [],
        "ai_failed":           False,
        "ai_failure_reason":   None,
        "validation_passed":   False,
    }

    # ── Step 3: Check Ollama — soft fail, do not return ───────────
    connection = check_ollama_connection()
    if not connection["connected"]:
        print(f"⚠️ Ollama unreachable: {connection.get('error')} — skipping graph, continuing to DORA")
        final_state["ai_failed"]         = True
        final_state["ai_failure_reason"] = f"Ollama unreachable: {connection.get('error')}"
        final_state["narrative"]         = (
            "AI forensic analysis unavailable — Ollama engine offline. "
            "DORA classification derived from observables only."
        )
    else:
        # ── Step 4: Run LangGraph — soft fail, do not return ─────
        initial_state = _build_initial_state(incident_data)
        try:
            graph_result = _get_graph().invoke(initial_state)
            # Merge graph output into final_state
            final_state.update({k: v for k, v in graph_result.items() if v is not None})
        except Exception as e:
            print(f"⚠️ LangGraph crashed: {e} — using safe fallback, continuing to DORA")
            final_state["ai_failed"]         = True
            final_state["ai_failure_reason"] = f"LangGraph Crash: {str(e)}"
            final_state["narrative"]         = (
                "AI forensic analysis failed due to a graph execution error. "
                "DORA classification derived from observables only."
            )

    # ── Step 5: Build ai_block from whatever final_state contains ─
    ai_block = {
        "intent":              final_state.get("intent"),
        "severity":            final_state.get("severity"),
        "cvss_vector":         final_state.get("cvss_vector"),
        "narrative":           final_state.get("narrative"),
        "recommended_actions": final_state.get("recommended_actions", []),
        "ai_failed":           final_state.get("ai_failed", False),
        "ai_failure_reason":   final_state.get("ai_failure_reason"),
    }

    # ── Step 6: DORA Classification — always runs, always returns ─
    print("📋 Running DORA Article 18/19 Classification...")
    dora_report = _run_dora_classification(
        incident_id, observables, ai_block, incident_data
    )

    # ── Step 7: Push to CVSS teammate (best-effort, non-blocking) ─
    if not final_state.get("ai_failed") and final_state.get("validation_passed"):
        scoring_payload = {
            "incident_id":    incident_id,
            "threat_summary": final_state.get("narrative"),
            "cvss":           final_state.get("cvss_vector"),
            "observables":    observables,
            "dora_report":    dora_report,
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

    # ── Step 8: Single guaranteed return — four pillars always present ──
    return {
        "incident_id":     incident_id,
        "threat_summary":  final_state.get("narrative"),
        "observables":     observables,
        "ai_analysis":     ai_block,
        "dora_compliance": dora_report,
    }