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
from prompt_builder import (
    build_dora_classification_prompt, 
    build_benchmark_analysis_prompt,
    build_direct_l0_analysis_prompt
)
from json_parser import parse_llm_response

from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.text import Text
import threading
import time

console = Console()

class L3UIState:
    def __init__(self):
        self.incidents_processed = 0
        self.successful_analyses = 0
        self.dora_evaluations = 0
        self.status = "Idling..."
        self.recent_analyses = []

ui_state = L3UIState()

def generate_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    
    header = Panel(Text("tuxSOC - Layer 3: AI Cognitive Analyst (Ollama)", justify="center", style="bold magenta"))
    layout["header"].update(header)
    
    layout["main"].split_row(
        Layout(name="stats", ratio=1),
        Layout(name="analyses", ratio=2)
    )
    
    stats = Table.grid(padding=1)
    stats.add_column(style="magenta", justify="left")
    stats.add_column(style="white", justify="right")
    stats.add_row("Status:", ui_state.status)
    stats.add_row("Processed:", str(ui_state.incidents_processed))
    stats.add_row("Success:", f"[green]{ui_state.successful_analyses}[/green]")
    stats.add_row("DORA Evals:", f"[cyan]{ui_state.dora_evaluations}[/cyan]")
    
    layout["stats"].update(Panel(stats, title="Agent Statistics", border_style="magenta"))
    
    a_table = Table(show_header=True, header_style="bold green", expand=True)
    a_table.add_column("Incident ID")
    a_table.add_column("Intent")
    a_table.add_column("Severity")
    
    for a in ui_state.recent_analyses[-15:]:
        a_table.add_row(str(a.get('id', 'N/A')), str(a.get('intent', 'N/A')), str(a.get('severity', 'N/A')))
        
    layout["analyses"].update(Panel(a_table, title="🧠 Recent Analyses", border_style="green"))
    return layout

import atexit
import threading
import time

# 1. Create an event flag to signal safe shutdown
_ui_stop_event = threading.Event()

def _live_updater():
    """
    Background thread to update the Rich Live display.
    Uses an event flag and robust exception handling to prevent
    fatal interpreter crashes during shutdown (e.g., _enter_buffered_busy).
    """
    try:
        # screen=True is particularly sensitive at shutdown
        with Live(generate_layout(), refresh_per_second=4, screen=True) as live:
            while not _ui_stop_event.is_set():
                try:
                    # Check if we can still write to stdout
                    if hasattr(sys.stdout, 'closed') and sys.stdout.closed:
                        break
                    
                    live.update(generate_layout())
                    
                    # Use wait() instead of sleep() for faster response to the stop event
                    if _ui_stop_event.wait(0.25):
                        break
                except (RuntimeError, IOError, ValueError, AttributeError):
                    # Catching errors related to closed streams or interpreter finalization
                    break
    except Exception:
        # Silently fail for any other TUI-related errors during shutdown
        pass

# 3. Register the stop event to trigger during interpreter shutdown
atexit.register(lambda: _ui_stop_event.set())

threading.Thread(target=_live_updater, daemon=True).start()


# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
CVSS_LAYER_URL = "http://localhost:8004/api/v1/score"
_graph = None

# ─────────────────────────────────────────
# OBSERVABLES EXTRACTOR
# ─────────────────────────────────────────
def _extract_observables(incident_data: dict) -> dict:
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
    return {
        "incident_data": incident_data,
        "event_id": incident_data.get("event_id"),
        "intent": None,
        "severity": None,
        "cvss_vector": None,
        "narrative": None,
        "kibana_query": None,
        "recommended_actions": None,
        "retry_count": 0,
        "validation_passed": False,
        "ai_failed": False,
        "ai_failure_reason": None,
        "error": None,
        "ai_analysis": None
    }

# ─────────────────────────────────────────
# DORA CLASSIFICATION ENGINE
# ─────────────────────────────────────────
def _run_dora_classification(incident_id: str, observables: dict,
                              ai_analysis: dict, incident_data: dict) -> dict:
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
        console.print(f"[bold yellow]⚠️ WARN: DORA classification failed:[/bold yellow] {e} — returning safe default")
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
    while isinstance(incident_data, list) and len(incident_data) > 0:
        incident_data = incident_data[0]

    observables = _extract_observables(incident_data)
    incident_id = (
        incident_data.get("incident_id")
        or incident_data.get("event_id")
        or "UNKNOWN"
    )

    final_state = {
        "intent":              None,
        "severity":            None,
        "cvss_vector":         None,
        "narrative":           None,
        "kibana_query":        None,
        "recommended_actions": [],
        "ai_failed":           False,
        "ai_failure_reason":   None,
        "validation_passed":   False,
    }

    is_benchmark = incident_data.get("is_benchmark_sequence", False)
    is_direct_l0 = incident_data.get("is_direct_l3", False) or incident_data.get("source_layer") == "layer_0"

    if is_benchmark:
        ui_state.status = "[magenta]🧠 Generating Benchmark Playbook...[/magenta]"
        prompt = build_benchmark_analysis_prompt(incident_data)
        
        dora_report = {}
        ai_block = {
            "intent": "BENCHMARK_SIMULATION",
            "severity": "critical",
            "cvss_vector": {},
            "narrative": "AI forensic analysis for methodology and playbook generation.",
            "kibana_query": None,
            "recommended_actions": [],
            "ai_failed": False,
            "ai_failure_reason": None,
            "cis_violations": [],
            "playbook_raw": None
        }
        
        connection = check_ollama_connection()
        if not connection["connected"]:
            ai_block["ai_failed"] = True
            ai_block["ai_failure_reason"] = f"Ollama unreachable: {connection.get('error')}"
        else:
            try:
                result = run_inference(prompt)
                ai_block["playbook_raw"] = result.get("response") if result.get("success") else None
            except Exception as e:
                ai_block["ai_failed"] = True
                ai_block["ai_failure_reason"] = f"Benchmark inference failed: {e}"
        
        ui_state.successful_analyses += 1
        try:
             ui_state.status = "[blue]🤝 Handing off to Layer 4...[/blue]"
             cvss_payload = {
                 "event_id":       incident_id,
                 "ai_analysis":    ai_block,
                 "dora_compliance": dora_report,
                 "observables":     observables,
                 "related_logs":    incident_data.get("correlated_evidence", [])
             }
             resp = requests.post(CVSS_LAYER_URL, json=cvss_payload, timeout=10)
             if resp.status_code == 200:
                 ui_state.status = "[green]✓ Ready for next incident[/green]"
             else:
                 ui_state.status = f"[yellow]⚠️ L4 returned {resp.status_code}[/yellow]"
        except Exception as e:
             ui_state.status = f"[red]❌ L4 handoff failed: {e}[/red]"
        
        ui_state.incidents_processed += 1
        return {
             "incident_id":     incident_id,
             "threat_summary":  "Benchmark Sequence Playbook Evaluation",
             "observables":     observables,
             "ai_analysis":     ai_block,
             "dora_compliance": dora_report,
        }
        
    elif is_direct_l0:
        ui_state.status = "[yellow]⚡ Rapid Triage (Direct from L0)...[/yellow]"
        prompt = build_direct_l0_analysis_prompt(incident_data)
        
        connection = check_ollama_connection()
        if not connection["connected"]:
            return {"error": "Ollama offline"}
            
        result = run_inference(prompt)
        parsed = parse_llm_response(result["response"])
        ai_block = parsed["data"] if parsed["parsed"] else {"error": "Parse failed"}
        
        ui_state.incidents_processed += 1
        ui_state.successful_analyses += 1
        
        # Immediate return or handoff for direct L0
        return {
            "incident_id": incident_id,
            "source": "direct_l0_triage",
            "ai_analysis": ai_block
        }

    connection = check_ollama_connection()
    if not connection["connected"]:
        ui_state.status = f"[bold yellow]⚠️ Ollama offline[/bold yellow]"
        final_state["ai_failed"]         = True
        final_state["ai_failure_reason"] = f"Ollama unreachable: {connection.get('error')}"
        final_state["narrative"]         = (
            "AI forensic analysis unavailable — Ollama engine offline. "
            "DORA classification derived from observables only."
        )
    else:
        initial_state = _build_initial_state(incident_data)
        try:
            ui_state.status = "[magenta]🧠 Agent evaluating incident...[/magenta]"
            graph_result = _get_graph().invoke(initial_state)
            final_state.update({k: v for k, v in graph_result.items() if v is not None})
        except Exception as e:
            ui_state.status = f"[bold yellow]⚠️ Graph crash: {e}[/bold yellow]"
            final_state["ai_failed"]         = True
            final_state["ai_failure_reason"] = f"LangGraph Crash: {str(e)}"
            final_state["narrative"]         = (
                "AI forensic analysis failed due to a graph execution error. "
                "DORA classification derived from observables only."
            )

    engine2 = incident_data.get("engine_2_threat_intel", {})
    cis_violations = engine2.get("cis_violations", [])

    ai_block = {
        "intent":              final_state.get("intent") or "Unknown",
        "severity":            final_state.get("severity") or "Unknown",
        "cvss_vector":         final_state.get("cvss_vector") or {},
        "narrative":           final_state.get("narrative") or "No narrative available.",
        "kibana_query":        final_state.get("kibana_query"),
        "recommended_actions": final_state.get("recommended_actions", []),
        "ai_failed":           final_state.get("ai_failed", False),
        "ai_failure_reason":   final_state.get("ai_failure_reason"),
        "cis_violations":      cis_violations,
    }

    ui_state.status = "[cyan]⚖️ Evaluating DORA compliance...[/cyan]"
    ui_state.dora_evaluations += 1
    dora_report = _run_dora_classification(
        incident_id, observables, ai_block, incident_data
    )

    if not final_state.get("ai_failed") and final_state.get("validation_passed"):
        ui_state.successful_analyses += 1
        try:
            ui_state.status = "[blue]🤝 Handing off to Layer 4...[/blue]"
            cvss_payload = {
                "event_id":       incident_id,
                "ai_analysis":    ai_block,
                "dora_compliance": dora_report,
                "observables":     observables,
                "related_logs":    incident_data.get("correlated_evidence", [])
            }
            resp = requests.post(CVSS_LAYER_URL, json=cvss_payload, timeout=10)
            if resp.status_code == 200:
                ui_state.status = "[green]✓ Ready for next incident[/green]"
            else:
                ui_state.status = f"[yellow]⚠️ L4 returned {resp.status_code}[/yellow]"
        except Exception as e:
            ui_state.status = f"[red]❌ L4 handoff failed: {e}[/red]"

    ui_state.incidents_processed += 1
    ui_state.recent_analyses.append({
        "id": incident_id,
        "intent": final_state.get("intent", "Unknown"),
        "severity": final_state.get("severity", "Unknown")
    })
    
    return {
        "incident_id":     incident_id,
        "threat_summary":  final_state.get("narrative"),
        "observables":     observables,
        "ai_analysis":     ai_block,
        "dora_compliance": dora_report,
    }

# ─────────────────────────────────────────
# SERVER STARTUP & CRASH CATCHER
# ─────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    import logging
    import traceback
    import sys

    # Force logs to be invisible to keep the Rich UI clean
    logging.getLogger("uvicorn").setLevel(logging.ERROR)
    logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

    console.print(f"[bold magenta]🚀 Starting tuxSOC Layer 3 as Module: {__package__}[/bold magenta]")
    
    try:
        # When running with -m, uvicorn needs the full path from the project root
        # We also set reload=False because reloader often crashes in module mode
        uvicorn.run(
            "layer_3_ai_analysis.app:app", 
            host="0.0.0.0", 
            port=8001, 
            log_level="error",
            access_log=False
        )
    except Exception as e:
        console.print("\n[bold red]❌ MODULE STARTUP FATAL ERROR:[/bold red]")
        console.print(traceback.format_exc())
        console.print(f"\n[yellow]Current Sys Path:[/yellow] {sys.path[0]}")
        input("\nCRASH PREVENTED: Press ENTER to close this window...")