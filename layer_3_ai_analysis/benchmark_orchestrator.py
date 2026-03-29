# benchmark_orchestrator.py
# Location: layer_3_ai_analysis/benchmark_orchestrator.py

import json
import os
import requests
import sys
import threading
import time
from typing import Dict, List, Any

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layer_3_ai_analysis.ollama_client import check_ollama_connection, run_inference
from layer_3_ai_analysis.prompt_builder import build_benchmark_analysis_prompt

from rich.console import Console
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.text import Text

console = Console()

class BenchmarkUIState:
    def __init__(self):
        self.benchmarks_processed = 0
        self.last_benchmark_id = "N/A"
        self.status = "Idling... (Isolated Benchmark Mode)"
        self.recent_benchmarks = []

ui_state = BenchmarkUIState()

def generate_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    
    header = Panel(Text("tuxSOC — Isolated Benchmark Methodology Engine", justify="center", style="bold cyan"))
    layout["header"].update(header)
    
    layout["main"].split_row(
        Layout(name="stats", ratio=1),
        Layout(name="results", ratio=2)
    )
    
    stats = Table.grid(padding=1)
    stats.add_column(style="cyan", justify="left")
    stats.add_column(style="white", justify="right")
    stats.add_row("Status:", ui_state.status)
    stats.add_row("Total Processed:", str(ui_state.benchmarks_processed))
    stats.add_row("Last ID:", ui_state.last_benchmark_id)
    
    layout["stats"].update(Panel(stats, title="Benchmark Stats", border_style="cyan"))
    
    r_table = Table(show_header=True, header_style="bold yellow", expand=True)
    r_table.add_column("Sequence ID")
    r_table.add_column("Methodology Identification")
    
    for r in ui_state.recent_benchmarks[-10:]:
        r_table.add_row(r['id'], r['methodology'])
        
    layout["results"].update(Panel(r_table, title="🛡️ Recent Counter-Playbooks Generated", border_style="yellow"))
    return layout

def _live_updater():
    with Live(generate_layout(), refresh_per_second=4, screen=True) as live:
        while True:
            live.update(generate_layout())
            time.sleep(0.25)

# Start UI Thread
threading.Thread(target=_live_updater, daemon=True).start()

# L4 Target
CVSS_LAYER_URL = "http://localhost:8004/api/v1/score"

def run_benchmark_analysis(incident_data: Dict[str, Any]):
    """
    Completely isolated methodology analysis for benchmarks.
    Bypasses ALL standard Layer 3 logic.
    """
    incident_id = incident_data.get("incident_id", "BM-UNKNOWN")
    ui_state.last_benchmark_id = incident_id
    ui_state.status = f"[bold yellow]🔍 Analyzing methodology for {incident_id}...[/bold yellow]"
    
    # 1. Build the deep forensic prompt
    prompt = build_benchmark_analysis_prompt(incident_data)
    
    # 2. Direct LLM Call
    result = {"success": False, "response": None}
    conn = check_ollama_connection()
    if conn["connected"]:
        try:
            result = run_inference(prompt)
        except Exception as e:
            ui_state.status = f"[red]Inference failed: {e}[/red]"
    else:
        ui_state.status = "[red]Ollama Disconnected[/red]"

    # 3. Handle Playbook Response
    ai_block = {
        "intent": "BENCHMARK_METHODOLOGY_STUDY",
        "severity": "CRITICAL",
        "cvss_vector": {}, # Benchmarks focus on methodology, not just metrics
        "narrative": "Isolated Benchmark Analysis: Methodology identified, critical factors extracted, and counter-playbook generated.",
        "recommended_actions": [],
        "ai_failed": not result.get("success", False),
        "playbook_raw": result.get("response") if result.get("success") else "FAILED TO GENERATE PLAYBOOK"
    }

    # Extract a methodology snippet for UI
    methodology_summary = "Study Complete; Counter-Playbook Ready."
    if result.get("success"):
        # Simple extraction for the TUI
        response_text = result.get("response", "")
        if "Attacker Methodology" in response_text:
            methodology_summary = response_text.split("Attacker Methodology")[1][:100].strip().replace("\n", " ") + "..."

    ui_state.recent_benchmarks.append({"id": incident_id, "methodology": methodology_summary})
    ui_state.benchmarks_processed += 1
    ui_state.status = f"[green]✓ Completed {incident_id}[/green]"

    # 4. Handoff to Layer 4 (Passing the raw playbook)
    try:
        l4_payload = {
            "event_id": incident_id,
            "ai_analysis": ai_block,
            "observables": incident_data.get("observables", {}),
            "related_logs": incident_data.get("correlated_evidence", []),
            "dora_compliance": {}
        }
        requests.post(CVSS_LAYER_URL, json=l4_payload, timeout=10)
    except Exception as e:
        console.print(f"[red]Failed to push benchmark to L4: {e}[/red]")

if __name__ == "__main__":
    # Keep alive for TUI if run directly
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
