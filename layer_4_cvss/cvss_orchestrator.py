from fastapi import FastAPI, HTTPException
from shared.schemas import LLMIncidentInput, ScoredIncidentOutput, Layer5Input
from layer_4_cvss.engine_1_scorer.scorer_orchestrator import score_incident
from layer_4_cvss.engine_2_classifier.classifier_orchestrator import classify_incident
import requests

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
import threading
import time

console = Console()

class L4UIState:
    def __init__(self):
        self.incidents_scored = 0
        self.critical_events = 0
        self.high_events = 0
        self.status = "Idling..."
        self.recent_scores = []
        self.dora_flagged = 0

ui_state = L4UIState()

def generate_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main")
    )
    
    header = Panel(Text("tuxSOC - Layer 4: CVSS Calculator & Severity Engine", justify="center", style="bold yellow"))
    layout["header"].update(header)
    
    layout["main"].split_row(
        Layout(name="stats", ratio=1),
        Layout(name="analyses", ratio=2)
    )
    
    stats = Table.grid(padding=1)
    stats.add_column(style="yellow", justify="left")
    stats.add_column(style="white", justify="right")
    stats.add_row("Status:", ui_state.status)
    stats.add_row("Scored:", str(ui_state.incidents_scored))
    stats.add_row("CRITICAL:", f"[red]{ui_state.critical_events}[/red]")
    stats.add_row("HIGH:", f"[orange3]{ui_state.high_events}[/orange3]")
    stats.add_row("DORA Flagged:", f"[cyan]{ui_state.dora_flagged}[/cyan]")
    
    layout["stats"].update(Panel(stats, title="Engine Statistics", border_style="yellow"))
    
    a_table = Table(show_header=True, header_style="bold green", expand=True)
    a_table.add_column("Incident ID")
    a_table.add_column("Vector")
    a_table.add_column("Base Score")
    a_table.add_column("Severity")
    
    for a in ui_state.recent_scores[-15:]:
        a_table.add_row(str(a.get('id', 'N/A')), str(a.get('vector', 'N/A')), str(a.get('score', 'N/A')), str(a.get('sev', 'N/A')))
        
    layout["analyses"].update(Panel(a_table, title="🧮 Recent Calculations", border_style="green"))
    return layout

def _live_updater():
    with Live(generate_layout(), refresh_per_second=4, screen=True) as live:
        while True:
            live.update(generate_layout())
            time.sleep(0.25)

threading.Thread(target=_live_updater, daemon=True).start()

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
RESPONSE_LAYER_URL = "http://localhost:8005/api/v1/respond"

app = FastAPI(
    title="tuxSOC Layer 4: CVSS Scoring Service",
    description="Stateless CVSS scoring microservice receiving CIS violations directly in the payload.",
    version="3.0.0"
)


@app.post("/api/v1/score", response_model=ScoredIncidentOutput)
async def score_incident_endpoint(incident: LLMIncidentInput):
    """
    Receives incident data from Layer 3 (AI Analysis) and returns a scored output for Layer 5.
    Purely stateless: CIS violations are expected in the payload.
    """
    try:
        ui_state.status = f"[cyan]Scoring {incident.event_id}...[/cyan]"
        # Unwrap nested models
        ai_analysis = incident.ai_analysis
        cvss_metrics = ai_analysis.cvss_vector
        cis_violations = [v.model_dump() for v in ai_analysis.cis_violations]

        # Engine 1: Scoring (penalties + vector + base score)
        score_result = score_incident(
            metrics=cvss_metrics,
            cis_violations=cis_violations,
        )

        # Engine 2: Classification (severity + priority)
        classification = classify_incident(
            base_score=score_result["base_score"],
            cis_violation_count=len(score_result["cis_violations"]),
            cis_penalty_applied=score_result["cis_penalty_applied"],
        )

        severity = classification["severity"]
        requires_auto_block = (
            severity == "CRITICAL"
            or (severity == "HIGH" and score_result["cis_penalty_applied"])
        )

        output = ScoredIncidentOutput(
            event_id=incident.event_id,
            base_score=score_result["base_score"],
            severity=severity,
            requires_auto_block=requires_auto_block,
            dora_compliance=incident.dora_compliance,
        )

        # Collect UI stats
        score_str = f"[bold red]{score_result['base_score']}[/bold red]" if score_result['base_score'] >= 7.0 else str(score_result['base_score'])
        
        ui_state.incidents_scored += 1
        if severity == "CRITICAL":
            ui_state.critical_events += 1
        elif severity == "HIGH":
            ui_state.high_events += 1
            
        if incident.dora_compliance:
            ui_state.dora_flagged += 1

        ui_state.recent_scores.append({
            "id": incident.event_id,
            "vector": score_result.get("cvss_vector", "Unknown"),
            "score": score_str,
            "sev": severity
        })
        
        # ── Push to Layer 5 (Response Layer) ───────────
        try:
            ui_state.status = f"[blue]Forwarding {incident.event_id} to L5...[/blue]"
            observables = incident.observables or {}
            l5_payload = Layer5Input(
                event_id=incident.event_id,
                base_score=score_result["base_score"],
                severity=severity,
                requires_auto_block=requires_auto_block,
                attacker_ip=observables.get("source_ip", "Unknown"),
                affected_entity=observables.get("affected_host", "Unknown"),
                intent=ai_analysis.intent or "Unknown Threat",
                kibana_query=ai_analysis.kibana_query,
                related_logs=incident.related_logs,
                dora_compliance=incident.dora_compliance
            )

            resp = requests.post(RESPONSE_LAYER_URL, json=l5_payload.model_dump(), timeout=5)
            if resp.status_code == 200:
                ui_state.status = "[green]✓ Handoff to Layer 5 complete[/green]"
            else:
                ui_state.status = f"[yellow]⚠️ L5 returned {resp.status_code}[/yellow]"
        except Exception as e:
            ui_state.status = f"[red]❌ L5 push failed: {e}[/red]"

        return output
    except Exception as e:
        ui_state.status = f"[bold red]❌ Scoring crash: {e}[/bold red]"
        raise HTTPException(status_code=500, detail=f"Scoring error: {str(e)}")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "layer_4_cvss"}


def process_incident(incident_data: LLMIncidentInput) -> ScoredIncidentOutput:
    """
    Compatibility shim used by tests and direct callers.
    """
    # Simply wrap the logic (or call the endpoint logic directly if it wasn't async)
    # For simplicity, we re-implement the logic here as it's standard scoring.
    ai_analysis = incident_data.ai_analysis
    cvss_metrics = ai_analysis.cvss_vector
    cis_violations = [v.model_dump() for v in ai_analysis.cis_violations]

    score_result = score_incident(cvss_metrics, cis_violations)
    classification = classify_incident(
        base_score=score_result["base_score"],
        cis_violation_count=len(score_result["cis_violations"]),
        cis_penalty_applied=score_result["cis_penalty_applied"],
    )

    severity = classification["severity"]
    requires_auto_block = (
        severity == "CRITICAL"
        or (severity == "HIGH" and score_result["cis_penalty_applied"])
    )

    return ScoredIncidentOutput(
        event_id=incident_data.event_id,
        base_score=score_result["base_score"],
        severity=severity,
        requires_auto_block=requires_auto_block,
        dora_compliance=incident_data.dora_compliance,
    )
if __name__ == "__main__":
    import uvicorn
    import logging

    # Silence uvicorn logs for clean Rich UI
    logging.getLogger("uvicorn").setLevel(logging.ERROR)
    logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

    uvicorn.run(app, host="0.0.0.0", port=8004, access_log=False)
