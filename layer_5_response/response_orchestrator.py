from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from typing import Optional, List, Dict, Any

# Internal imports
from layer_5_response.engine_1_action.auto_responder import execute_firewall_block, send_soc_alert
from layer_5_response.engine_1_action.action_recommender import get_recommendations
from layer_5_response.playbook_generator import generate_markdown_playbook
from layer_5_response.ticket_creator import generate_soc_ticket

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

# Attempt to load shared schema, fallback to robust local definition if not found
try:
    from shared.schemas import Layer5Input
except ImportError:
    class Layer5Input(BaseModel):
        event_id: str
        base_score: float
        severity: str
        requires_auto_block: bool
        # Use Optional to prevent 422 errors if Layer 2 sends 'null'
        attacker_ip: Optional[str] = "Unknown"
        affected_entity: Optional[str] = "Unknown"
        intent: Optional[str] = "Unknown Threat"
        dora_compliance: Optional[dict] = None

# Create FastAPI app
app = FastAPI(
    title="tuxSOC Layer 5: Response Service",
    description="SOAR microservice for automated incident response and ticket creation",
    version="1.1.0"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "Layer 5: Response"}

@app.post("/api/v1/respond")
async def respond_to_incident(incident: Layer5Input):
    """
    Main endpoint to process incoming security incidents and orchestrate response.
    Includes sanitization for missing data (IPs/Intent).
    """
    
    # 1. Sanitize incoming Null values immediately
    safe_attacker_ip = incident.attacker_ip or "Unknown"
    safe_target_entity = incident.affected_entity or "Unknown"
    safe_intent = incident.intent or "Unknown Threat"

    console.print(f"\n[bold magenta]============================================================[/bold magenta]")
    console.print(f"[bold cyan]📥 PROCESSING EVENT:[/bold cyan] {incident.event_id}")
    console.print(f"[bold white]Severity:[/bold white] {incident.severity} | [bold white]Score:[/bold white] {incident.base_score}/10.0")
    console.print(f"[bold white]Intent:[/bold white] {safe_intent}")
    console.print(f"[bold white]Attacker IP:[/bold white] {safe_attacker_ip}")
    console.print(f"[bold white]Target:[/bold white] {safe_target_entity}")
    
    if incident.dora_compliance:
        console.print("[dim green]DORA Compliance Data: RECEIVED (EU Regulatory Processing Active)[/dim green]")
    else:
        console.print("[dim]DORA Compliance Data: NOT RECEIVED[/dim]")
    console.print(f"[bold magenta]============================================================[/bold magenta]\n")

    actions_taken = []

    # 2. Get recommendations based on severity and sanitized intent
    recommendations = get_recommendations(incident.severity, intent=safe_intent)

    # 3. Controlled Auto-Response Logic
    if incident.requires_auto_block:
        if safe_attacker_ip not in ["Unknown", "0.0.0.0", None]:
            console.print(f"[bold red]🛡️ AUTO-BLOCK TRIGGERED:[/bold red] Initiating firewall response for {safe_attacker_ip}...")
            action_result = execute_firewall_block(safe_attacker_ip)
            actions_taken.append(action_result)
        else:
            console.print("[dim]AUTO-BLOCK SKIPPED: No valid Attacker IP available for mitigation.[/dim]")

        console.print("[bold yellow]🚨 Sending critical SOC alert...[/bold yellow]")
        alert_result = send_soc_alert(incident.event_id, incident.severity)
        actions_taken.append(alert_result)
    else:
        console.print(f"[dim]No auto-block required for event {incident.event_id}[/dim]")

    # 4. Finalize incident data package for Playbooks and Tickets
    incident_dict = {
        "event_id": incident.event_id,
        "base_score": incident.base_score,
        "severity": incident.severity,
        "requires_auto_block": incident.requires_auto_block,
        "attacker_ip": safe_attacker_ip,
        "affected_entity": safe_target_entity,
        "intent": safe_intent,
        "dora_compliance": incident.dora_compliance,
        "related_logs": incident.related_logs
    }

    # 5. Document generation
    playbook_path = generate_markdown_playbook(incident_dict, recommendations)
    ticket_path = generate_soc_ticket(incident_dict, actions_taken, recommendations, playbook_path)
    ticket_id = f"TICK-{incident.event_id}"

    # --- CLI BEAUTIFICATION: Print Playbook & Logs ---
    try:
        with open(playbook_path, "r") as f:
            md = Markdown(f.read())
            console.print(Panel(md, title="[bold green]🛡️ Executed Response Playbook[/bold green]", border_style="green"))

        if incident.related_logs:
            log_table = Table(title="🔍 Correlated Evidence (Raw Elasticsearch Logs)", show_header=True, header_style="bold yellow", title_justify="left")
            log_table.add_column("Index", style="dim")
            log_table.add_column("Timestamp", style="cyan")
            log_table.add_column("Action", style="magenta")
            log_table.add_column("Source", style="green")
            log_table.add_column("Dest", style="red")
            
            for index, log in enumerate(incident.related_logs[:10]):
                ts = str(log.get("@timestamp", ""))
                action = str(log.get("raw_event", {}).get("action", "") or log.get("event", {}).get("action", "") or "")
                src = str(log.get("source", {}).get("ip", ""))
                dst = str(log.get("destination", {}).get("ip", "") or log.get("destination", {}).get("port", ""))
                log_table.add_row(f"{index+1:02d}", ts, action[:40], src, dst)
                
            console.print(log_table)
            if len(incident.related_logs) > 10:
                console.print(f"[dim]... and {len(incident.related_logs) - 10} more logs (view in Kibana)[/dim]")
    except Exception as e:
        console.print(f"[dim]Could not render playbook/logs to console: {e}[/dim]")
    # ------------------------------------------------

    return {
        "event_id": incident.event_id,
        "ticket_id": ticket_id,
        "actions_executed": actions_taken,
        "ticket_path": ticket_path,
        "playbook_path": playbook_path,
        "recommendations": recommendations,
        "summary": {
            "total_actions": len(actions_taken),
            "successful_actions": len([a for a in actions_taken if a.get("status") == "SUCCESS"]),
            "recommendations_count": len(recommendations),
            "auto_block_executed": incident.requires_auto_block,
            "dora_active": incident.dora_compliance is not None
        }
    }

if __name__ == "__main__":
    import uvicorn
    import logging
    
    log = logging.getLogger("uvicorn")
    log.setLevel(logging.ERROR)
    log = logging.getLogger("uvicorn.access")
    log.setLevel(logging.ERROR)

    uvicorn.run(app, host="0.0.0.0", port=8005, access_log=False)