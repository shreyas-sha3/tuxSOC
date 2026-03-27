from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

# ONLY THESE IMPORTS
from layer_5_response.engine_1_action.auto_responder import execute_firewall_block, send_soc_alert
from layer_5_response.engine_1_action.action_recommender import get_recommendations
from layer_5_response.playbook_generator import generate_markdown_playbook
from layer_5_response.ticket_creator import generate_soc_ticket
# Note: We assume shared/schemas.py exists and contains the Layer5Input model
try:
    from shared.schemas import Layer5Input
except ImportError:
    # Fallback for development - define the model if shared.schemas is not available
    # In production, this should be imported from shared.schemas
    from pydantic import BaseModel
    from typing import Optional

    class Layer5Input(BaseModel):
        event_id: str
        base_score: float
        severity: str
        requires_auto_block: bool
        attacker_ip: str = "Unknown"
        affected_entity: str = "Unknown"
        intent: str = "Unknown Threat"

# Create FastAPI app
app = FastAPI(
    title="tuxSOC Layer 5: Response Service",
    description="SOAR microservice for automated incident response and ticket creation",
    version="1.0.0"
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "Layer 5: Response"}

@app.post("/api/v1/respond")
async def respond_to_incident(incident: Layer5Input):
    """
    Main endpoint to process incoming security incidents and orchestrate response.

    Args:
        incident (Layer5Input): The incident data from Layer 4 (CVSS Scoring)

    Returns:
        dict: Response containing event_id, ticket_id, actions_executed, ticket_path, playbook_path, and recommendations
    """
    # Print massive processing banner
    print("\n" + "🚨" + "="*60)
    print(f"🚨 PROCESSING EVENT: {incident.event_id}")
    print(f"🚨 Severity: {incident.severity} | Score: {incident.base_score}/10.0")
    print(f"🚨 Intent: {incident.intent}")
    print(f"🚨 Attacker IP: {incident.attacker_ip}")
    print(f"🚨 Target: {incident.affected_entity}")
    print("🚨" + "="*60 + "\n")

    # Initialize actions taken list
    actions_taken = []

    # Get recommendations based on severity and intent
    recommendations = get_recommendations(incident.severity, intent=incident.intent)
    print(f"💡 Generated {len(recommendations)} response recommendations")

    # Check if auto-block is required
    if incident.requires_auto_block:
        # Execute firewall block action
        print("🛡️ AUTO-BLOCK TRIGGERED: Initiating firewall response...")
        action_result = execute_firewall_block(incident.attacker_ip)
        actions_taken.append(action_result)

        # Send SOC alert
        print("📢 Sending critical SOC alert...")
        alert_result = send_soc_alert(incident.event_id, incident.severity)
        actions_taken.append(alert_result)

        print(f"🔧 Actions executed: {len([a for a in actions_taken if a.get('status') == 'SUCCESS'])} successful")
    else:
        print(f"ℹ️ No auto-block required for event {incident.event_id}")

    # Prepare incident data dictionary for ticket and playbook creation
    incident_dict = {
        "event_id": incident.event_id,
        "base_score": incident.base_score,
        "severity": incident.severity,
        "requires_auto_block": incident.requires_auto_block,
        "attacker_ip": incident.attacker_ip,
        "affected_entity": incident.affected_entity,
        "intent": incident.intent
    }

    # Generate Markdown playbook
    print("📖 Generating response playbook...")
    playbook_path = generate_markdown_playbook(incident_dict, recommendations)

    # Generate SOC ticket
    print("📄 Creating SOC ticket...")
    ticket_path = generate_soc_ticket(incident_dict, actions_taken, recommendations, playbook_path)

    # Extract ticket ID from the path for response
    ticket_id = f"TICK-{incident.event_id}"

    # Return comprehensive response
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
            "auto_block_executed": incident.requires_auto_block
        }
    }

# Run the application if executed directly
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8005)