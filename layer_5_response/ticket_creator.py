import os
import json
import datetime
from typing import Dict, List

def generate_soc_ticket(incident_data: Dict, actions_taken: List[Dict], recommendations: List[str], playbook_path: str = "") -> str:
    """
    Generates a SOC ticket in JSON format and saves it to the shared/tickets directory.

    Args:
        incident_data (dict): The incident data from Layer 5 input.
        actions_taken (list): List of actions taken during response.
        recommendations (list): List of recommended next steps.
        playbook_path (str): Path to the generated playbook file.

    Returns:
        str: The file path of the generated ticket.
    """
    # Create shared/tickets directory if it doesn't exist
    tickets_dir = os.path.join(os.path.dirname(__file__), 'shared', 'tickets')
    os.makedirs(tickets_dir, exist_ok=True)

    # Extract relevant data from incident_data
    event_id = incident_data.get("event_id", "unknown")
    base_score = incident_data.get("base_score", 0.0)
    severity = incident_data.get("severity", "UNKNOWN")
    attacker_ip = incident_data.get("attacker_ip", "Unknown")
    affected_entity = incident_data.get("affected_entity", "Unknown")
    intent = incident_data.get("intent", "Unknown Threat")

    # Determine ticket status: RESOLVED if auto-block was successful, otherwise OPEN
    # Check if any action was a successful firewall block
    auto_blocked_success = any(
        action.get("action") == "firewall_block" and action.get("status") == "SUCCESS"
        for action in actions_taken
    )
    status = "RESOLVED" if auto_blocked_success else "OPEN"

    # Generate ticket ID and timestamp
    ticket_id = f"TICK-{event_id}"
    timestamp = datetime.datetime.now().isoformat()

    # Construct the ticket dictionary
    dora_compliance = incident_data.get("dora_compliance")
    
    ticket = {
        "ticket_id": ticket_id,
        "timestamp": timestamp,
        "event_id": event_id,
        "severity": severity,
        "base_score": base_score,
        "attacker_ip": attacker_ip,
        "affected_entity": affected_entity,
        "intent": intent,
        "status": status,
        "actions_taken": actions_taken,
        "recommendations": recommendations,
        "playbook_path": playbook_path,
        "dora_compliance": dora_compliance
    }

    if dora_compliance:
        article_18 = dora_compliance.get("article_18_classification", {})
        if article_18.get("is_major_incident"):
            ticket["regulatory_flag"] = "REGULATORY_ESCALATION_REQUIRED"

    # Define the file path
    file_name = f"{ticket_id}.json"
    file_path = os.path.join(tickets_dir, file_name)

    # Write the ticket to a JSON file
    with open(file_path, 'w') as f:
        json.dump(ticket, f, indent=2)

    print(f"[L5-RESPONSE] Ticket generated: {file_path}")
    return file_path